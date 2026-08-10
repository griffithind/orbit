package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/griffithind/orbit/internal/store"
)

// Offline token management.
//
// This exists for one situation: every admin token is lost, expired, or
// revoked, and there is therefore no way to call POST /v1/tokens — the endpoint
// that mints tokens requires a token. Without an offline path the only remedies
// are re-running bootstrap for a throwaway network, or hand-computing a SHA-256
// and INSERTing it, which is fiddly enough to get wrong at exactly the moment
// nobody can afford to.
//
// It grants no privilege that the DSN did not already carry. orbit_app holds
// INSERT on orbit.api_token because POST /v1/tokens needs it, so anyone able to
// run this could already have written the same row by hand. The command makes
// the supported path convenient rather than opening a new one.
//
// Unlike the API path there is no authenticated actor, so the audit entry is
// attributed to the system with the invoking OS user recorded in meta. That is
// weaker attribution than a token or an OIDC subject, and saying so in the
// record is better than implying a precision that is not there.

func tokenCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: orbitd token create -name <name> [-scopes '*'] [-expires-days N]")
	}

	switch args[0] {
	case "create":
		return tokenCreate(args[1:])
	default:
		return fmt.Errorf("unknown token subcommand %q (want: create)", args[0])
	}
}

func tokenCreate(args []string) error {
	fs := flag.NewFlagSet("token create", flag.ExitOnError)
	var (
		dsn = fs.String("dsn", "", "postgres DSN (or ORBIT_DSN)")
		// No default. A break-glass credential and a CI credential want very
		// different names in an audit log, and "token" tells a reader nothing.
		name   = fs.String("name", "", "token name, recorded in the audit log (required)")
		scopes = fs.String("scopes", "*", "comma-separated scopes; \"*\" grants everything")
		days   = fs.Int("expires-days", 0, "expire after N days; 0 means never")
	)
	_ = fs.Parse(args)

	if *name == "" {
		return errors.New("-name is required; it is what the audit log will say about every action this token takes")
	}

	scopeList := splitCSV(*scopes)
	if len(scopeList) == 0 {
		return errors.New("-scopes must name at least one scope")
	}

	ctx := context.Background()
	st, err := openStore(ctx, *dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	plaintext, hash, err := store.NewAPIToken()
	if err != nil {
		return err
	}

	var expiresAt *time.Time
	if *days > 0 {
		t := time.Now().AddDate(0, 0, *days)
		expiresAt = &t
	}

	var tokenID string
	err = st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		id, err := tx.CreateAPIToken(ctx, *name, hash, scopeList, expiresAt)
		if err != nil {
			return err
		}
		tokenID = id.String()

		// Audited like any other token creation. A credential that appears in
		// the database with no record of its creation is exactly the shape of
		// an attacker's persistence, and a legitimate break-glass token should
		// not be indistinguishable from one.
		e := store.AuditEntry{
			ActorType:    store.ActorSystem,
			ActorDisplay: osUser(),
			Action:       store.ActionTokenCreated,
			TargetType:   "token",
			TargetID:     tokenID,
			Meta:         store.AuditMeta(map[string]any{"via": "orbitd token create", "name": *name}),
		}
		return tx.AppendAudit(ctx, e)
	})
	if err != nil {
		return err
	}

	expiry := "never"
	if expiresAt != nil {
		expiry = expiresAt.Format(time.RFC3339)
	}

	// stdout, so the token can be piped straight into a password manager
	// without the surrounding prose. Everything else goes to stderr.
	fmt.Fprintf(os.Stderr, `
token   %s
name    %s
scopes  %s
expires %s

Shown once and not recoverable — only its SHA-256 is stored.

`, tokenID, *name, strings.Join(scopeList, ", "), expiry)
	fmt.Println(plaintext)

	if containsStr(scopeList, "*") {
		fmt.Fprint(os.Stderr, `
This token holds "*" and passes every scope check. If it is a break-glass
credential, store the plaintext somewhere that does not depend on this machine
or on the overlay — the failure it exists for is one where neither is reachable.
Revoke it with DELETE /v1/tokens/`+tokenID+` once a narrower token is in place.
`)
	}
	return nil
}

// osUser reports who ran the command, for the audit record. Best effort: it is
// a hint about a shell session, not an authenticated identity, and the audit
// entry says so by attributing the action to the system rather than to a user.
func osUser() string {
	for _, k := range []string{"SUDO_USER", "USER", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "unknown"
}

func containsStr(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
