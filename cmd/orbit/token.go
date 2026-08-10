package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

func tokenLs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("token ls", flag.ContinueOnError)
	var o options
	o.bind(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	res, err := o.client.ListTokens(ctx)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	// LAST USED is the column that makes a listing worth having: after a leak,
	// the question is whether the token was used and when. Revoked tokens stay
	// listed for the same reason — a row that vanishes cannot answer "was it used
	// after we revoked it".
	t := newTable(o.r,
		column{name: "NAME", elastic: true},
		column{name: "SCOPES"},
		column{name: "STATE"},
		column{name: "LAST USED"},
		column{name: "EXPIRES", optional: true},
		column{name: "ID", optional: true},
	)
	for _, tok := range res.Value {
		state := "active"
		if tok.RevokedAt != "" {
			state = "revoked"
		}
		t.add(tok.Name, strings.Join(tok.Scopes, ","), state,
			orNever(tok.LastUsedAt), orNever(tok.ExpiresAt), tok.ID)
	}
	if t.empty() {
		fmt.Fprintln(errOut, "no tokens")
		return nil
	}
	t.render(out)
	return nil
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

// tokenCreate mints a credential.
//
// The plaintext goes alone on stdout and every word of prose to stderr, the
// property `orbitd token create` established and a test there asserts. It is what
// makes this pipe into a password manager:
//
//	orbit token create -name ci -scopes hosts:read | op create item
//
// A token that has to be copied out of a scrollback buffer is one that ends up in
// a shell history.
func tokenCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	var o options
	fl := bindTokenCreate(fs, &o)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if *fl.name == "" {
		return usageErrorf("-name is required; it is what the audit log will say about every action this token takes")
	}
	scopeList := splitCSV(*fl.scopes)
	if len(scopeList) == 0 {
		return usageErrorf("-scopes must name at least one scope, e.g. -scopes hosts:read,networks:read")
	}
	if err := o.load(); err != nil {
		return err
	}

	o.announce(fmt.Sprintf("Creating token %q with scopes %s", *fl.name, strings.Join(scopeList, ", ")))

	res, err := o.client.CreateToken(ctx, wire.CreateTokenRequest{
		Name: *fl.name, Scopes: scopeList, ExpiresInDays: *fl.days,
	})
	if err != nil {
		return err
	}
	if o.json {
		// The API response carries the plaintext, so -json is already the
		// pipe-friendly form for a script that wants the id alongside it.
		return emitJSON(res.Raw)
	}

	tok := res.Value
	fmt.Fprintf(errOut, `
id      %s
name    %s
scopes  %s
expires %s

Shown once and not recoverable — only its SHA-256 is stored.

`, tok.ID, tok.Name, strings.Join(tok.Scopes, ", "), orNever(tok.ExpiresAt))

	fmt.Fprintln(out, tok.Token)

	for _, s := range scopeList {
		if s == "*" {
			fmt.Fprintf(errOut, `
This token holds "*" and passes every scope check. If it is a break-glass
credential, store the plaintext somewhere that does not depend on the control
plane or on the overlay — the failure it exists for is one where neither is
reachable. Revoke it once a narrower token is in place:

  orbit token revoke %s
`, tok.ID)
			break
		}
	}
	return nil
}

func tokenRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	var o options
	o.bind(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit token revoke <uuid>")
	}
	if err := o.load(); err != nil {
		return err
	}

	// Tokens are addressed by uuid only. They have names, but nothing makes a
	// name unique, and resolving one would mean guessing which credential to
	// destroy. `orbit token ls` prints the ids.
	tokenID, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		return usageErrorf("token revoke takes a uuid, not a name: token names are not unique. "+
			"Find the id with `orbit token ls` (%v)", err)
	}

	o.announce(fmt.Sprintf("About to REVOKE token %s", tokenID))

	// Prompt only when this is the credential making the request. Revoking your
	// own token is legitimate — it is what the last step of a rotation looks
	// like, and refusing it would mean the most privileged token is the one you
	// cannot retire — but doing it by accident locks you out of the API, and the
	// remedy is `orbitd token create` on the control plane host.
	if who, err := o.client.WhoAmI(ctx); err == nil && who.Value.ID == tokenID.String() {
		if err := o.confirm(
			"This is the token you are authenticating with. Revoking it makes this the last " +
				"request it can make, and a replacement can then only be minted with " +
				"`orbitd token create` on the control plane host. Continue?"); err != nil {
			return err
		}
	}

	if err := o.client.RevokeToken(ctx, tokenID); err != nil {
		return err
	}
	fmt.Fprintf(out, "revoked %s\n", tokenID)
	return nil
}

// tokenCreateFlags are the flags of `orbit tokenCreate`, declared here so the
// command tree can register them: completion offers exactly the set the
// command parses, because there is only one declaration of it.
type tokenCreateFlags struct {
	name   *string
	scopes *string
	days   *int
}

func bindTokenCreate(fs *flag.FlagSet, o *options) tokenCreateFlags {
	o.bind(fs)
	return tokenCreateFlags{
		// No default name, matching `orbitd token create`. A CI credential and a
		// break-glass credential want very different names in an audit log, and
		// "token" tells a reader nothing.
		name:   fs.String("name", "", "token name, recorded in the audit log (required)"),
		scopes: fs.String("scopes", "", "comma separated scopes; \"*\" grants everything (required)"),
		days:   fs.Int("expires-days", 0, "expire after N days; 0 means never"),
	}
}
