package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/griffithind/orbit/internal/vault"
)

// `orbitd kek rotate` re-seals every stored secret under a new passphrase.
//
// An offline operator command against the database, not an API. Rotation needs
// the CURRENT passphrase to read what it is about to rewrite, and an endpoint
// that accepts the deployment's root secret over HTTP is a worse idea than the
// problem it solves. It is also the shape the work already has: the control
// plane holds the old key in memory, and the operator holds the new one.
//
// docs/key-custody.md has claimed since it was written that the KEK "rotates, by
// resealing every secret". The primitives existed — Tx.ListSecrets and
// Tx.ResealSecret, both carrying doc comments saying they were for exactly this
// — and nothing called either. This is the caller.
func kekCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: orbitd kek rotate [-dsn ...]")
	}
	switch args[0] {
	case "rotate":
		return kekRotate(args[1:])
	default:
		return fmt.Errorf("unknown kek subcommand %q; the only one is rotate", args[0])
	}
}

func kekRotate(args []string) error {
	fs := flag.NewFlagSet("kek rotate", flag.ContinueOnError)
	dsn := fs.String("dsn", "", "postgres connection string (or ORBIT_DSN)")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Both passphrases before touching the database. The new one is read from
	// its own variable rather than a flag: a passphrase on a command line is in
	// the shell history and in ps, which is the failure ORBIT_KEK_PASSPHRASE_FILE
	// exists to avoid on the other side.
	next := []byte(os.Getenv("ORBIT_KEK_NEW_PASSPHRASE"))
	if f := os.Getenv("ORBIT_KEK_NEW_PASSPHRASE_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read ORBIT_KEK_NEW_PASSPHRASE_FILE: %w", err)
		}
		next = []byte(strings.TrimSpace(string(b)))
	}
	if len(next) == 0 {
		return errors.New("set ORBIT_KEK_NEW_PASSPHRASE or ORBIT_KEK_NEW_PASSPHRASE_FILE " +
			"to the passphrase to rotate TO; the current one is read the usual way")
	}

	ctx := context.Background()
	st, err := openStore(ctx, *dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	// Opening proves the CURRENT passphrase before anything is rewritten. Vault
	// checks the stored verifier, so a wrong one fails here rather than after
	// half a rotation.
	vlt, err := vault.Open(ctx, st)
	if err != nil {
		return fmt.Errorf("open the vault with the current passphrase: %w", err)
	}

	if !*yes {
		fmt.Fprintf(os.Stderr,
			"About to re-seal every stored secret under a new passphrase.\n\n"+
				"  Every control plane replica must be given the new passphrase before\n"+
				"  it next starts. One still holding the old one will fail its verifier\n"+
				"  check and refuse to boot.\n\n"+
				"  Take a database backup first. A backup taken BEFORE this only opens\n"+
				"  with the OLD passphrase, so keep both until the next backup succeeds.\n\n"+
				"Continue? [y/N] ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			return errors.New("cancelled")
		}
	}

	n, err := vlt.Rotate(ctx, next)
	if err != nil {
		return fmt.Errorf("rotate: %w", err)
	}

	fmt.Printf("re-sealed %d secret(s) under the new passphrase\n\n", n)
	fmt.Print("Next, in this order:\n" +
		"  1. give every replica the new passphrase\n" +
		"  2. restart them\n" +
		"  3. take a fresh backup — the previous one needs the OLD passphrase\n")
	return nil
}
