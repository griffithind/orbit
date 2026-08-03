package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/griffithind/orbit/internal/db"
)

// Schema migrations.
//
// A subcommand rather than a separate binary. It was one for a while, and the
// separation bought nothing: both run on the control plane host, both talk to
// the same Postgres, and the privilege boundary that matters is between two
// DSNs, not between two executables. `orbitd migrate` takes -dsn, `orbitd
// serve` takes its own; nothing about shipping them apart enforced that.
//
// The boundary itself is real and stays. The migration role can create schemas,
// tables, and roles; the application connects as orbit_app, which holds no
// CREATE and cannot rewrite the audit log. Running the control plane as the
// migration role would give a bug the ability to alter the schema and a
// compromise the ability to erase its own tracks.
func migrateCmd(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	var (
		dsn     = fs.String("dsn", os.Getenv("ORBIT_ADMIN_DSN"), "admin connection string (or ORBIT_ADMIN_DSN)")
		dryRun  = fs.Bool("dry-run", false, "list the embedded migrations without applying them")
		timeout = fs.Duration("timeout", 2*time.Minute, "overall timeout")
		appPass = fs.String("app-password", "",
			"set orbit_app's password after migrating (or ORBIT_APP_PASSWORD). "+
				"Without it the role is created with no password and cannot log in")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *dryRun {
		migrations, err := db.Migrations()
		if err != nil {
			return err
		}
		// Without a connection we cannot tell applied from pending, so list
		// everything and say so, rather than implying these will all run.
		fmt.Println("embedded migrations (already-applied ones are skipped at run time):")
		for _, m := range migrations {
			fmt.Println("  ", m.Name)
		}
		return nil
	}

	if *dsn == "" {
		return errors.New("-dsn is required (or set ORBIT_ADMIN_DSN)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(context.Background())

	applied, err := db.Migrate(ctx, conn)
	if err != nil {
		return err
	}

	if len(applied) == 0 {
		fmt.Println("database is up to date")
	}
	for _, name := range applied {
		fmt.Println("applied", name)
	}

	// Set the password even when there was nothing to migrate. Returning early
	// on an up-to-date database would make `migrate -app-password` a no-op that
	// reports success, which is how a rotated password appears to have been
	// applied and has not been.
	if *appPass == "" {
		*appPass = os.Getenv("ORBIT_APP_PASSWORD")
	}
	if *appPass == "" {
		fmt.Println()
		fmt.Println("Note: orbit_app was created without a password. Set one before")
		fmt.Println("connecting the control plane, with -app-password or:")
		fmt.Println()
		fmt.Println("  ALTER ROLE orbit_app LOGIN PASSWORD '<secret>';")
		return nil
	}

	// Set here rather than left as a psql step an operator runs by hand.
	//
	// It is the same connection and the same privilege that just created the
	// role, and leaving it out produced a documented sequence where the role
	// exists, cannot log in, and the failure surfaces later as an
	// authentication error that looks like a wrong password.
	//
	// quoteLiteral, not %s: a password is arbitrary text and this is DDL that
	// cannot be parameterised.
	if _, err := conn.Exec(ctx,
		"ALTER ROLE orbit_app LOGIN PASSWORD "+quoteLiteral(*appPass)); err != nil {
		return fmt.Errorf("set orbit_app password: %w", err)
	}
	fmt.Println()
	fmt.Println("orbit_app can now log in.")
	return nil
}

// quoteLiteral escapes a string for a SQL literal.
//
// Postgres doubles a single quote inside a literal, and nothing else needs
// escaping in a standard_conforming_strings session, which is the default and
// has been since 9.1.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
