package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
		return nil
	}
	for _, name := range applied {
		fmt.Println("applied", name)
	}

	fmt.Println()
	fmt.Println("Note: orbit_app was created without a password. Set one before")
	fmt.Println("connecting the control plane:")
	fmt.Println()
	fmt.Println("  ALTER ROLE orbit_app LOGIN PASSWORD '<secret>';")
	return nil
}
