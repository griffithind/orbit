// Command orbit-migrate applies database migrations.
//
// It connects with an administrative role that can create schemas, tables, and
// roles. That is deliberately not the role the control plane runs as: the
// application connects as orbit_app, which holds no CREATE and cannot rewrite
// the audit log. Running the application as the migration role would give a bug
// the ability to alter the schema and a compromise the ability to erase its own
// tracks.
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
	"github.com/griffithind/orbit/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "orbit-migrate:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dsn     = flag.String("dsn", os.Getenv("ORBIT_ADMIN_DSN"), "admin connection string (or ORBIT_ADMIN_DSN)")
		dryRun  = flag.Bool("dry-run", false, "list pending migrations without applying them")
		timeout = flag.Duration("timeout", 2*time.Minute, "overall timeout")
		showVer = flag.Bool("version", false, "print the build version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version.Version)
		return nil
	}

	if *dsn == "" {
		return errors.New("-dsn is required (or set ORBIT_ADMIN_DSN)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

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
