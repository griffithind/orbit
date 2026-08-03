// Package db owns the Postgres connection pool and schema migrations.
//
// The migration runner is deliberately small: sequential, forward-only, one
// transaction per file, guarded by an advisory lock so that N control-plane
// replicas starting simultaneously do not race. There is no down-migration
// support, because a down migration against a database holding certificate
// state is a way to lose an audit trail, not a recovery strategy. Roll forward.
package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationLockID is an arbitrary but stable key for pg_advisory_lock. It must
// not collide with any other advisory lock the application takes.
const migrationLockID int64 = 0x0067_0072_0062_0074 // "orbt"

// Migration is one embedded SQL file.
type Migration struct {
	Name string
	SQL  string
}

// Migrations returns the embedded migrations in lexical order, which is
// therefore also application order. Files are named NNNN_description.sql.
func Migrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		out = append(out, Migration{Name: e.Name(), SQL: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Migrate applies any migrations the database has not yet seen.
//
// conn must be connected as a role that can create schemas, tables, and
// (ideally) roles. That is not the role the application runs as: the app
// connects as orbit_app, which holds no CREATE and cannot rewrite the audit
// log.
func Migrate(ctx context.Context, conn *pgx.Conn) (applied []string, err error) {
	// Serialize across replicas. The lock is released when the session ends,
	// but unlock explicitly so a long-lived bootstrap connection does not hold
	// it for its whole life.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, uerr := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockID); uerr != nil && err == nil {
			err = fmt.Errorf("release migration lock: %w", uerr)
		}
	}()

	// The bookkeeping table lives in the orbit schema, so the schema has to
	// exist before the first migration runs. 0001 also creates it (IF NOT
	// EXISTS), which keeps that file runnable on its own.
	if _, err := conn.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS orbit`); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}
	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS orbit.schema_migration (
			name       text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return nil, fmt.Errorf("create migration table: %w", err)
	}

	rows, err := conn.Query(ctx, `SELECT name FROM orbit.schema_migration`)
	if err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	seen := map[string]struct{}{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		seen[n] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	migrations, err := Migrations()
	if err != nil {
		return nil, err
	}

	for _, m := range migrations {
		if _, ok := seen[m.Name]; ok {
			continue
		}

		// One transaction per migration. A file that fails leaves the database
		// at the previous migration rather than half-applied.
		tx, err := conn.Begin(ctx)
		if err != nil {
			return applied, fmt.Errorf("begin %s: %w", m.Name, err)
		}
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("apply %s: %w", m.Name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO orbit.schema_migration (name) VALUES ($1)`, m.Name); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("record %s: %w", m.Name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, fmt.Errorf("commit %s: %w", m.Name, err)
		}
		applied = append(applied, m.Name)
	}

	return applied, nil
}

// MigrateDSN opens a single connection, migrates, and closes it. Convenience
// for bootstrap paths and tests.
func MigrateDSN(ctx context.Context, dsn string) ([]string, error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)
	return Migrate(ctx, conn)
}
