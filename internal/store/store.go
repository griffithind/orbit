// Package store is the data access layer.
//
// Every mutation runs in a transaction, obtained from Store.Tx; reads that need
// a consistent view use Store.Read, which opens a read-only one so an
// accidental write fails loudly instead of committing.
//
// The application connects as an unprivileged role (migrations/0002_grants.sql):
// it holds no CREATE and cannot rewrite the audit log, so a bug cannot alter the
// schema and a compromise cannot erase its own tracks.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Common errors. Callers should test with errors.Is rather than comparing
// pgx errors directly, so the storage layer stays swappable.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	// ErrInvalid is a CHECK constraint refusing the value it was given. The
	// caller sent something the schema forbids, so it belongs in the 4xx range
	// with the constraint named — not in a 500, which tells an operator only
	// that something went wrong somewhere.
	ErrInvalid   = errors.New("invalid")
	ErrNoActived = errors.New("network has no active CA")
)

// Store owns the connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// New wraps an existing pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Open connects using dsn. The DSN should authenticate as the unprivileged
// application role (orbit_app), not the migration role, so the application
// cannot alter the schema or rewrite the audit log.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Pool exposes the underlying pool for LISTEN/NOTIFY consumers, which need a
// dedicated connection rather than a transaction.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Tx is an open transaction. Every repository method hangs off it, so a caller
// cannot accidentally run a multi-statement operation outside one.
type Tx struct {
	tx pgx.Tx
}

// Tx runs fn inside a read-write transaction, committing if it returns nil.
//
// fn must not retain the *Tx beyond its own return.
func (s *Store) Tx(ctx context.Context, fn func(context.Context, *Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		// Rollback after a successful Commit is a no-op that returns
		// ErrTxClosed, which we ignore.
		_ = tx.Rollback(ctx)
	}()

	if err := fn(ctx, &Tx{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// Read runs fn inside a read-only transaction.
//
// A separate method so read paths are visibly read paths at the call site, and
// so an accidental write fails loudly rather than committing.
func (s *Store) Read(ctx context.Context, fn func(context.Context, *Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(ctx, &Tx{tx: tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// epochKind identifies which of a network's monotonic counters to advance.
// It is a closed type rather than a string because the value is interpolated
// into an identifier position in SQL, where parameters are not permitted.
type epochKind int

const (
	// EpochConfig covers anything changing a host's rendered configuration.
	EpochConfig epochKind = iota
	// EpochBlocklist covers revocation specifically. It is separate so that a
	// routine config change does not make every agent re-evaluate trust, and so
	// that convergence on revocation can be measured on its own.
	EpochBlocklist
)

func (e epochKind) column() string {
	switch e {
	case EpochBlocklist:
		return "blocklist_epoch"
	default:
		return "config_epoch"
	}
}

func (e epochKind) String() string {
	switch e {
	case EpochBlocklist:
		return "blocklist"
	default:
		return "config"
	}
}

// BumpEpoch advances a network's counter and queues a notification.
//
// Both happen in the caller's transaction. pg_notify delivers on commit, so a
// rolled-back change cannot wake agents for an update that never happened, and
// a committed one cannot fail to. That ordering is why the notify belongs here
// rather than in a service layer after the commit.
func (t *Tx) BumpEpoch(ctx context.Context, networkID uuid.UUID, kind epochKind) (int64, error) {
	// #nosec G201 -- kind is a closed enum; column() returns one of two literals.
	q := fmt.Sprintf(
		`UPDATE orbit.network SET %s = %s + 1 WHERE id = $1 RETURNING %s`,
		kind.column(), kind.column(), kind.column())

	var epoch int64
	if err := t.tx.QueryRow(ctx, q, networkID).Scan(&epoch); err != nil {
		return 0, mapErr(err, "bump epoch")
	}

	payload := fmt.Sprintf(`{"network_id":%q,"kind":%q,"epoch":%d}`, networkID, kind, epoch)
	if _, err := t.tx.Exec(ctx, `SELECT pg_notify('orbit_epoch', $1)`, payload); err != nil {
		return 0, fmt.Errorf("notify: %w", err)
	}
	return epoch, nil
}

// nonNil converts a nil slice to an empty one.
//
// pgx encodes a nil Go slice as SQL NULL, which the NOT NULL array columns
// reject. Every such column already has a DEFAULT '{}', so the caller's intent
// when leaving a slice nil is unambiguously "empty", and normalizing here is
// better than making the columns nullable and pushing NULL-vs-empty ambiguity
// into every reader.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// mapErr translates pgx and Postgres errors into the package's sentinel errors
// so callers do not have to import pgx to tell "already exists" from "broken".
func mapErr(err error, what string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%s: %w", what, ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%s: %w: %s", what, ErrConflict, pgErr.ConstraintName)
		case "23503": // foreign_key_violation
			// A reference to a row that does not exist. Reported as not-found
			// rather than as a database error, because that is what it means to
			// the caller.
			return fmt.Errorf("%s: %w: %s", what, ErrNotFound, pgErr.ConstraintName)
		case "23514": // check_violation
			// A value the schema forbids. Several invariants live only in CHECK
			// constraints — network names that look like uuids, port ranges,
			// state values — and without this they surfaced as a 500, which
			// tells an operator that something broke rather than that they sent
			// something the system will never accept.
			//
			// The constraint name is included deliberately: it is the only
			// machine-readable thing distinguishing one refusal from another,
			// and it is what lets a handler add a sentence about this specific
			// rule instead of a generic one.
			return fmt.Errorf("%s: %w: %s", what, ErrInvalid, pgErr.ConstraintName)
		}
	}
	return fmt.Errorf("%s: %w", what, err)
}
