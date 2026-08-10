// Package store is the data access layer.
//
// Every mutation runs in a transaction, obtained from Store.Tx; reads that need
// a consistent view use Store.Read, which opens a read-only one so an
// accidental write fails loudly instead of committing.
//
// The application connects as an unprivileged role (migrations/0001_initial.sql):
// it holds no CREATE and cannot rewrite the audit log, so a bug cannot alter the
// schema and a compromise cannot erase its own tracks.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

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

	// ErrNoNetworkIdentity means a network was created without the key its ID
	// commits to.
	//
	// A distinct error because the caller has to generate one — it cannot be
	// defaulted, invented, or derived from anything else — and a generic
	// constraint violation would send them looking at the database instead.
	ErrNoNetworkIdentity = errors.New("a network needs an identity key: it is what its ID commits to")
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

// Open connects using dsn. The DSN should authenticate as the unprivileged
// application role (orbit_app), not the migration role, so the application
// cannot alter the schema or rewrite the audit log.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	applyPoolDefaults(cfg)
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

// Pool and statement limits, set explicitly because every default here is wrong
// for a control plane.
//
// MaxConns: pgxpool defaults to max(4, NumCPU). On a small control plane that is
// four, and four is not a pool, it is a queue with a deadline. It also made the
// nested-acquisition bug below fatal rather than merely wasteful.
//
// lock_timeout: PutPolicy and UpdateRole take FOR UPDATE. Without a timeout, one
// wedged transaction blocks every writer for that network until their HTTP
// contexts expire — while each of them holds a pool connection.
//
// idle_in_transaction_session_timeout: a client that vanishes mid-transaction
// otherwise holds its row locks until the TCP connection is reaped, which can be
// hours.
const (
	poolMaxConns        = 16
	poolMaxConnLifetime = time.Hour
	stmtTimeout         = "30s"
	lockTimeout         = "5s"
	idleInTxTimeout     = "60s"
)

func applyPoolDefaults(cfg *pgxpool.Config) {
	cfg.MaxConns = poolMaxConns
	cfg.MaxConnLifetime = poolMaxConnLifetime
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	// Set rather than defaulted: a DSN that names one of these means the
	// operator has thought about it, and overriding that silently is worse than
	// either value.
	for k, v := range map[string]string{
		"statement_timeout":                   stmtTimeout,
		"lock_timeout":                        lockTimeout,
		"idle_in_transaction_session_timeout": idleInTxTimeout,
	} {
		if _, ok := cfg.ConnConfig.RuntimeParams[k]; !ok {
			cfg.ConnConfig.RuntimeParams[k] = v
		}
	}
}

// CloseGrace bounds how long Close waits for the pool to drain.
//
// Bounded because pgxpool.Close waits for every acquired connection to be
// RELEASED, and one of them is held by the epoch notifier parked in
// WaitForNotification. If that connection does not come back — a cancellation
// that leaves the socket mid-read, a server that stopped answering — Close
// never returns.
//
// What makes that worse than a slow shutdown: Close is called from a defer in
// orbitd's serve(). A startup failure AFTER the store opens therefore returns
// an error, runs this defer, blocks forever, and main() never reaches the line
// that prints the error. The process looks like it hung during startup, with no
// message anywhere, when in fact it failed immediately and the reason is
// trapped behind this call. That cost an afternoon of a real deployment.
const CloseGrace = 5 * time.Second

// Close releases the pool, and gives up if it will not drain.
//
// Abandoning connections at exit costs nothing: the process is going away and
// Postgres reaps the backends when the sockets close. Never returning costs the
// error message.
func (s *Store) Close() {
	done := make(chan struct{})
	go func() {
		s.pool.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(CloseGrace):
	}
}

// Pool exposes the underlying pool for LISTEN/NOTIFY consumers, which need a
// dedicated connection rather than a transaction.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Tx is an open transaction. Every repository method hangs off it, so a caller
// cannot accidentally run a multi-statement operation outside one.
type Tx struct {
	tx pgx.Tx
}

// inTxKey carries the open transaction so a nested Read can join it rather than
// acquire a second connection.
type inTxKey struct{}

// ErrNestedTx is returned when a transaction is opened while one is already held
// on the same context.
//
// This is a deadlock, not a style violation. Both Tx and Read acquire from the
// pool unconditionally, so a nested call takes a SECOND connection while holding
// the first and blocks in Acquire until its context expires. With MaxConns
// connections doing it at once, none can ever be released.
//
// It was reachable: Enroll opens a transaction, and the certificate path reaches
// Vault.get, which called Store.Read. The registry cache hid it, so it surfaced
// only when the cache was cold — a restart, or immediately after a CA rotation
// changed the fingerprint that keys it. Which is to say: exactly when enrollment
// load is highest.
//
// Failing loudly in development is the point. A hang gives no stack, no log line
// and no clue.
var ErrNestedTx = errors.New("store: transaction opened while one is already held on this context; " +
	"pass the existing *Tx down instead of calling Store.Tx or Store.Read again")

func markInTx(ctx context.Context, tx *Tx) context.Context {
	return context.WithValue(ctx, inTxKey{}, tx)
}

// currentTx returns the transaction already open on this context, if any.
func currentTx(ctx context.Context) *Tx {
	tx, _ := ctx.Value(inTxKey{}).(*Tx)
	return tx
}

// Tx runs fn inside a read-write transaction, committing if it returns nil.
//
// fn must not retain the *Tx beyond its own return.
func (s *Store) Tx(ctx context.Context, fn func(context.Context, *Tx) error) error {
	if currentTx(ctx) != nil {
		return ErrNestedTx
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		// Rollback after a successful Commit is a no-op that returns
		// ErrTxClosed, which we ignore.
		_ = tx.Rollback(ctx)
	}()

	wrapped := &Tx{tx: tx}
	ctx = markInTx(ctx, wrapped)
	if err := fn(ctx, wrapped); err != nil {
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
// RepeatableRead rather than the default READ COMMITTED, because a read path
// that issues several statements and calls the result consistent has to be. The
// trust-bundle handler reads the bundle, then the CA list, then per-CA counts;
// at READ COMMITTED those are three snapshots. It costs nothing under Postgres
// MVCC and makes the guarantee the callers already assume a real one.
//
// Note this is safe to add here and NOT on Tx: there is no 40001 retry anywhere
// in this package, which is correct at READ COMMITTED for writes. Raising the
// write path's isolation without adding one would turn ordinary contention into
// 500s.
// A Read nested inside an open transaction JOINS it rather than acquiring a
// second connection. That is what makes the deadlock structurally impossible
// instead of merely detected: Vault.get reads a secret through Store.Read, and
// the certificate path reaches it from inside Enroll's transaction. Erroring
// there would be honest but would simply move the outage.
//
// Joining is also the more correct read. The nested query sees the outer
// transaction's own uncommitted writes, which is what a caller reading back
// something it just wrote expects.
//
// It does cost one property: a nested Read runs inside a read-WRITE transaction,
// so it no longer fails loudly on an accidental write. Store.Tx remaining an
// error when nested is what keeps that from being a general escape hatch.
func (s *Store) Read(ctx context.Context, fn func(context.Context, *Tx) error) error {
	if tx := currentTx(ctx); tx != nil {
		return fn(ctx, tx)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
		IsoLevel:   pgx.RepeatableRead,
	})
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	wrapped := &Tx{tx: tx}
	ctx = markInTx(ctx, wrapped)
	if err := fn(ctx, wrapped); err != nil {
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
