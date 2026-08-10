package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNestedReadJoinsTheOpenTransaction.
//
// The bug this pins: Store.Tx and Store.Read both acquired from the pool
// unconditionally, so a Read reached from inside a Tx took a SECOND connection
// while holding the first. Enroll does exactly that — its certificate path
// reaches Vault.get, which reads through Store.Read — and with MaxConns
// enrollments in flight none of them could ever release. The registry cache hid
// it until the cache was cold, which is a restart or a CA rotation.
//
// No database required: the assertion is which *Tx the callback receives.
func TestNestedReadJoinsTheOpenTransaction(t *testing.T) {
	outer := &Tx{}
	ctx := markInTx(context.Background(), outer)

	// A Store with a nil pool. If Read tried to acquire, this would panic —
	// which is a perfectly good assertion that it did not.
	s := &Store{}

	var got *Tx
	if err := s.Read(ctx, func(_ context.Context, tx *Tx) error {
		got = tx
		return nil
	}); err != nil {
		t.Fatalf("nested Read: %v", err)
	}
	if got != outer {
		t.Error("nested Read did not join the open transaction; it would acquire a second connection")
	}
}

// TestNestedReadPropagatesItsError. Joining must not swallow the callback's
// error just because there is no commit to perform.
func TestNestedReadPropagatesItsError(t *testing.T) {
	ctx := markInTx(context.Background(), &Tx{})
	boom := errors.New("nope")

	err := (&Store{}).Read(ctx, func(context.Context, *Tx) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want %v", err, boom)
	}
}

// TestNestedTxIsRefused. Unlike Read, a nested Tx cannot join: the inner call
// would return success on a transaction the outer one has not committed. There
// is no correct behaviour here other than refusing.
func TestNestedTxIsRefused(t *testing.T) {
	ctx := markInTx(context.Background(), &Tx{})

	called := false
	err := (&Store{}).Tx(ctx, func(context.Context, *Tx) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrNestedTx) {
		t.Fatalf("got %v, want ErrNestedTx", err)
	}
	if called {
		t.Error("the callback ran; a refused nested transaction must not execute its body")
	}
}

// TestPoolDefaultsAreSet. Every one of these was unset, and each turned a
// contended moment into an outage rather than a slow request.
func TestPoolDefaultsAreSet(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://u:p@localhost:5432/db")
	if err != nil {
		t.Fatal(err)
	}
	applyPoolDefaults(cfg)

	if cfg.MaxConns != poolMaxConns {
		t.Errorf("MaxConns = %d, want %d", cfg.MaxConns, poolMaxConns)
	}
	if cfg.MaxConnLifetime != poolMaxConnLifetime {
		t.Errorf("MaxConnLifetime = %v, want %v", cfg.MaxConnLifetime, poolMaxConnLifetime)
	}
	for k, want := range map[string]string{
		"statement_timeout":                   stmtTimeout,
		"lock_timeout":                        lockTimeout,
		"idle_in_transaction_session_timeout": idleInTxTimeout,
	} {
		if got := cfg.ConnConfig.RuntimeParams[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

// TestPoolDefaultsDoNotOverrideTheDSN. An operator who names one of these has
// thought about it; silently replacing their value is worse than either number.
func TestPoolDefaultsDoNotOverrideTheDSN(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://u:p@localhost:5432/db?statement_timeout=90s")
	if err != nil {
		t.Fatal(err)
	}
	applyPoolDefaults(cfg)

	if got := cfg.ConnConfig.RuntimeParams["statement_timeout"]; got != "90s" {
		t.Errorf("statement_timeout = %q, want the DSN's 90s", got)
	}
	if got := cfg.ConnConfig.RuntimeParams["lock_timeout"]; got != lockTimeout {
		t.Errorf("lock_timeout = %q, want the default %q", got, lockTimeout)
	}
}
