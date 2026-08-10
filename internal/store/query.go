package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Query helpers.
//
// Three shapes accounted for roughly 450 lines across this package, repeated 31,
// 27 and 11 times. The repetition was not just bulk: two of the collection loops
// closed rows by hand on each error branch instead of deferring, which is a leak
// waiting for a fourth branch, and one of the ErrNoRows sites converted a miss
// into (nil, nil) — a silent "no exit node chosen" that reads as success.

// collect runs a query and scans every row.
//
// pgx.CollectRows closes the rows and folds rows.Err() in, which is exactly the
// part the hand-written loops kept getting subtly different.
func collect[T any](ctx context.Context, t *Tx, what, sql string,
	scan func(pgx.CollectableRow) (T, error), args ...any) ([]T, error) {
	rows, err := t.tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, mapErr(err, what)
	}
	out, err := pgx.CollectRows(rows, scan)
	if err != nil {
		return nil, mapErr(err, what)
	}
	return out, nil
}
