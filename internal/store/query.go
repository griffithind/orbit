package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// one runs a query expected to return a single row, mapping a miss to notFound.
//
// notFound is a parameter rather than always ErrNotFound because callers want to
// say which thing was missing — "no such network" and "no such role" send an
// operator to different places, and a bare ErrNotFound sends them to neither.
func one[T any](ctx context.Context, t *Tx, what string, notFound error,
	scan func(pgx.Row) (T, error), sql string, args ...any) (T, error) {
	v, err := scan(t.tx.QueryRow(ctx, sql, args...))
	if err != nil {
		var zero T
		if errors.Is(err, pgx.ErrNoRows) {
			if notFound == nil {
				notFound = ErrNotFound
			}
			return zero, notFound
		}
		return zero, mapErr(err, what)
	}
	return v, nil
}

// affected turns "the UPDATE or DELETE matched nothing" into a not-found error.
//
// Worth a helper because the bare form — `if tag.RowsAffected() == 0` — is easy
// to omit, and omitting it makes a mutation against a row that does not exist
// return success.
func affected(tag pgconn.CommandTag, what string) error {
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s: %w", what, ErrNotFound)
	}
	return nil
}

// mapErrAs is mapErr with a caller-chosen not-found error.
func mapErrAs(err error, what string, notFound error) error {
	if errors.Is(err, pgx.ErrNoRows) && notFound != nil {
		return notFound
	}
	return mapErr(err, what)
}
