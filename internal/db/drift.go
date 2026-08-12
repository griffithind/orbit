package db

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Schema drift, compared by NAME rather than by count.
//
// `orbitd doctor` used to compare `count(*)` against `len(Migrations())`, which
// is wrong in two directions at once. It cannot see the general case — N applied
// and N bundled with different names reports "up to date" — and on the one case
// it did detect, a database predating the migration collapse, it reported the
// opposite of the truth: 26 applied against 1 bundled took the "more applied
// than bundled" branch and told the operator their database had been migrated by
// a NEWER orbitd. It is older.
//
// See docs/adr/0026-a-process-that-disagrees-with-the-schema-refuses-to-serve.md.

// Drift is how a database's applied migration set differs from this binary's.
type Drift struct {
	// Missing are bundled here and not applied there: this binary is ahead, and
	// `orbitd migrate` is the answer.
	Missing []string

	// Unknown are applied there and not bundled here: the database has seen a
	// binary this one does not know about — or it predates the collapse.
	Unknown []string

	// PreCollapse means the database was migrated by a build from before the
	// twenty-six sequential migrations were collapsed into one initial schema.
	// Re-running the collapsed file against it fails on the first CREATE, safely
	// but opaquely, which is the failure this flag exists to name.
	PreCollapse bool
}

// OK reports whether this binary and this database agree.
func (d Drift) OK() bool { return len(d.Missing) == 0 && len(d.Unknown) == 0 }

// Reason states the disagreement and what to do about it, in one line each.
func (d Drift) Reason() string {
	switch {
	case d.OK():
		return "schema is up to date"
	case d.PreCollapse:
		return fmt.Sprintf(
			"this database predates the migration collapse: it records %d sequential "+
				"migrations (%s…) and none of this binary's %d. It cannot be migrated "+
				"forward — see docs/adr/0005-no-compatibility-before-v1.md, which "+
				"authorised the collapse as safe exactly once, before anything was deployed",
			len(d.Unknown), first(d.Unknown), len(d.Missing))
	case len(d.Unknown) > 0 && len(d.Missing) > 0:
		return fmt.Sprintf(
			"this database and this binary have diverged: it is missing %s and carries "+
				"%s, which this build does not bundle",
			list(d.Missing), list(d.Unknown))
	case len(d.Unknown) > 0:
		return fmt.Sprintf(
			"this database was migrated by a NEWER orbitd: it carries %s, which this "+
				"build does not bundle. Serving against it risks reading columns this "+
				"build does not know about", list(d.Unknown))
	default:
		return fmt.Sprintf(
			"this database is behind this binary: %s not applied. Run `orbitd migrate` "+
				"with THIS binary before serving; serve does not migrate", list(d.Missing))
	}
}

// CheckSchema reads the applied set and compares it to the bundled one.
func CheckSchema(ctx context.Context, conn *pgx.Conn) (Drift, error) {
	var d Drift

	applied := map[string]struct{}{}
	rows, err := conn.Query(ctx, `SELECT name FROM orbit.schema_migration`)
	if err != nil {
		return d, fmt.Errorf("read applied migrations: %w", err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return d, err
		}
		applied[n] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return d, err
	}

	bundled, err := Migrations()
	if err != nil {
		return d, err
	}
	have := map[string]struct{}{}
	for _, m := range bundled {
		have[m.Name] = struct{}{}
		if _, ok := applied[m.Name]; !ok {
			d.Missing = append(d.Missing, m.Name)
		}
	}
	for n := range applied {
		if _, ok := have[n]; !ok {
			d.Unknown = append(d.Unknown, n)
		}
	}
	sort.Strings(d.Missing)
	sort.Strings(d.Unknown)

	// A database that shares NO migration name with this binary, and has some of
	// its own, is not "ahead" — it is from before the names were rewritten. That
	// is the collapse, and it is the only rewrite this project has performed.
	d.PreCollapse = len(d.Unknown) > 0 && len(d.Missing) == len(bundled)

	return d, nil
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func list(s []string) string {
	if len(s) <= 3 {
		return strings.Join(s, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(s[:3], ", "), len(s)-3)
}
