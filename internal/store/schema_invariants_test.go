package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// countRow runs one counting query on an admin connection.
//
// A direct connection rather than the Store: these ask the catalog about the
// schema itself, which *store.Tx deliberately gives no way to do.
func countRow(t *testing.T, sql string, args ...any) int {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	var n int
	if err := conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	return n
}

// The invariants the schema is supposed to hold, checked against a live one.
//
// These were DO blocks inside the sequential migrations. Collapsing twenty-six
// files into one lost them, and the equivalence proof for that collapse could
// not have caught it: it compared catalog state — columns, constraints,
// indexes, grants, triggers — and a migration-time assertion leaves nothing in
// the catalog. It is invisible to exactly the method used to check the move was
// faithful.
//
// Restoring them as DO blocks would have been theatre. A DO block in
// 0001_initial.sql runs once, when the database is created, at which point the
// column it forbids cannot exist. Their teeth in the old layout came from
// ORDERING: 0018 ran after 0011 through 0017, so it was checking what earlier
// migrations had done. There are no earlier migrations now.
//
// As tests they are stronger than they ever were in either layout: they run on
// every CI run against the current schema, so they fail on the change that adds
// the column rather than on a fresh install that never happens again.

// TestNoTableHoldsPrivateKeyMaterial.
//
// The control plane holds public halves and sealed ciphertext, and that is the
// property the whole design rests on: an operator with database read access can
// impersonate nothing. Each of these tables is a plausible place to "just add a
// plaintext column" while debugging, and each would silently undo it.
func TestNoTableHoldsPrivateKeyMaterial(t *testing.T) {
	setup(t) // ensures the schema is migrated

	forbidden := map[string][]string{
		// Envelope encryption's whole point: database read access must not be
		// sufficient to mint a certificate.
		"secret": {"plaintext", "private_key", "key_pem", "unsealed", "secret_key"},
		// A control plane that can read a device key can impersonate the device.
		"device": {"private_key", "key_pem", "secret_key", "priv"},
		// A control plane that can read this can be impersonated as the network.
		"network": {"identity_private_key", "private_key", "key_pem", "identity_key"},
		// A session is a REFERENCE to a token. A copy of the token's scopes here
		// would survive that token's revocation — see store/session.go.
		"ui_session": {"scopes", "token", "token_hash", "bearer"},
	}

	var found []string
	for table, cols := range forbidden {
		for _, col := range cols {
			n := countRow(t, `
				SELECT count(*) FROM information_schema.columns
				 WHERE table_schema = 'orbit' AND table_name = $1 AND column_name = $2`,
				table, col)
			if n != 0 {
				found = append(found, "orbit."+table+"."+col)
			}
		}
	}
	if len(found) > 0 {
		t.Errorf("these columns must not exist: %v\n\n"+
			"The control plane holds public halves and sealed ciphertext. A column "+
			"here makes read access to the database sufficient to impersonate "+
			"something, which is the one property this design cannot lose.", found)
	}
}

// TestTheAppRoleCannotDestroyWhatItMustNotDestroy.
//
// Two grants that are load-bearing rather than tidy. The audit log is
// append-only because the application role holds no grant to rewrite it — not
// because no code does. And orbit.kek holds the single row every stored secret
// is sealed against: dropping it orphans every CA signing key in the deployment
// and cannot be undone, so the application must not be able to.
//
// 0002's version of the audit assertion is the reason the REVOKE beside it
// exists at all — it was written expecting the GRANT to be enough, and failed
// on its first run.
func TestTheAppRoleCannotDestroyWhatItMustNotDestroy(t *testing.T) {
	setup(t)

	for _, c := range []struct{ table, privilege, why string }{
		{"audit_log", "UPDATE", "an audit trail the application can rewrite is not an audit trail"},
		{"audit_log", "DELETE", "an audit trail the application can erase is not an audit trail"},
		{"kek", "DELETE", "dropping that row orphans every stored secret and cannot be undone"},
		{"kek", "TRUNCATE", "same, by another name"},
	} {
		n := countRow(t, `
			SELECT count(*) FROM information_schema.table_privileges
			 WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
			   AND table_name = $1 AND privilege_type = $2`, c.table, c.privilege)
		if n != 0 {
			t.Errorf("orbit_app holds %s on orbit.%s: %s", c.privilege, c.table, c.why)
		}
	}

	// And the positive half, so a migration that revokes too much fails here
	// rather than at the first write of an incident.
	for _, c := range []struct{ table, privilege string }{
		{"audit_log", "INSERT"},
		{"secret", "INSERT"},
		{"ui_session", "INSERT"},
		{"ui_session", "UPDATE"},
		{"device", "INSERT"},
		{"device", "UPDATE"},
		{"network_policy", "INSERT"},
	} {
		n := countRow(t, `
			SELECT count(*) FROM information_schema.table_privileges
			 WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
			   AND table_name = $1 AND privilege_type = $2`, c.table, c.privilege)
		if n == 0 {
			t.Errorf("orbit_app lacks %s on orbit.%s, which it needs to work", c.privilege, c.table)
		}
	}
}
