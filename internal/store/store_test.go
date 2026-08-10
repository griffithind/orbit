package store_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/db"
	"github.com/griffithind/orbit/internal/store"
)

// These tests run against a real Postgres. The invariants they cover are
// enforced by the database — partial unique indexes, conditional updates,
// grants — so an in-memory double would test nothing.
//
//	make db-up && go test ./...
//
// Tests skip (not fail) when no database is reachable, so `go test ./...`
// stays useful without Docker.

const (
	defaultAdminDSN = "postgres://postgres:orbit@localhost:5433/orbit?sslmode=disable"
	appPassword     = "orbit_app_test"
)

var (
	testStore *store.Store
	setupOnce sync.Once
	setupErr  error
)

func adminDSN() string {
	if v := os.Getenv("ORBIT_TEST_DSN"); v != "" {
		return v
	}
	return defaultAdminDSN
}

// appDSN derives the unprivileged connection string from the admin one.
// Connecting as the app role matters for the append-only audit test: the
// migration role owns the tables and could rewrite the log.
func appDSN() string {
	if v := os.Getenv("ORBIT_TEST_APP_DSN"); v != "" {
		return v
	}
	return fmt.Sprintf("postgres://orbit_app:%s@localhost:5433/orbit?sslmode=disable", appPassword)
}

func setup(t *testing.T) *store.Store {
	t.Helper()
	setupOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		admin, err := pgx.Connect(ctx, adminDSN())
		if err != nil {
			setupErr = fmt.Errorf("connect as admin: %w", err)
			return
		}
		defer admin.Close(ctx)

		if _, err := db.Migrate(ctx, admin); err != nil {
			setupErr = fmt.Errorf("migrate: %w", err)
			return
		}

		// Migrations create orbit_app NOLOGIN and set no password, since
		// credentials are a deployment concern. Give it one for the test.
		// EnsureRoleLogin serializes on the migration advisory lock; the e2e
		// package does the same thing, and go test runs packages in parallel.
		if err := db.EnsureRoleLogin(ctx, admin, "orbit_app", appPassword); err != nil {
			setupErr = err
			return
		}

		s, err := store.Open(ctx, appDSN())
		if err != nil {
			setupErr = fmt.Errorf("connect as orbit_app: %w", err)
			return
		}
		testStore = s
	})

	if setupErr != nil {
		t.Skipf("postgres unavailable, skipping store tests: %v", setupErr)
	}
	return testStore
}

func quoteLiteral(s string) string { return "'" + s + "'" }

// newNetwork creates an isolated network. Every test gets its own so they can
// run in any order without interfering.
func newNetwork(t *testing.T, s *store.Store, cidr string) *store.Network {
	t.Helper()

	var net store.Network
	err := s.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		net = store.Network{
			Name:  "net-" + uuid.NewString()[:8],
			CIDRs: []netip.Prefix{netip.MustParsePrefix(cidr)},
		}
		withIdentity(t, &net)
		return tx.CreateNetwork(ctx, &net)
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	return &net
}

func newHost(t *testing.T, s *store.Store, net *store.Network, name, addr string) *store.Membership {
	t.Helper()
	var h store.Membership
	err := s.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		h = store.Membership{
			NetworkID: net.ID,
			Name:      name,
			Addrs:     []netip.Addr{netip.MustParseAddr(addr)},
			State:     store.MembershipActive,
		}
		return insertHost(ctx, tx, &h)
	})
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	return &h
}

// TestOverlappingNetworkCIDRs covers two networks using the same prefix. They
// are separate meshes and never exchange traffic, so this is legal — and it is
// why the agent lookup takes a network id rather than inferring one from the
// address. Dropping multi-tenancy did not remove this case: one organization
// can perfectly well run prod and staging on the same numbering.
func TestOverlappingNetworkCIDRs(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	netA := newNetwork(t, s, "10.42.0.0/16")
	netB := newNetwork(t, s, "10.42.0.0/16") // same prefix, different mesh

	hostA := newHost(t, s, netA, "a", "10.42.0.7")
	hostB := newHost(t, s, netB, "b", "10.42.0.7") // same address

	addr := netip.MustParseAddr("10.42.0.7")

	gotA, err := s.ResolveAgentHost(ctx, netA.ID, addr)
	if err != nil {
		t.Fatalf("ResolveAgentHost(A): %v", err)
	}
	if gotA.MembershipID != hostA.ID {
		t.Errorf("resolved to the wrong host for network A")
	}

	gotB, err := s.ResolveAgentHost(ctx, netB.ID, addr)
	if err != nil {
		t.Fatalf("ResolveAgentHost(B): %v", err)
	}
	if gotB.MembershipID != hostB.ID {
		t.Errorf("resolved to the wrong host for network B")
	}
}

//------------------------------------------------------------------------------
// Database-enforced invariants
//------------------------------------------------------------------------------

// TestOverlayAddressUniqueness proves address allocation cannot be raced. Two
// hosts claiming one address would leave one of them unable to communicate.
func TestOverlayAddressUniqueness(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	newHost(t, s, net, "first", "10.42.0.7")

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		h := store.Membership{
			NetworkID: net.ID,
			Name:      "second",
			Addrs:     []netip.Addr{netip.MustParseAddr("10.42.0.7")},
		}
		return insertHost(ctx, tx, &h)
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate address error = %v, want ErrConflict", err)
	}
}

// TestOneActiveCAPerNetwork proves issuance can never be ambiguous, and that
// rotation still works despite the constraint.
func TestOneActiveCAPerNetwork(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	now := time.Now()

	mkCA := func(tx *store.Tx, name string) *store.CA {
		c := store.CA{
			NetworkID: net.ID, Name: name,
			Fingerprint: uuid.NewString(), CertPEM: "-----BEGIN NEBULA CERTIFICATE-----\n",
			SignerRef: "file://dev.key", Curve: "P256",
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		}
		if err := tx.CreateCA(ctx, &c); err != nil {
			t.Fatalf("CreateCA: %v", err)
		}
		return &c
	}

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		ca1 := mkCA(tx, "ca-1")
		ca2 := mkCA(tx, "ca-2")

		// No active CA yet.
		if _, err := tx.GetActiveCA(ctx, net.ID); !errors.Is(err, store.ErrNoActived) {
			t.Errorf("GetActiveCA with none active = %v, want ErrNoActived", err)
		}

		if err := tx.ActivateCA(ctx, net.ID, ca1.ID); err != nil {
			t.Fatalf("ActivateCA(ca1): %v", err)
		}
		got, err := tx.GetActiveCA(ctx, net.ID)
		if err != nil {
			t.Fatalf("GetActiveCA: %v", err)
		}
		if got.ID != ca1.ID {
			t.Errorf("active CA = %s, want ca1", got.Name)
		}

		// Rotation: promoting ca2 must demote ca1 in the same transaction, or
		// the partial unique index would reject it.
		if err := tx.ActivateCA(ctx, net.ID, ca2.ID); err != nil {
			t.Fatalf("ActivateCA(ca2): %v", err)
		}
		got, err = tx.GetActiveCA(ctx, net.ID)
		if err != nil {
			t.Fatalf("GetActiveCA after rotation: %v", err)
		}
		if got.ID != ca2.ID {
			t.Errorf("active CA after rotation = %s, want ca2", got.Name)
		}

		// Both are still in the trust bundle: retiring, not retired. This
		// overlap is what makes rotation safe for hosts that have not yet
		// converged.
		bundle, err := tx.TrustBundlePEM(ctx, net.ID)
		if err != nil {
			t.Fatalf("TrustBundlePEM: %v", err)
		}
		if len(bundle) == 0 {
			t.Error("trust bundle is empty")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestEnrollmentCredentialSingleUse runs concurrent redemptions of one
// credential and asserts exactly one wins.
//
// This is the security property the entire enrollment path rests on. The
// arbiter is a conditional UPDATE inside a SECURITY DEFINER function, not a
// check-then-write in Go, precisely so that this test can pass under
// concurrency.
func TestEnrollmentCredentialSingleUse(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	host := newHost(t, s, net, "enrolling", "10.42.0.7")

	secretHash := []byte("argon2id-hash-stand-in-" + uuid.NewString())
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		c := store.EnrollmentCredential{
			NetworkID:    net.ID,
			MembershipID: &host.ID,
			Method:       store.MethodCode,
			ExpiresAt:    time.Now().Add(15 * time.Minute),
		}
		return tx.CreateEnrollmentCredential(ctx, &c, secretHash)
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentCredential: %v", err)
	}

	const racers = 16
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		wins     int
		notFound int
	)
	from := netip.MustParseAddr("203.0.113.9")

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.RedeemEnrollmentCredential(ctx, secretHash, from)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, store.ErrNotFound):
				notFound++
			default:
				t.Errorf("unexpected redemption error: %v", err)
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Errorf("%d concurrent redemptions succeeded, want exactly 1", wins)
	}
	if notFound != racers-1 {
		t.Errorf("%d redemptions rejected, want %d", notFound, racers-1)
	}
}

// TestExpiredCredentialCannotBeRedeemed covers the TTL half of the guarantee.
func TestExpiredCredentialCannotBeRedeemed(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	host := newHost(t, s, net, "late", "10.42.0.8")

	secretHash := []byte("expired-" + uuid.NewString())
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		c := store.EnrollmentCredential{
			NetworkID: net.ID, MembershipID: &host.ID, Method: store.MethodCode,
			ExpiresAt: time.Now().Add(-time.Minute),
		}
		return tx.CreateEnrollmentCredential(ctx, &c, secretHash)
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentCredential: %v", err)
	}

	if _, err := s.RedeemEnrollmentCredential(ctx, secretHash, netip.Addr{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("redeeming an expired credential = %v, want ErrNotFound", err)
	}
}

// TestAuditLogIsAppendOnly proves the application role holds no UPDATE or
// DELETE grant. An audit trail the application can rewrite is not one.
func TestAuditLogIsAppendOnly(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	newNetwork(t, s, "10.42.0.0/16")

	// A unique target: the audit log is deployment-wide, so a test that counts
	// every row counts every other test's rows too.
	target := uuid.NewString()

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "user", ActorID: "alice",
			Action: store.ActionMembershipCreated, TargetType: "host", TargetID: target,
		})
	})
	if err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	// Attempt to tamper, using the pool directly to bypass the store's API.
	_, err = s.Pool().Exec(ctx, `UPDATE orbit.audit_log SET action = 'tampered'`)
	if err == nil {
		t.Error("application role was able to UPDATE the audit log")
	}
	_, err = s.Pool().Exec(ctx, `DELETE FROM orbit.audit_log`)
	if err == nil {
		t.Error("application role was able to DELETE from the audit log")
	}

	// And reading back works normally.
	err = s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		recs, err := tx.ListAudit(ctx, store.AuditFilter{TargetID: target})
		if err != nil {
			return err
		}
		if len(recs) != 1 {
			t.Errorf("audit entries for %s = %d, want 1", target, len(recs))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestHostRoleIsScopedToNetwork proves the database refuses to assign a host a
// role belonging to a different network.
//
// Nothing in Go checks this: internal/api/admin.go parses role_id and
// internal/store/host.go stores it, neither comparing role.network_id against
// host.network_id. That is the right division of labour — an application-layer
// check can be raced by a concurrent request, and a control plane that mints
// identities cannot rest an isolation property on one — but it means the
// role_network_id_fkey in 0001_initial.sql is the only thing standing
// between an operator typo and network B's firewall rules being rendered
// verbatim into a network A host's config by enroll.renderFor.
//
// A foreign-key violation surfaces as ErrNotFound (mapErr, 23503), which is the
// honest answer: no such role exists in this host's network.
func TestHostRoleIsScopedToNetwork(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	netA := newNetwork(t, s, "10.42.0.0/16")
	netB := newNetwork(t, s, "10.43.0.0/16")

	var roleA, roleB store.Role
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		roleA = store.Role{NetworkID: netA.ID, Name: "web"}
		if err := tx.CreateRole(ctx, &roleA); err != nil {
			return err
		}
		roleB = store.Role{NetworkID: netB.ID, Name: "web"}
		return tx.CreateRole(ctx, &roleB)
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	// Baseline: a host with no role, and a host with a role from its own
	// network, both insert. The constraint is composite and MATCH SIMPLE, so a
	// NULL role_id skips it entirely — "a host may have no role" must survive.
	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		h := store.Membership{NetworkID: netA.ID, Name: "no-role"}
		return insertHost(ctx, tx, &h)
	})
	if err != nil {
		t.Fatalf("CreateHost without a role: %v", err)
	}

	var hostA store.Membership
	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		hostA = store.Membership{NetworkID: netA.ID, Name: "same-network", RoleID: &roleA.ID}
		return insertHost(ctx, tx, &hostA)
	})
	if err != nil {
		t.Fatalf("CreateHost with a role from its own network: %v", err)
	}

	// Creation with another network's role.
	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		h := store.Membership{NetworkID: netA.ID, Name: "cross-network", RoleID: &roleB.ID}
		return insertHost(ctx, tx, &h)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("CreateHost with network B's role = %v, want ErrNotFound", err)
	}

	// And the update path, which is what PATCH /v1/memberships/:id reaches through
	// UpdateHostMeta. Closing only the insert would leave the hole open to any
	// host that was created correctly and re-roled afterwards.
	crossRole := roleB.ID.String()
	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.UpdateHostMeta(ctx, hostA.ID, &crossRole, nil)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UpdateHostMeta to network B's role = %v, want ErrNotFound", err)
	}

	// The rejected update must not have taken effect.
	err = s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		got, err := tx.GetHost(ctx, hostA.ID)
		if err != nil {
			return err
		}
		if got.RoleID == nil || *got.RoleID != roleA.ID {
			t.Errorf("host role after the rejected update = %v, want %v", got.RoleID, roleA.ID)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestFutureTablesAreGrantedToAppRole covers ALTER DEFAULT PRIVILEGES.
//
// The GRANT ... ON ALL TABLES in 0001_initial.sql is evaluated once and covers only the tables
// that existed at that moment, so a table created by a later migration reached
// production with no grant to orbit_app — a failure that shows up as a runtime
// permission error rather than a migration failure. This asserts the standing
// rule that replaced it, by creating a table the way a migration would and
// checking the app role can use it without any explicit grant.
func TestFutureTablesAreGrantedToAppRole(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, adminDSN())
	if err != nil {
		t.Skipf("connect as admin: %v", err)
	}
	defer admin.Close(ctx)

	// Unique per run: packages run in parallel and this table is deployment-wide.
	table := "orbit.grant_probe_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx,
		"CREATE TABLE "+table+" (id bigserial PRIMARY KEY, v text)"); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(cctx, adminDSN())
		if err != nil {
			return
		}
		defer conn.Close(cctx)
		_, _ = conn.Exec(cctx, "DROP TABLE IF EXISTS "+table)
	})

	// Deliberately no GRANT. Everything below comes from the default privileges.
	for _, stmt := range []string{
		"INSERT INTO " + table + " (v) VALUES ('x')",
		"SELECT * FROM " + table,
		"UPDATE " + table + " SET v = 'y'",
		"DELETE FROM " + table,
	} {
		if _, err := s.Pool().Exec(ctx, stmt); err != nil {
			t.Errorf("app role could not run %q on a newly created table: %v", stmt, err)
		}
	}

	// The default rule grants UPDATE and DELETE, which is right for an ordinary
	// table and wrong for an append-only one. Re-assert that adding it did not
	// loosen the audit log, since that is the property it could plausibly break.
	var upd, del bool
	if err := s.Pool().QueryRow(ctx, `
		SELECT has_table_privilege('orbit_app', 'orbit.audit_log', 'UPDATE'),
		       has_table_privilege('orbit_app', 'orbit.audit_log', 'DELETE')`,
	).Scan(&upd, &del); err != nil {
		t.Fatalf("query audit_log privileges: %v", err)
	}
	if upd || del {
		t.Errorf("orbit_app holds UPDATE=%v DELETE=%v on orbit.audit_log; want neither", upd, del)
	}
}

//------------------------------------------------------------------------------
// Revocation and convergence
//------------------------------------------------------------------------------

// TestBlockHostFlow exercises the transaction behind POST /v1/memberships/:id/block:
// revoke certificates, add blocklist entries, suspend the host, advance the
// epoch, all atomically.
func TestBlockHostFlow(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	host := newHost(t, s, net, "doomed", "10.42.0.7")
	now := time.Now()

	var caID uuid.UUID
	var fingerprint string
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		c := store.CA{
			NetworkID: net.ID, Name: "ca", Fingerprint: uuid.NewString(),
			CertPEM: "pem", SignerRef: "file://k", Curve: "P256",
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		}
		if err := tx.CreateCA(ctx, &c); err != nil {
			return err
		}
		if err := tx.ActivateCA(ctx, net.ID, c.ID); err != nil {
			return err
		}
		caID = c.ID

		fingerprint = uuid.NewString()
		cert := store.Certificate{
			MembershipID: host.ID, CAID: caID, Fingerprint: fingerprint, PEM: "pem",
			CertVer: 2, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		}
		return tx.InsertCertificate(ctx, &cert)
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	var epochBefore, epochAfter int64
	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		n, err := tx.GetNetwork(ctx, net.ID)
		if err != nil {
			return err
		}
		epochBefore = n.BlocklistEpoch

		epochAfter, err = tx.BlockHost(ctx, host.ID, "compromised")
		return err
	})
	if err != nil {
		t.Fatalf("BlockHost: %v", err)
	}

	if epochAfter <= epochBefore {
		t.Errorf("blocklist epoch did not advance: %d -> %d", epochBefore, epochAfter)
	}

	err = s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		fps, err := tx.LiveBlocklist(ctx, net.ID, time.Now())
		if err != nil {
			return err
		}
		if len(fps) != 1 || fps[0] != fingerprint {
			t.Errorf("blocklist = %v, want [%s]", fps, fingerprint)
		}

		h, err := tx.GetHost(ctx, host.ID)
		if err != nil {
			return err
		}
		if h.State != store.MembershipSuspended {
			t.Errorf("host state = %q, want suspended", h.State)
		}

		certs, err := tx.ActiveCertificates(ctx, host.ID)
		if err != nil {
			return err
		}
		if len(certs) != 0 {
			t.Errorf("host still has %d active certificates after blocking", len(certs))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestLiveBlocklistExcludesExpired covers the pruning rule. Nebula rejects an
// expired certificate before consulting the blocklist, so distributing the
// fingerprint costs bytes in every host's config and buys nothing. Without this
// the blocklist grows without bound.
func TestLiveBlocklistExcludesExpired(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	now := time.Now()

	// Two hosts: one with a live certificate, one already expired.
	live := newHost(t, s, net, "live", "10.42.0.10")
	stale := newHost(t, s, net, "stale", "10.42.0.11")

	var liveFP, staleFP string
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		ca := store.CA{
			NetworkID: net.ID, Name: "ca", Fingerprint: uuid.NewString(),
			CertPEM: "pem", SignerRef: "file://k", Curve: "P256",
			NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		}
		if err := tx.CreateCA(ctx, &ca); err != nil {
			return err
		}

		liveFP, staleFP = uuid.NewString(), uuid.NewString()
		c1 := store.Certificate{
			MembershipID: live.ID, CAID: ca.ID, Fingerprint: liveFP, PEM: "p", CertVer: 2,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		}
		if err := tx.InsertCertificate(ctx, &c1); err != nil {
			return err
		}
		c2 := store.Certificate{
			MembershipID: stale.ID, CAID: ca.ID, Fingerprint: staleFP, PEM: "p", CertVer: 2,
			NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour),
		}
		return tx.InsertCertificate(ctx, &c2)
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.BlockHost(ctx, live.ID, "compromised"); err != nil {
			return err
		}
		_, err := tx.BlockHost(ctx, stale.ID, "decommissioned")
		return err
	})
	if err != nil {
		t.Fatalf("BlockHost: %v", err)
	}

	err = s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		fps, err := tx.LiveBlocklist(ctx, net.ID, time.Now())
		if err != nil {
			return err
		}
		if len(fps) != 1 || fps[0] != liveFP {
			t.Errorf("live blocklist = %v, want only the unexpired fingerprint %s", fps, liveFP)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAgentReportIsMonotonic proves a replayed or rolled-back agent report
// cannot lower a recorded epoch. Allowing regression would make a network look
// less converged than it is and could stall a CA rotation indefinitely.
func TestAgentReportIsMonotonic(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	host := newHost(t, s, net, "reporter", "10.42.0.7")

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := tx.RecordAgentReport(ctx, host.ID, store.AgentReport{
			ConfigEpoch: 5, BlocklistEpoch: 5, AgentVersion: "0.1.0",
		}); err != nil {
			return err
		}
		// A stale replay.
		if err := tx.RecordAgentReport(ctx, host.ID, store.AgentReport{
			ConfigEpoch: 2, BlocklistEpoch: 1,
		}); err != nil {
			return err
		}

		h, err := tx.GetHost(ctx, host.ID)
		if err != nil {
			return err
		}
		if h.AppliedConfigEpoch != 5 || h.AppliedBlocklistEpoch != 5 {
			t.Errorf("epochs regressed to (%d, %d), want (5, 5)",
				h.AppliedConfigEpoch, h.AppliedBlocklistEpoch)
		}
		if h.AgentVersion != "0.1.0" {
			t.Errorf("agent version = %q, want 0.1.0", h.AgentVersion)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestConvergence covers the measurement that gates CA rotation and backs the
// revocation SLO.
func TestConvergence(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	h1 := newHost(t, s, net, "converged", "10.42.0.1")
	h2 := newHost(t, s, net, "lagging", "10.42.0.2")

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		epoch, err := tx.BumpEpoch(ctx, net.ID, store.EpochBlocklist)
		if err != nil {
			return err
		}

		// Only h1 reports applying it.
		if err := tx.RecordAgentReport(ctx, h1.ID, store.AgentReport{
			ConfigEpoch: 1, BlocklistEpoch: epoch,
		}); err != nil {
			return err
		}

		c, err := tx.Convergence(ctx, net.ID, 10)
		if err != nil {
			return err
		}
		if c.MembershipsTotal != 2 {
			t.Errorf("hosts total = %d, want 2", c.MembershipsTotal)
		}
		if c.BlockApplied != 1 {
			t.Errorf("blocklist converged = %d, want 1", c.BlockApplied)
		}
		if len(c.Lagging) != 1 || c.Lagging[0].MembershipID != h2.ID {
			t.Errorf("lagging = %+v, want just %s", c.Lagging, h2.Name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestCertificateSupersedesPerVersion proves renewal supersedes the previous
// certificate of the same version only. During a v1 to v2 migration a host
// legitimately holds one active certificate of each, and superseding across
// versions would revoke half of a working configuration.
func TestCertificateSupersedesPerVersion(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	host := newHost(t, s, net, "migrating", "10.42.0.7")
	now := time.Now()

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		ca := store.CA{
			NetworkID: net.ID, Name: "ca", Fingerprint: uuid.NewString(),
			CertPEM: "pem", SignerRef: "file://k", Curve: "P256",
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		}
		if err := tx.CreateCA(ctx, &ca); err != nil {
			return err
		}

		mk := func(ver int16) store.Certificate {
			return store.Certificate{
				MembershipID: host.ID, CAID: ca.ID, Fingerprint: uuid.NewString(), PEM: "p",
				CertVer: ver, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
			}
		}

		v1, v2 := mk(1), mk(2)
		if err := tx.InsertCertificate(ctx, &v1); err != nil {
			return err
		}
		if err := tx.InsertCertificate(ctx, &v2); err != nil {
			return err
		}

		certs, err := tx.ActiveCertificates(ctx, host.ID)
		if err != nil {
			return err
		}
		if len(certs) != 2 {
			t.Fatalf("active certificates = %d, want 2 (one per version)", len(certs))
		}

		// Renew v2 only; v1 must survive.
		v2b := mk(2)
		if err := tx.InsertCertificate(ctx, &v2b); err != nil {
			return err
		}
		certs, err = tx.ActiveCertificates(ctx, host.ID)
		if err != nil {
			return err
		}
		if len(certs) != 2 {
			t.Errorf("active certificates after renewal = %d, want 2", len(certs))
		}
		for _, c := range certs {
			if c.CertVer == 2 && c.ID != v2b.ID {
				t.Error("renewal did not supersede the previous v2 certificate")
			}
			if c.CertVer == 1 && c.ID != v1.ID {
				t.Error("renewing v2 disturbed the v1 certificate")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

//------------------------------------------------------------------------------
// Membership listing: filters, keyset pagination, count
//------------------------------------------------------------------------------

// listHosts is the common "one page, no filters beyond these" call.
func listHosts(t *testing.T, s *store.Store, f store.MembershipFilter) store.MembershipPage {
	t.Helper()
	var page store.MembershipPage
	err := s.Read(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		page, err = tx.ListHosts(ctx, f)
		return err
	})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	return page
}

func membershipNames(page store.MembershipPage) []string {
	out := make([]string, 0, len(page.Memberships))
	for _, h := range page.Memberships {
		out = append(out, h.Name)
	}
	return out
}

// TestListHostsFiltersInSQL covers every filter the store offers, and asserts
// the role name comes back with the host.
//
// The filters exist because an operator's questions are not "give me every
// host": they are "what is suspended", "what carries this tag", "what carries
// this role", and "the web boxes". Answering those in Go would mean fetching
// the whole table per request — the cost NetworkTopology's comment describes.
func TestListHostsFiltersInSQL(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")

	var web, db store.Role
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		web = store.Role{NetworkID: net.ID, Name: "web"}
		if err := tx.CreateRole(ctx, &web); err != nil {
			return err
		}
		db = store.Role{NetworkID: net.ID, Name: "db"}
		return tx.CreateRole(ctx, &db)
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		hosts := []store.Membership{
			{NetworkID: net.ID, Name: "web-01", RoleID: &web.ID,
				Tags: []string{"prod", "eu"}, State: store.MembershipActive,
				Addrs: []netip.Addr{netip.MustParseAddr("10.42.0.1")}},
			{NetworkID: net.ID, Name: "web-02", RoleID: &web.ID,
				Tags: []string{"staging"}, State: store.MembershipSuspended,
				Addrs: []netip.Addr{netip.MustParseAddr("10.42.0.2")}},
			{NetworkID: net.ID, Name: "db-01", RoleID: &db.ID,
				Tags: []string{"prod"}, State: store.MembershipActive,
				Addrs: []netip.Addr{netip.MustParseAddr("10.42.0.3")}},
			{NetworkID: net.ID, Name: "unroled", State: store.MembershipCreated,
				Addrs: []netip.Addr{netip.MustParseAddr("10.42.0.4")}},
		}
		for i := range hosts {
			if err := insertHost(ctx, tx, &hosts[i]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	base := store.MembershipFilter{NetworkID: net.ID}

	cases := []struct {
		name   string
		filter store.MembershipFilter
		want   []string
	}{
		{"unfiltered", base, []string{"db-01", "unroled", "web-01", "web-02"}},
		{"state", store.MembershipFilter{NetworkID: net.ID, State: store.MembershipSuspended}, []string{"web-02"}},
		{"tag", store.MembershipFilter{NetworkID: net.ID, Tag: "prod"}, []string{"db-01", "web-01"}},
		{"role", store.MembershipFilter{NetworkID: net.ID, RoleID: &web.ID}, []string{"web-01", "web-02"}},
		{"name substring", store.MembershipFilter{NetworkID: net.ID, NameContains: "eb-0"}, []string{"web-01", "web-02"}},
		// Case-insensitive: an operator typing a hostname does not think about case.
		{"name case", store.MembershipFilter{NetworkID: net.ID, NameContains: "WEB"}, []string{"web-01", "web-02"}},
		// A name containing a LIKE metacharacter must be matched literally. With
		// LIKE, "_01" would match "web-01" too and the filter would quietly
		// answer a different question than the one asked.
		{"name metacharacter", store.MembershipFilter{NetworkID: net.ID, NameContains: "b_01"}, nil},
		{"combined", store.MembershipFilter{NetworkID: net.ID, RoleID: &web.ID, Tag: "prod"}, []string{"web-01"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := membershipNames(listHosts(t, s, tc.filter))
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("names = %v, want %v", got, tc.want)
			}
		})
	}

	// The role name has to arrive with the host, or a client rendering a list
	// makes one lookup per row.
	for _, h := range listHosts(t, s, base).Memberships {
		switch h.Name {
		case "web-01", "web-02":
			if h.RoleName != "web" {
				t.Errorf("%s role name = %q, want web", h.Name, h.RoleName)
			}
		case "unroled":
			if h.RoleName != "" || h.RoleID != nil {
				t.Errorf("unroled host has role %v/%q", h.RoleID, h.RoleName)
			}
		}
	}
}

// TestListHostsBehindFilter covers the incident question: which hosts have not
// applied the current generation. It must agree with Convergence, which counts
// only enrolled and active hosts — a host in 'created' has never held a
// certificate and can never report an epoch.
func TestListHostsBehindFilter(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	caughtUp := newHost(t, s, net, "caught-up", "10.42.1.1")
	newHost(t, s, net, "behind", "10.42.1.2")

	// A host that never enrolled: behind by the numbers, excluded on purpose.
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		h := store.Membership{NetworkID: net.ID, Name: "never-enrolled", State: store.MembershipCreated,
			Addrs: []netip.Addr{netip.MustParseAddr("10.42.1.3")}}
		return insertHost(ctx, tx, &h)
	})
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	var conv *store.Convergence
	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		epoch, err := tx.BumpEpoch(ctx, net.ID, store.EpochConfig)
		if err != nil {
			return err
		}
		if err := tx.RecordAgentReport(ctx, caughtUp.ID, store.AgentReport{
			ConfigEpoch: epoch, BlocklistEpoch: 1,
		}); err != nil {
			return err
		}
		conv, err = tx.Convergence(ctx, net.ID, 10)
		return err
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	page := listHosts(t, s, store.MembershipFilter{NetworkID: net.ID, Behind: true})
	got := membershipNames(page)
	if fmt.Sprint(got) != fmt.Sprint([]string{"behind"}) {
		t.Errorf("behind = %v, want [behind]", got)
	}
	// The filter and the convergence endpoint must not disagree about who is
	// behind; two numbers for one question is how an operator loses trust in
	// both.
	if len(got) != conv.MembershipsTotal-conv.ConfigApplied {
		t.Errorf("behind filter returned %d hosts, convergence says %d are lagging",
			len(got), conv.MembershipsTotal-conv.ConfigApplied)
	}
}

// TestListHostsKeysetPagination covers the two boundaries that actually break.
//
// First, a page edge that lands exactly on the last row: a listing that decides
// "there is more" by comparing the row count with the limit hands out a cursor
// that returns nothing, and a client that trusts it shows an empty final page.
//
// Second, a host created between two page fetches. Under OFFSET, an insert
// before the offset shifts every later page by one and a row is silently
// skipped; a keyset cursor names a position, so what came before it cannot
// move.
func TestListHostsKeysetPagination(t *testing.T) {
	s := setup(t)
	net := newNetwork(t, s, "10.42.0.0/16")
	for i, name := range []string{"a", "b", "c", "d"} {
		newHost(t, s, net, name, fmt.Sprintf("10.42.2.%d", i+1))
	}

	// Four hosts, two per page: the second page is exactly full and is still
	// the last one.
	var (
		seen   []string
		cursor *store.MembershipCursor
		pages  int
	)
	for {
		page := listHosts(t, s, store.MembershipFilter{NetworkID: net.ID, Limit: 2, After: cursor})
		pages++
		seen = append(seen, membershipNames(page)...)
		if !page.More {
			if len(page.Memberships) != 2 {
				t.Errorf("final page had %d hosts, want 2 (an exactly-full last page)", len(page.Memberships))
			}
			break
		}
		if len(page.Memberships) == 0 {
			t.Fatal("a page reported More with no rows to build a cursor from")
		}
		last := page.Memberships[len(page.Memberships)-1]
		cursor = &store.MembershipCursor{Name: last.Name, ID: last.ID}
		if pages > 5 {
			t.Fatal("pagination did not terminate")
		}
	}
	if pages != 2 {
		t.Errorf("walked %d pages, want 2 — the last full page must not claim a next one", pages)
	}
	if fmt.Sprint(seen) != fmt.Sprint([]string{"a", "b", "c", "d"}) {
		t.Errorf("paged names = %v, want [a b c d]", seen)
	}

	// Now the concurrent insert. Take the first page, create a host that sorts
	// before the cursor and one that sorts after, then take the second page.
	first := listHosts(t, s, store.MembershipFilter{NetworkID: net.ID, Limit: 2})
	last := first.Memberships[len(first.Memberships)-1]
	after := &store.MembershipCursor{Name: last.Name, ID: last.ID}

	newHost(t, s, net, "a-inserted", "10.42.2.20") // before the cursor
	newHost(t, s, net, "c-inserted", "10.42.2.21") // after it

	second := listHosts(t, s, store.MembershipFilter{NetworkID: net.ID, Limit: 2, After: after})
	got := membershipNames(second)
	// "c" is still the row after the cursor: the insert before it did not shift
	// the window, which is exactly what OFFSET would have got wrong.
	if fmt.Sprint(got) != fmt.Sprint([]string{"c", "c-inserted"}) {
		t.Errorf("page after a concurrent insert = %v, want [c c-inserted]", got)
	}
	if !second.More {
		t.Error("second page should report more: d is still unread")
	}

	// A cursor past the end is an empty page, not an error.
	end := listHosts(t, s, store.MembershipFilter{
		NetworkID: net.ID,
		After:     &store.MembershipCursor{Name: "zzz", ID: uuid.Nil},
	})
	if len(end.Memberships) != 0 || end.More {
		t.Errorf("cursor past the end returned %d hosts (more=%v)", len(end.Memberships), end.More)
	}
}

// TestListHostsCountIsOptIn proves the count describes the filter rather than
// the page, and that not asking is different from a count of zero.
func TestListHostsCountIsOptIn(t *testing.T) {
	s := setup(t)
	net := newNetwork(t, s, "10.42.0.0/16")
	for i, name := range []string{"one", "two", "three"} {
		newHost(t, s, net, name, fmt.Sprintf("10.42.3.%d", i+1))
	}

	page := listHosts(t, s, store.MembershipFilter{NetworkID: net.ID, Limit: 2})
	if page.Total != nil {
		t.Errorf("count was returned without being asked for: %d", *page.Total)
	}

	page = listHosts(t, s, store.MembershipFilter{NetworkID: net.ID, Limit: 2, WithCount: true})
	if page.Total == nil {
		t.Fatal("WithCount returned no total")
	}
	if *page.Total != 3 {
		t.Errorf("total = %d, want 3 (the filter, not the page)", *page.Total)
	}
	if len(page.Memberships) != 2 {
		t.Errorf("page = %d hosts, want 2", len(page.Memberships))
	}

	// And it narrows with the filter, or it is not a count of anything useful.
	page = listHosts(t, s, store.MembershipFilter{
		NetworkID: net.ID, NameContains: "t", WithCount: true,
	})
	if page.Total == nil || *page.Total != 2 {
		t.Errorf("filtered total = %v, want 2", page.Total)
	}
}

//------------------------------------------------------------------------------
// Certificate history
//------------------------------------------------------------------------------

// TestHostCertificateHistory covers the listing behind
// GET /v1/memberships/{id}/certificates: newest first, the issuing CA by name, and a
// cursor that works when every row shares a timestamp.
//
// Sharing a timestamp is the normal case, not a contrived one: issued_at
// defaults to now(), which in Postgres is the transaction's start time, and
// nebula's second-granularity validity means renewals genuinely collide. A
// cursor keyed on issued_at alone would re-serve or skip those rows.
func TestHostCertificateHistory(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.42.0.0/16")
	host := newHost(t, s, net, "renewer", "10.42.4.1")
	other := newHost(t, s, net, "bystander", "10.42.4.2")
	now := time.Now()

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		caRow := store.CA{
			NetworkID: net.ID, Name: "history-ca", Fingerprint: uuid.NewString(),
			CertPEM: "pem", SignerRef: "file://k", Curve: "P256",
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		}
		if err := tx.CreateCA(ctx, &caRow); err != nil {
			return err
		}

		// Four superseded renewals and one current certificate, all in one
		// transaction and therefore all with the same issued_at.
		for i := 0; i < 4; i++ {
			c := store.Certificate{
				MembershipID: host.ID, CAID: caRow.ID, Fingerprint: uuid.NewString(), PEM: "p",
				CertVer: 2, NotBefore: now.Add(-time.Duration(i+1) * time.Hour),
				NotAfter: now.Add(time.Duration(i) * time.Hour), State: store.CertSuperseded,
			}
			if err := tx.InsertCertificate(ctx, &c); err != nil {
				return err
			}
		}
		current := store.Certificate{
			MembershipID: host.ID, CAID: caRow.ID, Fingerprint: uuid.NewString(), PEM: "p",
			CertVer: 2, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		}
		if err := tx.InsertCertificate(ctx, &current); err != nil {
			return err
		}
		// A certificate belonging to another host must never appear below.
		stray := store.Certificate{
			MembershipID: other.ID, CAID: caRow.ID, Fingerprint: uuid.NewString(), PEM: "p",
			CertVer: 2, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		}
		return tx.InsertCertificate(ctx, &stray)
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	certPage := func(f store.CertFilter) store.CertPage {
		t.Helper()
		var page store.CertPage
		err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
			var err error
			page, err = tx.MembershipCertificates(ctx, host.ID, f)
			return err
		})
		if err != nil {
			t.Fatalf("MembershipCertificates: %v", err)
		}
		return page
	}

	all := certPage(store.CertFilter{})
	if len(all.Certificates) != 5 {
		t.Fatalf("history = %d rows, want 5", len(all.Certificates))
	}
	for _, c := range all.Certificates {
		if c.MembershipID != host.ID {
			t.Errorf("history contains another host's certificate: %s", c.ID)
		}
		if c.CAName != "history-ca" {
			t.Errorf("ca name = %q, want history-ca", c.CAName)
		}
		// RenewAt is the whole reason "overdue" is legible without arithmetic.
		if want := c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore) / 2); !c.RenewAt().Equal(want) {
			t.Errorf("RenewAt() = %s, want %s", c.RenewAt(), want)
		}
	}

	// Paging with the tiebreaker: every row shares issued_at, so if id were not
	// part of the key this would loop or lose rows.
	var (
		seen   []uuid.UUID
		cursor *store.CertCursor
	)
	for i := 0; ; i++ {
		page := certPage(store.CertFilter{Limit: 2, After: cursor})
		for _, c := range page.Certificates {
			seen = append(seen, c.ID)
		}
		if !page.More {
			break
		}
		last := page.Certificates[len(page.Certificates)-1]
		cursor = &store.CertCursor{IssuedAt: last.IssuedAt, ID: last.ID}
		if i > 5 {
			t.Fatal("certificate pagination did not terminate")
		}
	}
	if len(seen) != 5 {
		t.Errorf("paged %d certificates, want 5", len(seen))
	}
	unique := map[uuid.UUID]bool{}
	for _, id := range seen {
		if unique[id] {
			t.Errorf("certificate %s was served on two pages", id)
		}
		unique[id] = true
	}

	// The state filter is what makes "which one is live" a single request.
	active := certPage(store.CertFilter{State: store.CertActive})
	if len(active.Certificates) != 1 {
		t.Errorf("active certificates = %d, want 1", len(active.Certificates))
	}
}

// TestRenewAtMidpoint pins the 50%-of-lifetime rule that the agent's renewal
// schedule and the sweep both depend on.
func TestRenewAtMidpoint(t *testing.T) {
	start := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	c := store.Certificate{NotBefore: start, NotAfter: start.Add(24 * time.Hour)}
	if want := start.Add(12 * time.Hour); !c.RenewAt().Equal(want) {
		t.Errorf("RenewAt() = %s, want %s", c.RenewAt(), want)
	}
}

// TestUpdateRoleOnlyReportsRealChanges is the guard on the config epoch.
//
// Every bump wakes every agent in the network to fetch and re-render a
// fragment. A PATCH that restates what is already stored must therefore report
// nothing changed, so that re-running a reconcile loop — or retrying a request
// that may not have landed — stays free instead of becoming fleet-wide work.
func TestUpdateRoleOnlyReportsRealChanges(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	net := newNetwork(t, s, "10.61.0.0/16")

	var role store.Role
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		role = store.Role{
			NetworkID: net.ID, Name: "web", Groups: []string{"web", "edge"},
			FirewallRules: []byte(`{"inbound":[{"port":"443","proto":"tcp","host":"any"}]}`),
		}
		return tx.CreateRole(ctx, &role)
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	update := func(u store.RoleUpdate) *store.RoleChange {
		t.Helper()
		var c *store.RoleChange
		err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			var err error
			c, err = tx.UpdateRole(ctx, role.ID, u)
			return err
		})
		if err != nil {
			t.Fatalf("UpdateRole: %v", err)
		}
		return c
	}

	// Nothing supplied at all.
	if c := update(store.RoleUpdate{}); c.Changed {
		t.Error("an empty update reported a change")
	}

	// The same rules, reformatted. firewall_rules is jsonb, so the database
	// compares it semantically: different whitespace and key order is not an
	// edit. A []byte comparison in Go would call this a change and bump the
	// epoch for it.
	same := []byte(`{ "inbound" : [ { "host":"any", "proto":"tcp", "port":"443" } ] }`)
	if c := update(store.RoleUpdate{Firewall: &same}); c.Changed {
		t.Error("re-sending the stored rules with different formatting reported a change")
	}

	// The same groups in the same order.
	groups := []string{"web", "edge"}
	if c := update(store.RoleUpdate{Groups: &groups}); c.Changed {
		t.Error("re-sending the stored groups reported a change")
	}

	// A real firewall edit is a change, and is not a group change: it converges
	// on the next poll rather than on the next certificate renewal.
	rules := []byte(`{"inbound":[{"port":"8443","proto":"tcp","host":"any"}]}`)
	c := update(store.RoleUpdate{Firewall: &rules})
	if !c.Changed {
		t.Fatal("a firewall edit reported no change")
	}
	if c.GroupsChanged {
		t.Error("a firewall edit reported GroupsChanged; it does not touch any certificate")
	}

	// A real group edit is both, and Before must still hold the old set: it is
	// what an audit entry needs to say what the change actually was.
	next := []string{"web"}
	c = update(store.RoleUpdate{Groups: &next})
	if !c.Changed || !c.GroupsChanged {
		t.Fatalf("group edit: Changed=%v GroupsChanged=%v", c.Changed, c.GroupsChanged)
	}
	if len(c.Before.Groups) != 2 || len(c.After.Groups) != 1 {
		t.Errorf("group edit went %v -> %v", c.Before.Groups, c.After.Groups)
	}
	// Untouched fields survive a partial update.
	if c.After.Name != "web" {
		t.Errorf("name became %q after a groups-only update", c.After.Name)
	}

	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.UpdateRole(ctx, uuid.New(), store.RoleUpdate{Name: &c.After.Name})
		return err
	}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UpdateRole on a missing role = %v, want ErrNotFound", err)
	}
}

// TestDeleteRoleIsRefusedWhileHostsCarryIt covers ON DELETE RESTRICT and the
// reason the store checks it itself.
//
// The database refuses the delete regardless. But mapErr renders a foreign key
// violation as ErrNotFound, so without the check the API would tell an operator
// the role does not exist when the truth is that hosts are using it.
func TestDeleteRoleIsRefusedWhileHostsCarryIt(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	net := newNetwork(t, s, "10.62.0.0/16")

	var role store.Role
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		role = store.Role{NetworkID: net.ID, Name: "carried"}
		return tx.CreateRole(ctx, &role)
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	var host store.Membership
	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		host = store.Membership{
			NetworkID: net.ID, Name: "carrier", RoleID: &role.ID,
			Addrs: []netip.Addr{netip.MustParseAddr("10.62.0.1")},
			State: store.MembershipActive,
		}
		return insertHost(ctx, tx, &host)
	})
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	del := func() error {
		return s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			return tx.DeleteRole(ctx, role.ID)
		})
	}
	if err := del(); !errors.Is(err, store.ErrRoleInUse) {
		t.Fatalf("DeleteRole with a host carrying it = %v, want ErrRoleInUse", err)
	}

	// A soft-deleted host still holds role_id, so it still blocks the delete.
	// A blocker list that filtered it out would report an empty set for a
	// delete the database then refuses.
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.SetHostState(ctx, host.ID, store.MembershipDeleted)
	}); err != nil {
		t.Fatalf("SetHostState: %v", err)
	}
	var carriers []store.RoleHost
	if err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		carriers, err = tx.RoleHosts(ctx, role.ID)
		return err
	}); err != nil {
		t.Fatalf("RoleHosts: %v", err)
	}
	if len(carriers) != 1 || carriers[0].Name != "carrier" {
		t.Errorf("RoleHosts after soft delete = %+v, want the carrier", carriers)
	}
	// A host that never enrolled has no certificate, so nothing stale to
	// replace when the role's groups change.
	if !carriers[0].CertNotAfter.IsZero() {
		t.Errorf("unenrolled host reported a certificate window: %+v", carriers[0])
	}
	if err := del(); !errors.Is(err, store.ErrRoleInUse) {
		t.Errorf("DeleteRole with a soft-deleted carrier = %v, want ErrRoleInUse", err)
	}

	// Reassign, and it goes.
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.UpdateHostMeta(ctx, host.ID, ptrStr(""), nil)
	}); err != nil {
		t.Fatalf("UpdateHostMeta: %v", err)
	}
	if err := del(); err != nil {
		t.Fatalf("DeleteRole with nothing carrying it: %v", err)
	}
	if err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.GetRole(ctx, role.ID)
		return err
	}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetRole after delete = %v, want ErrNotFound", err)
	}
}

func ptrStr(s string) *string { return &s }

// A host that has reported is active. "Enrolled" means it holds a certificate;
// "active" means it is using it, which nothing but a report can observe.
//
// Before this, the only assignment of MembershipActive anywhere was in UnblockHost —
// so a host reached active solely by being blocked and then unblocked, and a
// normally enrolled fleet read as permanently mid-setup in `orbit membership ls`.
func TestReportingMakesAHostActive(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	net := newNetwork(t, s, "10.90.0.0/16")
	host := newHost(t, s, net, "reporter", "10.90.0.7")

	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.SetHostState(ctx, host.ID, store.MembershipEnrolled)
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RecordAgentReport(ctx, host.ID, store.AgentReport{
			ConfigEpoch: 1, BlocklistEpoch: 1, AgentVersion: "test",
		})
	}); err != nil {
		t.Fatalf("RecordAgentReport: %v", err)
	}

	if got := readHostState(t, s, host.ID); got != store.MembershipActive {
		t.Errorf("state = %q after reporting, want %q", got, store.MembershipActive)
	}
}

// TestReportingDoesNotResurrectABlockedHost is the half that constrains the
// half above.
//
// A blocked host keeps talking until its certificate expires or the blocklist
// reaches its peers, so it will report after being cut off. Letting that move
// it out of suspended would let a host undo an operator's decision about it,
// and the operator would see a fleet where nothing is blocked.
func TestReportingDoesNotResurrectABlockedHost(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	net := newNetwork(t, s, "10.91.0.0/16")

	for i, state := range []string{store.MembershipSuspended, store.MembershipCreated, store.MembershipDeleted} {
		t.Run(state, func(t *testing.T) {
			host := newHost(t, s, net, "host-"+state, fmt.Sprintf("10.91.0.%d", i+10))
			if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
				return tx.SetHostState(ctx, host.ID, state)
			}); err != nil {
				t.Fatal(err)
			}

			if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
				return tx.RecordAgentReport(ctx, host.ID, store.AgentReport{
					ConfigEpoch: 2, BlocklistEpoch: 2,
				})
			}); err != nil {
				t.Fatalf("RecordAgentReport: %v", err)
			}

			if got := readHostState(t, s, host.ID); got != state {
				t.Errorf("a %s host reported and became %q; a report is not consent "+
					"to undo a decision somebody made about this host", state, got)
			}
		})
	}
}

func readHostState(t *testing.T, s *store.Store, id uuid.UUID) string {
	t.Helper()
	var state string
	if err := s.Read(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		h, err := tx.GetHost(ctx, id)
		if err != nil {
			return err
		}
		state = h.State
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return state
}

// insertHost creates a membership with a device, which is the only kind there is.
//
// Every fixture here used to call tx.CreateHost directly, which stopped
// compiling in spirit and started failing in fact when device_id became NOT NULL
// (migration 0015). That is the constraint doing its job: a membership is "this
// device, in that network", so a test that creates one without a machine is
// testing a state the product cannot reach.
//
// A fresh device per host, because real machines have their own. Sharing one
// would make every fixture the same device and would hide exactly the bugs the
// device model exists to prevent.
func insertHost(ctx context.Context, tx *store.Tx, h *store.Membership) error {
	d := store.Device{PublicKey: randomKeyBytes()}
	if err := tx.SeeDevice(ctx, &d); err != nil {
		return err
	}
	h.DeviceID = &d.ID
	return tx.CreateHost(ctx, h)
}

func randomKeyBytes() []byte {
	k := make([]byte, 65)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	k[0] = 0x04
	return k
}

// withIdentity fills the network identity a real bootstrap would generate.
//
// Every network needs one: its ID derives from it, and a network without a
// verifiable ID is one a machine cannot safely join. `orbitd bootstrap`
// generates the pair and writes the private half to a file; these tests only
// need the public half and a ref, because nothing here verifies a proof.
//
// The ref still points at a real path so it is the same SHAPE the store stores
// in production — a locator, never the key. A test that DOES verify a proof
// (e2e) writes the file too.
func withIdentity(t *testing.T, n *store.Network) {
	t.Helper()
	pub, _, err := ca.GenerateNetworkIdentity()
	if err != nil {
		t.Fatalf("generate network identity: %v", err)
	}
	n.IdentityPublicKey = pub
	n.IdentitySignerRef = "file://" + filepath.Join(t.TempDir(), "network-identity.key")
}
