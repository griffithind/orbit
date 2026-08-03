package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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
		return tx.CreateNetwork(ctx, &net)
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	return &net
}

func newHost(t *testing.T, s *store.Store, net *store.Network, name, addr string) *store.Host {
	t.Helper()
	var h store.Host
	err := s.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		h = store.Host{
			NetworkID: net.ID,
			Name:      name,
			Addrs:     []netip.Addr{netip.MustParseAddr(addr)},
			State:     store.HostActive,
		}
		return tx.CreateHost(ctx, &h)
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
	if gotA.HostID != hostA.ID {
		t.Errorf("resolved to the wrong host for network A")
	}

	gotB, err := s.ResolveAgentHost(ctx, netB.ID, addr)
	if err != nil {
		t.Fatalf("ResolveAgentHost(B): %v", err)
	}
	if gotB.HostID != hostB.ID {
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
		h := store.Host{
			NetworkID: net.ID,
			Name:      "second",
			Addrs:     []netip.Addr{netip.MustParseAddr("10.42.0.7")},
		}
		return tx.CreateHost(ctx, &h)
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
			SignerRef: "file://dev.key", Curve: "CURVE25519",
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
			NetworkID: net.ID,
			HostID:    &host.ID,
			Method:    store.MethodCode,
			ExpiresAt: time.Now().Add(15 * time.Minute),
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
			NetworkID: net.ID, HostID: &host.ID, Method: store.MethodCode,
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
			Action: store.ActionHostCreated, TargetType: "host", TargetID: target,
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

//------------------------------------------------------------------------------
// Revocation and convergence
//------------------------------------------------------------------------------

// TestBlockHostFlow exercises the transaction behind POST /v1/hosts/:id/block:
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
			CertPEM: "pem", SignerRef: "file://k", Curve: "CURVE25519",
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
			HostID: host.ID, CAID: caID, Fingerprint: fingerprint, PEM: "pem",
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
		if h.State != store.HostSuspended {
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
			CertPEM: "pem", SignerRef: "file://k", Curve: "CURVE25519",
			NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		}
		if err := tx.CreateCA(ctx, &ca); err != nil {
			return err
		}

		liveFP, staleFP = uuid.NewString(), uuid.NewString()
		c1 := store.Certificate{
			HostID: live.ID, CAID: ca.ID, Fingerprint: liveFP, PEM: "p", CertVer: 2,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		}
		if err := tx.InsertCertificate(ctx, &c1); err != nil {
			return err
		}
		c2 := store.Certificate{
			HostID: stale.ID, CAID: ca.ID, Fingerprint: staleFP, PEM: "p", CertVer: 2,
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
		if c.HostsTotal != 2 {
			t.Errorf("hosts total = %d, want 2", c.HostsTotal)
		}
		if c.BlockApplied != 1 {
			t.Errorf("blocklist converged = %d, want 1", c.BlockApplied)
		}
		if len(c.Lagging) != 1 || c.Lagging[0].HostID != h2.ID {
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
			CertPEM: "pem", SignerRef: "file://k", Curve: "CURVE25519",
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		}
		if err := tx.CreateCA(ctx, &ca); err != nil {
			return err
		}

		mk := func(ver int16) store.Certificate {
			return store.Certificate{
				HostID: host.ID, CAID: ca.ID, Fingerprint: uuid.NewString(), PEM: "p",
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

// TestRenewAtMidpoint pins the 50%-of-lifetime rule that the agent's renewal
// schedule and the sweep both depend on.
func TestRenewAtMidpoint(t *testing.T) {
	start := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	c := store.Certificate{NotBefore: start, NotAfter: start.Add(24 * time.Hour)}
	if want := start.Add(12 * time.Hour); !c.RenewAt().Equal(want) {
		t.Errorf("RenewAt() = %s, want %s", c.RenewAt(), want)
	}
}
