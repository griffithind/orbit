package e2e

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/sched"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// TestMaintenancePrunesBlocklist proves the sweep actually removes entries.
//
// Before the scheduler existed, PruneBlocklist had zero non-test callers: the
// blocklist grew forever and was shipped in full to every host in every
// configuration, while docs/revocation.md described pruning as though it
// happened.
func TestMaintenancePrunesBlocklist(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()
	now := time.Now()

	var host wire.MembershipResponse
	h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "prunable", OverlayAddr: "10.42.20.5",
		RoleID: h.roleID.String(),
	}, &host)
	membershipID := uuid.MustParse(host.ID)

	// Give it a certificate that expired long ago, then block it.
	err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		caRow, err := tx.GetActiveCA(ctx, h.netID)
		if err != nil {
			return err
		}
		c := store.Certificate{
			MembershipID: membershipID, CAID: caRow.ID, Fingerprint: uuid.NewString(), PEM: "p",
			CertVer: 2, NotBefore: now.Add(-90 * 24 * time.Hour), NotAfter: now.Add(-60 * 24 * time.Hour),
		}
		if err := tx.InsertCertificate(ctx, &c); err != nil {
			return err
		}
		_, err = tx.BlockHost(ctx, membershipID, "test")
		return err
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// The entry exists but is already excluded from distribution, because its
	// certificate expired. Pruning is about the row, not the config.
	var before int
	err = h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		fps, err := tx.LiveBlocklist(ctx, h.netID, now)
		before = len(fps)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if before != 0 {
		t.Errorf("live blocklist has %d entries for an expired certificate, want 0", before)
	}

	runner := sched.New(h.store, sched.Config{BlocklistGrace: time.Hour},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	stats, err := runner.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.BlocklistPruned == 0 {
		t.Error("sweep pruned nothing despite a long-expired blocklist entry")
	}
	t.Logf("sweep: networks=%d blocklistPruned=%d credentialsPruned=%d overdue=%d",
		stats.Networks, stats.BlocklistPruned, stats.CredentialsPruned, stats.CertificatesOverdue)
}

// TestMaintenancePrunesExpiredCredentials covers the other orphaned method.
// Redeemed credentials must survive: they are evidence.
func TestMaintenancePrunesExpiredCredentials(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	var host wire.MembershipResponse
	h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "cred-prune", OverlayAddr: "10.42.20.9",
		RoleID: h.roleID.String(),
	}, &host)
	membershipID := uuid.MustParse(host.ID)

	err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		c := store.EnrollmentCredential{
			NetworkID: h.netID, MembershipID: &membershipID, Method: store.MethodCode,
			ExpiresAt: time.Now().Add(-time.Hour),
		}
		return tx.CreateEnrollmentCredential(ctx, &c, []byte("stale-"+uuid.NewString()))
	})
	if err != nil {
		t.Fatal(err)
	}

	runner := sched.New(h.store, sched.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	stats, err := runner.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.CredentialsPruned == 0 {
		t.Error("sweep did not prune an expired unredeemed credential")
	}
}

// TestMaintenanceReportsOverdueRenewals covers the visibility half. The control
// plane cannot renew for a host (the host holds the key), so this is the only
// signal that a fleet has quietly stopped rotating.
func TestMaintenanceReportsOverdueRenewals(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()
	now := time.Now()

	var host wire.MembershipResponse
	h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "overdue", OverlayAddr: "10.42.20.11",
		RoleID: h.roleID.String(),
	}, &host)
	membershipID := uuid.MustParse(host.ID)

	err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := tx.SetHostState(ctx, membershipID, store.MembershipActive); err != nil {
			return err
		}
		caRow, err := tx.GetActiveCA(ctx, h.netID)
		if err != nil {
			return err
		}
		// Past its midpoint: issued 20h ago with a 24h lifetime.
		c := store.Certificate{
			MembershipID: membershipID, CAID: caRow.ID, Fingerprint: uuid.NewString(), PEM: "p",
			CertVer: 2, NotBefore: now.Add(-20 * time.Hour), NotAfter: now.Add(4 * time.Hour),
		}
		return tx.InsertCertificate(ctx, &c)
	})
	if err != nil {
		t.Fatal(err)
	}

	runner := sched.New(h.store, sched.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	stats, err := runner.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.CertificatesOverdue == 0 {
		t.Error("sweep did not report a certificate well past its renewal point")
	}
}

// TestEnrollmentIsRateLimited covers the invariant docs/enrollment.md §2 has
// claimed since the design was written and that the code did not implement.
func TestEnrollmentIsRateLimited(t *testing.T) {
	h := setup(t)
	ts := h.serveRateLimited(t, freeUDPPort(t))

	client := agent.NewClient(ts.URL)
	kp, _ := agent.GenerateKeypair(cert.Curve_P256)
	// Any identity: the credential is bogus and redemption fails before the
	// signature is looked at, which is the order that keeps an attacker with a
	// junk code from costing a signature verification.
	id, err := device.Generate()
	if err != nil {
		t.Fatalf("device key: %v", err)
	}

	var limited bool
	for i := 0; i < 40; i++ {
		_, err := client.Enroll(context.Background(), id, "orb_1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", kp, "e2e")
		var apiErr *agent.APIError
		if errorsAs(err, &apiErr) && apiErr.Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("40 rejected enrollment attempts from one address were never rate limited")
	}
}

// TestFailedEnrollmentIsAudited covers the attributable half of the invariant.
//
// An attempt whose credential does not resolve is audited with no target, since
// there is no host to name. Once a credential HAS been redeemed the host is
// known, and a subsequent failure — the shape of a replayed code — is audited
// against it.
func TestFailedEnrollmentIsAudited(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	var host wire.MembershipResponse
	h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "audited-failure", OverlayAddr: "10.42.20.21",
		RoleID: h.roleID.String(),
	}, &host)

	var code wire.EnrollmentCodeResponse
	h.adminPost(t, ts.URL+"/v1/memberships/"+host.ID+"/enrollment-code", nil, &code)

	// Redeem with a public key for the wrong curve: redemption succeeds (so the
	// host is known), issuance then fails.
	//
	// CURVE25519 deliberately, and it must stay that way even though Orbit only
	// creates P-256 networks now — the mismatch IS the test. nebula's cert
	// library still knows both curves, so this exercises the control plane's
	// check rather than a parse failure.
	kp, _ := agent.GenerateKeypair(cert.Curve_CURVE25519)
	_, err := agent.NewClient(ts.URL).Enroll(ctx, h.deviceFor(t, host.ID), code.Code, kp, "e2e")
	if err == nil {
		t.Fatal("enrollment with a mismatched curve succeeded")
	}

	var audit []wire.AuditRecordResponse
	h.adminReq(t, http.MethodGet, ts.URL+"/v1/audit-logs?action="+store.ActionEnrollFailed, nil, &audit)
	if len(audit) == 0 {
		t.Fatal("an attributable enrollment failure was not audited")
	}
	if audit[0].TargetID != host.ID {
		t.Errorf("audit target = %q, want the host %q", audit[0].TargetID, host.ID)
	}
	t.Logf("audited: %s target=%s meta=%s", audit[0].Action, audit[0].TargetID, audit[0].Meta)
}

var _ = enroll.DefaultCodeTTL
