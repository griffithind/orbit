package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/agent/generation"
	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/sched"
	"github.com/griffithind/orbit/internal/secrets"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// CA rotation.
//
// Nebula has no intermediate CAs, so the key Orbit signs with is a root that
// every host trusts directly. Rotation is therefore the only recovery from a
// compromised signing key, and a half-built rotation is worse than a documented
// manual one: you will believe it works.
//
// The five steps from docs/design.md §6:
//
//	1. create CA₂ (pending)
//	2. publish it into every trust bundle
//	3. wait for convergence, measured
//	4. promote CA₂, demote CA₁ to retiring
//	5. retire CA₁ once nothing it signed is still live

func (h *harness) createCA(t *testing.T, ts, name string) wire.CAResponse {
	t.Helper()
	var ca wire.CAResponse
	if code := h.adminPost(t, ts+"/v1/cas", wire.CreateCARequest{
		NetworkID: h.netID.String(), Name: name,
		Networks: []string{"10.42.0.0/16"}, Groups: []string{"default"}, Days: 30,
	}, &ca); code != http.StatusCreated {
		t.Fatalf("create CA %s: %d", name, code)
	}
	return ca
}

func (h *harness) networkEpochs(t *testing.T, ts string) wire.ConvergenceResponse {
	t.Helper()
	var c wire.ConvergenceResponse
	h.adminReq(t, http.MethodGet, ts+"/v1/networks/"+h.netID.String()+"/convergence", nil, &c)
	return c
}

// TestNewCAIsPublishedImmediately is step 2, and it is the step that was
// missing.
//
// Creating a CA has to advance the config epoch. Without that the pending CA
// sits in the database, reaches no trust bundle, and convergence reports 100%
// because nothing changed — so an operator promotes it and partitions the whole
// fleet. The pending state exists precisely to prevent that, and it only works
// if pending CAs are actually distributed.
func TestNewCAIsPublishedImmediately(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	before := h.networkEpochs(t, ts.URL)
	ca2 := h.createCA(t, ts.URL, "rotation-ca-2")
	after := h.networkEpochs(t, ts.URL)

	if after.ConfigEpoch <= before.ConfigEpoch {
		t.Fatalf("creating a CA did not advance the config epoch (%d -> %d); "+
			"it would never reach a trust bundle", before.ConfigEpoch, after.ConfigEpoch)
	}
	if ca2.State != "pending" {
		t.Errorf("new CA state = %q, want pending", ca2.State)
	}

	// And it must actually appear in what hosts are handed.
	host := h.createAndEnroll(t, ts, "bundle-check", "10.42.40.5", false, false, nil)
	bundle := readFile(t, host.dir+"/ca.crt")
	if countPEMBlocks(bundle) < 2 {
		t.Errorf("trust bundle has %d CAs, want the original plus the pending one",
			countPEMBlocks(bundle))
	}
}

// TestActivationIsGatedOnConvergence is step 3, the one people skip.
func TestActivationIsGatedOnConvergence(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	// A host that will never report, so the network cannot converge.
	h.createAndEnroll(t, ts, "straggler", "10.42.41.5", false, false, nil)

	ca2 := h.createCA(t, ts.URL, "rotation-ca-gated")

	// Plain activation must be refused, and must say who is behind.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/cas/"+ca2.ID+"/activate", nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("activation with hosts behind = %d, want 409\n%s", resp.StatusCode, body)
	}
	var conflict struct {
		Error   string             `json:"error"`
		Lagging []wire.LaggingHost `json:"lagging"`
	}
	_ = json.Unmarshal(body, &conflict)
	if len(conflict.Lagging) == 0 {
		t.Error("refusal did not name the lagging hosts; not actionable")
	}

	// The CA must still be pending — a refused activation changes nothing.
	var cas []wire.CAResponse
	h.adminReq(t, http.MethodGet, ts.URL+"/v1/cas?network_id="+h.netID.String(), nil, &cas)
	for _, c := range cas {
		if c.ID == ca2.ID && c.State != "pending" {
			t.Errorf("refused activation left the CA in state %q", c.State)
		}
	}
}

// TestEmergencyActivationIsAuditedDistinctly covers the key-compromise path:
// cutting off unconverged hosts is the lesser harm, but it must be deliberate
// and it must be distinguishable in the audit trail.
func TestEmergencyActivationIsAuditedDistinctly(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	h.createAndEnroll(t, ts, "cut-off", "10.42.42.5", false, false, nil)
	ca2 := h.createCA(t, ts.URL, "rotation-ca-emergency")

	if code := h.adminPost(t, ts.URL+"/v1/cas/"+ca2.ID+"/activate",
		wire.ActivateCARequest{AcknowledgeCutoff: true}, nil); code != http.StatusOK {
		t.Fatalf("acknowledged activation = %d, want 200", code)
	}

	var audit []wire.AuditRecordResponse
	h.adminReq(t, http.MethodGet, ts.URL+"/v1/audit-logs?target_id="+ca2.ID, nil, &audit)

	var forced *wire.AuditRecordResponse
	for i := range audit {
		if audit[i].Action == store.ActionCAForceActivated {
			forced = &audit[i]
		}
		if audit[i].Action == store.ActionCAActivated {
			t.Error("a forced activation was recorded as a routine one")
		}
	}
	if forced == nil {
		t.Fatal("forced activation was not audited as ca.force_activated")
	}
	if len(forced.Meta) == 0 || string(forced.Meta) == "{}" {
		t.Errorf("forced activation audit does not record how many hosts were cut off: %s", forced.Meta)
	}
	t.Logf("audited: %s meta=%s", forced.Action, forced.Meta)
}

// TestRetireRefusesWhileCertificatesAreLive is step 5's safety check. Retiring
// drops a CA from every trust bundle; doing that while hosts still present its
// certificates invalidates exactly the hosts that had not renewed.
func TestRetireRefusesWhileCertificatesAreLive(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	// A host holding a certificate from the original CA.
	h.createAndEnroll(t, ts, "still-on-ca1", "10.42.43.5", false, false, nil)

	var cas []wire.CAResponse
	h.adminReq(t, http.MethodGet, ts.URL+"/v1/cas?network_id="+h.netID.String(), nil, &cas)
	var ca1 wire.CAResponse
	for _, c := range cas {
		if c.State == "active" {
			ca1 = c
		}
	}
	if ca1.ID == "" {
		t.Fatal("no active CA")
	}
	if ca1.ActiveCertificates == 0 {
		t.Error("CA reports no active certificates despite an enrolled host")
	}

	// Cannot retire the active CA at all.
	if code := h.adminPost(t, ts.URL+"/v1/cas/"+ca1.ID+"/retire", nil, nil); code != http.StatusConflict {
		t.Errorf("retiring the active CA = %d, want 409", code)
	}

	// Promote a replacement, then the old one is retiring but still in use.
	ca2 := h.createCA(t, ts.URL, "rotation-ca-replacement")
	if code := h.adminPost(t, ts.URL+"/v1/cas/"+ca2.ID+"/activate",
		wire.ActivateCARequest{AcknowledgeCutoff: true}, nil); code != http.StatusOK {
		t.Fatalf("activate replacement: %d", code)
	}
	if code := h.adminPost(t, ts.URL+"/v1/cas/"+ca1.ID+"/retire", nil, nil); code != http.StatusConflict {
		t.Errorf("retiring a CA with live certificates = %d, want 409", code)
	}
}

// TestFullRotation walks all five steps and ends with the old CA out of the
// trust bundle and every host on the new one.
func TestFullRotation(t *testing.T) {
	h := setup(t)
	// The full harness, not the public-only one: this test drives a renewal,
	// which lives on the agent surface.
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	host := h.createAndEnroll(t, ts, "rotates", "10.42.44.5", false, false, nil)

	var cas []wire.CAResponse
	h.adminReq(t, http.MethodGet, ts.URL+"/v1/cas?network_id="+h.netID.String(), nil, &cas)
	var ca1 wire.CAResponse
	for _, c := range cas {
		if c.State == "active" {
			ca1 = c
		}
	}

	// 1 + 2: create and publish.
	ca2 := h.createCA(t, ts.URL, "rotation-ca-full")

	// 3 + 4: converge (acknowledged here, since the host has no running agent),
	// then promote.
	if code := h.adminPost(t, ts.URL+"/v1/cas/"+ca2.ID+"/activate",
		wire.ActivateCARequest{AcknowledgeCutoff: true}, nil); code != http.StatusOK {
		t.Fatalf("activate CA2: %d", code)
	}

	// The host renews and lands on CA₂.
	st, _ := agent.ReadState(host.dir)
	layout := paths.DefaultLayout(host.dir)
	loop := &agent.Loop{
		Client: xffClient(t, ts.URL, host.addr),
		Applier: &generation.Applier{
			Layout: layout, Reloader: generation.NoopReloader{},
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		Policy: agent.DefaultRenewalPolicy(),
		Layout: layout, Curve: cert.Curve_P256,
		Guard: agent.GuardPolicy{Disabled: true},
		State: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := loop.RenewNow(ctx); err != nil {
		t.Fatalf("renew onto the new CA: %v", err)
	}

	// 5: CA₁ has no live certificates left, so it can be retired.
	h.adminReq(t, http.MethodGet, ts.URL+"/v1/cas?network_id="+h.netID.String(), nil, &cas)
	for _, c := range cas {
		if c.ID == ca1.ID && c.ActiveCertificates != 0 {
			t.Fatalf("CA1 still has %d active certificates after renewal", c.ActiveCertificates)
		}
	}
	if code := h.adminPost(t, ts.URL+"/v1/cas/"+ca1.ID+"/retire", nil, nil); code != http.StatusOK {
		t.Fatalf("retire CA1: %d", code)
	}

	// The old CA must be gone from what hosts are handed.
	before := countPEMBlocks(readFile(t, host.dir+"/ca.crt"))
	if err := loop.Tick(ctx); err != nil {
		t.Logf("tick: %v", err)
	}
	after := countPEMBlocks(readFile(t, host.dir+"/ca.crt"))
	if after >= before {
		t.Errorf("trust bundle did not shrink after retirement: %d -> %d", before, after)
	}
	t.Logf("rotation complete: trust bundle %d -> %d CAs", before, after)
}

// TestSweepRetiresExpiredCAs covers the automatic half.
//
// A CA past its own NotAfter is provably safe to drop: nebula enforces
// leaf.NotAfter <= ca.NotAfter, so nothing it signed can still verify.
func TestSweepRetiresExpiredCAs(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	now := time.Now()

	var caID uuid.UUID
	err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		c := store.CA{
			NetworkID: h.netID, Name: "long-expired", Fingerprint: uuid.NewString(),
			CertPEM: "pem", SignerRef: stubSignerRef, Curve: "P256",
			NotBefore: now.Add(-90 * 24 * time.Hour), NotAfter: now.Add(-24 * time.Hour),
			State: store.CARetiring,
		}
		if err := tx.CreateCA(ctx, &c); err != nil {
			return err
		}
		caID = c.ID
		return nil
	})
	if err != nil {
		t.Fatalf("create expired CA: %v", err)
	}

	runner := sched.New(h.store, sched.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	stats, err := runner.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.CAsRetired == 0 {
		t.Error("sweep did not retire a CA that outlived its own validity")
	}

	err = h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		c, err := tx.GetCA(ctx, caID)
		if err != nil {
			return err
		}
		if c.State != store.CARetired {
			t.Errorf("expired CA state = %q, want retired", c.State)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestSweepLeavesAnExpiredActiveCAAlone is the other half of the same rule.
//
// An expired *active* CA is broken whatever the sweep does — ca.ValidityFor
// refuses to sign against it — so the only choice is which failure an operator
// is left holding. Force-retiring it trades "CA %q expired at %s", which names
// the CA and the moment, for a bare "network has no active CA"; it erases the
// record of what was signing; and it is not undoable through the API, because
// ActivateCA promotes only pending and retiring CAs. So the sweep leaves it,
// keeps it in the trust bundle, and says so at Error.
//
// The pending CA in the same network is the control: expired non-signers are
// still cleaned up, which is the half that was always meant to be automatic.
func TestSweepLeavesAnExpiredActiveCAAlone(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	now := time.Now()

	const activePEM = "-----BEGIN NEBULA CERTIFICATE-----\nexpired-signer\n-----END NEBULA CERTIFICATE-----\n"

	var netID, activeID, pendingID uuid.UUID
	err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		// A network of its own: ca_one_active_per_network means an expired
		// active CA cannot be staged alongside the harness's live one.
		identityPub, identityPriv, err := ca.GenerateNetworkIdentity()
		if err != nil {
			return err
		}
		identityRef, err := h.vault.PutTx(ctx, tx, secrets.KindNetworkIdentity, nil,
			ca.MarshalNetworkIdentityPEM(identityPriv))
		if err != nil {
			return err
		}
		net := store.Network{
			Name:              "expired-signer-" + uuid.NewString()[:8],
			CIDRs:             []netip.Prefix{netip.MustParsePrefix("10.43.0.0/16")},
			IdentityPublicKey: identityPub,
			IdentitySignerRef: identityRef,
		}
		if err := tx.CreateNetwork(ctx, &net); err != nil {
			return err
		}
		netID = net.ID

		active := store.CA{
			NetworkID: net.ID, Name: "expired-signer", Fingerprint: uuid.NewString(),
			CertPEM: activePEM, SignerRef: stubSignerRef, Curve: "P256",
			NotBefore: now.Add(-90 * 24 * time.Hour), NotAfter: now.Add(-2 * time.Hour),
			State: store.CAActive,
		}
		if err := tx.CreateCA(ctx, &active); err != nil {
			return err
		}
		activeID = active.ID

		pending := store.CA{
			NetworkID: net.ID, Name: "expired-pending", Fingerprint: uuid.NewString(),
			CertPEM: "pending-pem", SignerRef: stubSignerRef, Curve: "P256",
			NotBefore: now.Add(-90 * 24 * time.Hour), NotAfter: now.Add(-2 * time.Hour),
			State: store.CAPending,
		}
		if err := tx.CreateCA(ctx, &pending); err != nil {
			return err
		}
		pendingID = pending.ID
		return nil
	})
	if err != nil {
		t.Fatalf("stage an expired active CA: %v", err)
	}

	var logs bytes.Buffer
	runner := sched.New(h.store, sched.Config{}, slog.New(slog.NewTextHandler(&logs, nil)))
	stats, err := runner.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.ExpiredActiveCAs == 0 {
		t.Error("sweep did not report a network signing with an expired CA")
	}

	err = h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		a, err := tx.GetCA(ctx, activeID)
		if err != nil {
			return err
		}
		if a.State != store.CAActive {
			t.Errorf("expired active CA state = %q, want it left active for an operator", a.State)
		}
		p, err := tx.GetCA(ctx, pendingID)
		if err != nil {
			return err
		}
		if p.State != store.CARetired {
			t.Errorf("expired pending CA state = %q, want retired", p.State)
		}

		// Retiring the signer would have taken it out of here, and the bundle is
		// the only thing that says which CA the network was meant to be using.
		bundle, err := tx.TrustBundlePEM(ctx, netID)
		if err != nil {
			return err
		}
		if !strings.Contains(bundle, activePEM) {
			t.Error("expired active CA was dropped from the trust bundle")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The state is only tolerable because it is loud. An operator who is not
	// told has a network that stops issuing certificates and no line to grep.
	line := logLineFor(logs.String(), netID.String(), "active certificate authority has expired")
	if line == "" {
		t.Fatalf("the expired signer was not reported at all:\n%s", logs.String())
	}
	if !strings.Contains(line, "level=ERROR") {
		t.Errorf("expired active CA was reported below Error, so nothing pages: %s", line)
	}
	if !strings.Contains(line, "expired-signer") {
		t.Errorf("report does not name the CA, leaving nothing to act on: %s", line)
	}
	t.Logf("reported: %s", line)
}

// logLineFor returns the first captured line containing every substring. The
// sweep covers every network in the database, including whatever other tests
// left behind, so an assertion has to pick out its own network's line.
func logLineFor(out string, want ...string) string {
	for _, line := range strings.Split(out, "\n") {
		found := true
		for _, w := range want {
			if !strings.Contains(line, w) {
				found = false
				break
			}
		}
		if found {
			return line
		}
	}
	return ""
}

func countPEMBlocks(s string) int {
	n := 0
	for i := 0; i+len("-----BEGIN") <= len(s); i++ {
		if s[i:i+len("-----BEGIN")] == "-----BEGIN" {
			n++
		}
	}
	return n
}
