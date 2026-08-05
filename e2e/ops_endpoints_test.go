package e2e

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The operational read surfaces.
//
// Four questions an operator asks during an incident — what is revoked, which
// CAs must a host trust, which certificates are failing to renew, which
// replicas are alive. Every one of them was answerable only from psql: the
// store methods existed and no route reached them.
//
// These tests compare each endpoint against the store method behind it rather
// than against a hardcoded expectation, because the failure worth catching is
// the endpoint quietly answering a narrower question than the store does — a
// filter applied twice, a limit defaulted wrong, an entry skipped because its
// host row is gone.

// fingerprintOf reads the fingerprint of a host's live certificate.
//
// Taken from the store rather than parsed out of the enrollment response,
// because the blocklist stores whatever the certificate row holds and this test
// is about matching that exactly.
func (h *harness) fingerprintOf(t *testing.T, membershipID string) string {
	t.Helper()
	id, err := uuid.Parse(membershipID)
	if err != nil {
		t.Fatalf("host id %q: %v", membershipID, err)
	}

	var fp string
	err = h.store.Read(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		certs, err := tx.ActiveCertificates(ctx, id)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			t.Fatalf("host %s has no active certificate", membershipID)
		}
		fp = certs[0].Fingerprint
		return nil
	})
	if err != nil {
		t.Fatalf("read certificates: %v", err)
	}
	return fp
}

func (h *harness) blocklist(t *testing.T, baseURL string) []wire.BlocklistEntryResponse {
	t.Helper()
	var out []wire.BlocklistEntryResponse
	if code := h.adminReq(t, http.MethodGet,
		baseURL+"/v1/networks/"+h.netID.String()+"/blocklist", nil, &out); code != http.StatusOK {
		t.Fatalf("GET blocklist: %d", code)
	}
	return out
}

// TestBlocklistSurvivesTheHostItRevoked is the case no other endpoint can show.
//
// store.DeleteHost blocks first and then deletes, and deliberately leaves the
// blocklist entries behind — otherwise decommissioning a machine would quietly
// un-revoke it. The consequence is that those fingerprints belong to a host
// that no longer appears in any listing, has no certificate history, and 404s
// on its own id. Before this endpoint they were invisible everywhere except the
// table itself.
func TestBlocklistSurvivesTheHostItRevoked(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	blocked := h.createAndEnroll(t, ts, "ops-blocked", "10.42.9.1", false, false, nil)
	deleted := h.createAndEnroll(t, ts, "ops-deleted", "10.42.9.2", false, false, nil)
	untouched := h.createAndEnroll(t, ts, "ops-untouched", "10.42.9.3", false, false, nil)

	blockedFP := h.fingerprintOf(t, blocked.id)
	deletedFP := h.fingerprintOf(t, deleted.id)
	untouchedFP := h.fingerprintOf(t, untouched.id)

	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+blocked.id+"/block", nil, nil); code != http.StatusOK {
		t.Fatalf("block: %d", code)
	}
	if code := h.adminReq(t, http.MethodDelete, ts.URL+"/v1/memberships/"+deleted.id, nil, nil); code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}

	// The premise: the deleted host is gone from the read surface entirely.
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/memberships/"+deleted.id, nil, nil); code != http.StatusNotFound {
		t.Fatalf("deleted host still readable: %d", code)
	}

	got := map[string]bool{}
	for _, e := range h.blocklist(t, ts.URL) {
		if e.Fingerprint == "" {
			t.Error("blocklist entry has no fingerprint, which is the only thing hosts act on")
		}
		got[e.Fingerprint] = true
	}

	if !got[blockedFP] {
		t.Error("blocked host's fingerprint is missing from the blocklist")
	}
	if !got[deletedFP] {
		t.Error("deleted host's fingerprint is missing from the blocklist.\n" +
			"Its host row is gone, so this endpoint is the only place it can appear — " +
			"and a decommissioned machine that reads as un-revoked is the worst outcome here")
	}
	if got[untouchedFP] {
		t.Error("a host that was never revoked appears in the blocklist")
	}
}

// TestBlocklistMatchesWhatHostsAreGiven. The endpoint must answer with the same
// set that is rendered into every host's configuration, not a superset: an
// entry whose certificate has already expired is deliberately dropped from
// distribution, and showing it here would have an operator believe a
// fingerprint is in force when no host is enforcing it.
func TestBlocklistMatchesWhatHostsAreGiven(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "ops-live", "10.42.9.10", false, false, nil)
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+host.id+"/block", nil, nil); code != http.StatusOK {
		t.Fatalf("block: %d", code)
	}

	var want []string
	err := h.store.Read(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		want, err = tx.LiveBlocklist(ctx, h.netID, time.Now())
		return err
	})
	if err != nil {
		t.Fatalf("live blocklist: %v", err)
	}

	entries := h.blocklist(t, ts.URL)
	if len(entries) != len(want) {
		t.Fatalf("blocklist has %d entries, the store distributes %d", len(entries), len(want))
	}
	for i, fp := range want {
		if entries[i].Fingerprint != fp {
			t.Errorf("entry %d = %q, store has %q", i, entries[i].Fingerprint, fp)
		}
	}
}

// TestBlocklistRendersForATerminal. The list is read while watching a
// revocation land, which happens at a shell far more often than in a browser.
// An empty list must say so in words: blank output and "nothing is revoked" are
// indistinguishable on a terminal and mean opposite things.
func TestBlocklistRendersForATerminal(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	url := ts.URL + "/v1/networks/" + h.netID.String() + "/blocklist?format=text"

	code, body := h.adminRaw(t, http.MethodGet, url, nil)
	if code != http.StatusOK {
		t.Fatalf("text blocklist: %d", code)
	}
	if !strings.Contains(body, "nothing is revoked") {
		t.Errorf("an empty blocklist rendered as %q, which is indistinguishable from no output", body)
	}

	host := h.createAndEnroll(t, ts, "ops-text", "10.42.9.11", false, false, nil)
	fp := h.fingerprintOf(t, host.id)
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+host.id+"/block", nil, nil); code != http.StatusOK {
		t.Fatalf("block: %d", code)
	}

	code, body = h.adminRaw(t, http.MethodGet, url, nil)
	if code != http.StatusOK {
		t.Fatalf("text blocklist: %d", code)
	}
	if !strings.Contains(body, fp) {
		t.Errorf("text blocklist does not contain the revoked fingerprint:\n%s", body)
	}
}

// TestTrustBundleIsFetchableMoreThanOnce is the whole reason the endpoint
// exists. A CA's PEM is returned by the create handler and by nothing else, so
// until now it was recoverable exactly once — and the moment it is wanted again
// is a rotation that has gone wrong, long after that response scrolled away.
func TestTrustBundleIsFetchableMoreThanOnce(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	second := h.createCA(t, ts.URL, "ops-rotation-ca")

	var bundle wire.TrustBundleResponse
	if code := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/networks/"+h.netID.String()+"/trust-bundle", nil, &bundle); code != http.StatusOK {
		t.Fatalf("GET trust-bundle: %d", code)
	}

	if bundle.NetworkID != h.netID.String() {
		t.Errorf("network_id = %q, want %q", bundle.NetworkID, h.netID)
	}
	// Bootstrap CA plus the one just created; neither is retired.
	if len(bundle.CAs) != 2 {
		t.Fatalf("bundle describes %d CAs, want 2 (bootstrap + rotation)", len(bundle.CAs))
	}

	// The description must match the bytes. A reader who trusts the CAs list
	// and a host who parses the PEM have to be looking at the same trust set.
	// Prefix rather than the full banner: nebula uses a different one for v1 and
	// v2 certificates, and this counts blocks, not versions.
	var (
		sawSecond bool
		pemCount  = strings.Count(bundle.PEM, "-----BEGIN NEBULA CERTIFICATE")
	)
	for _, c := range bundle.CAs {
		if c.CertPEM == "" {
			t.Errorf("CA %s carries no PEM; re-exporting the CAs is the point of this endpoint", c.Name)
			continue
		}
		if !strings.Contains(bundle.PEM, c.CertPEM) {
			t.Errorf("CA %s is described but its PEM is not in the concatenated bundle", c.Name)
		}
		if c.ID == second.ID {
			sawSecond = true
		}
	}
	if !sawSecond {
		t.Error("a pending CA is missing from the trust bundle; it is distributed to hosts before it signs")
	}
	if pemCount != 2 {
		t.Errorf("bundle PEM holds %d certificates, want 2", pemCount)
	}

	// And it matches the bytes agents actually receive.
	var storeBundle string
	err := h.store.Read(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		storeBundle, err = tx.TrustBundlePEM(ctx, h.netID)
		return err
	})
	if err != nil {
		t.Fatalf("store trust bundle: %v", err)
	}
	if bundle.PEM != storeBundle {
		t.Error("the exported bundle differs from the one hosts are given")
	}
}

// TestExpiringCertificatesNameTheHosts. The metrics endpoint reports how many;
// this reports which, and during a renewal failure only the names are
// actionable.
//
// The default window is "already due", so freshly issued certificates must not
// appear: an endpoint that listed every certificate by default would report a
// perfectly healthy fleet as a fleet-wide emergency.
func TestExpiringCertificatesNameTheHosts(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "ops-renewing", "10.42.9.20", false, false, nil)
	base := ts.URL + "/v1/networks/" + h.netID.String() + "/certificates/expiring"

	var due []wire.ExpiringCertificateResponse
	if code := h.adminReq(t, http.MethodGet, base, nil, &due); code != http.StatusOK {
		t.Fatalf("GET expiring: %d", code)
	}
	if len(due) != 0 {
		t.Errorf("a certificate issued seconds ago is already reported as due: %+v", due)
	}

	// The harness issues 24h certificates, so the renewal point is ~12h out.
	// A 13h horizon must reach it and a 1h horizon must not — which is the
	// property that makes ?window mean anything.
	if code := h.adminReq(t, http.MethodGet, base+"?window=1h", nil, &due); code != http.StatusOK {
		t.Fatalf("GET expiring window=1h: %d", code)
	}
	if len(due) != 0 {
		t.Errorf("window=1h reached a renewal point 12h away: %+v", due)
	}

	if code := h.adminReq(t, http.MethodGet, base+"?window=13h", nil, &due); code != http.StatusOK {
		t.Fatalf("GET expiring window=13h: %d", code)
	}
	if len(due) == 0 {
		t.Fatal("window=13h found nothing, but the only certificate on this network renews in ~12h")
	}

	found := false
	for _, c := range due {
		if c.MembershipID != host.id {
			continue
		}
		found = true
		if c.MembershipName != "ops-renewing" {
			t.Errorf("host_name = %q, want %q — a uuid alone sends the reader to another endpoint per row",
				c.MembershipName, "ops-renewing")
		}
		if c.Fingerprint == "" {
			t.Error("no fingerprint; it is what identifies the certificate to revoke")
		}
		renewAt, err := time.Parse(time.RFC3339, c.RenewAt)
		if err != nil {
			t.Fatalf("renew_at %q: %v", c.RenewAt, err)
		}
		notAfter, err := time.Parse(time.RFC3339, c.NotAfter)
		if err != nil {
			t.Fatalf("not_after %q: %v", c.NotAfter, err)
		}
		// RenewAt is the midpoint, so it must sit strictly inside the
		// certificate's life. Reporting NotAfter in both fields would make
		// every entry look like an emergency.
		if !renewAt.Before(notAfter) {
			t.Errorf("renew_at %s is not before not_after %s", c.RenewAt, c.NotAfter)
		}
	}
	if !found {
		t.Errorf("host %s is missing from the expiring list", host.id)
	}
}

// TestExpiringCertificatesRefuseAQuestionTheyCannotAnswer.
//
// A parameter the API accepts and drops is worse than one it does not offer:
// the caller reads an unfiltered page as the answer to the question they asked,
// and "nothing is expiring" is the wrong thing to conclude during an incident.
func TestExpiringCertificatesRefuseAQuestionTheyCannotAnswer(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	base := ts.URL + "/v1/networks/" + h.netID.String() + "/certificates/expiring"

	for _, q := range []string{
		"?window=soon",  // not a duration
		"?window=-1h",   // narrows to a different question
		"?limit=0",      // returns nothing, which reads as "all clear"
		"?limit=-5",     //
		"?limit=100000", // a work queue, not a history
		"?limit=lots",
	} {
		if code, body := h.adminRaw(t, http.MethodGet, base+q, nil); code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400 (%s)", q, code, strings.TrimSpace(body))
		}
	}
}

// TestExpiringCertificatesRenderForATerminal.
func TestExpiringCertificatesRenderForATerminal(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	h.createAndEnroll(t, ts, "ops-render", "10.42.9.21", false, false, nil)

	base := ts.URL + "/v1/networks/" + h.netID.String() + "/certificates/expiring"

	code, body := h.adminRaw(t, http.MethodGet, base+"?format=text", nil)
	if code != http.StatusOK {
		t.Fatalf("text expiring: %d", code)
	}
	if !strings.Contains(body, "renewing on schedule") {
		t.Errorf("an empty result rendered as %q, which reads as a broken command", body)
	}

	code, body = h.adminRaw(t, http.MethodGet, base+"?window=13h&format=text", nil)
	if code != http.StatusOK {
		t.Fatalf("text expiring: %d", code)
	}
	if !strings.Contains(body, "ops-render") {
		t.Errorf("text rendering omits the host name:\n%s", body)
	}
}

// TestReplicasReportTheEndpointsAgentsAreGiven.
//
// The list is measured from control-plane heartbeats, not configured, and it is
// the same list — with the same staleness bound — that agents receive as
// EnrollResponse.AgentEndpoints. An operator asking which replicas are live has
// to get the answer the fleet is acting on.
func TestReplicasReportTheEndpointsAgentsAreGiven(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "ops-replica", "10.42.9.30", false, false, nil)
	membershipID := uuid.MustParse(host.id)
	addr := netip.MustParseAddr("10.42.9.30")

	err := h.store.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return tx.RegisterControlPlane(ctx, h.netID, membershipID, addr, 8443)
	})
	if err != nil {
		t.Fatalf("register control plane: %v", err)
	}

	var replicas []wire.ControlPlaneResponse
	if code := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/networks/"+h.netID.String()+"/replicas", nil, &replicas); code != http.StatusOK {
		t.Fatalf("GET replicas: %d", code)
	}

	var found *wire.ControlPlaneResponse
	for i := range replicas {
		if replicas[i].Addr == addr.String() {
			found = &replicas[i]
		}
	}
	if found == nil {
		t.Fatalf("the replica that just heartbeated is missing: %+v", replicas)
	}
	if found.MembershipID != host.id {
		t.Errorf("membership_id = %q, want %q", found.MembershipID, host.id)
	}
	if found.AgentPort != 8443 {
		t.Errorf("agent_port = %d, want 8443 — an endpoint without its port is not dialable",
			found.AgentPort)
	}
	if found.LastSeenAt == "" {
		t.Error("no last_seen_at; liveness here is entirely a function of how recently it heartbeated")
	}
}

// TestOperationalReadsCarryTheScopeTheyDeclare.
//
// The bootstrap token holds "*" and can therefore never prove a route checks
// anything. These four are read surfaces over revocation, CA material,
// certificates, and topology, and each declares the scope of the resource it
// exposes — trust-bundle in particular must not be reachable with a token that
// was only ever trusted to read network metadata.
func TestOperationalReadsCarryTheScopeTheyDeclare(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "ops-networks-read", Scopes: []string{"networks:read"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	net := ts.URL + "/v1/networks/" + h.netID.String()
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/blocklist", http.StatusOK},
		{"/replicas", http.StatusOK},
		{"/trust-bundle", http.StatusForbidden},
		{"/certificates/expiring", http.StatusForbidden},
	} {
		if code := h.reqAs(t, tok.Token, http.MethodGet, net+tc.path, nil, nil); code != tc.want {
			t.Errorf("GET %s with networks:read = %d, want %d", tc.path, code, tc.want)
		}
	}
}

// TestOperationalReadsRefuseAnUnknownNetwork.
//
// Every one of these would otherwise answer an unknown network with an empty
// result: no blocklist entries, an empty bundle, no expiring certificates, no
// replicas. Each of those is a plausible-looking all-clear, and the caller has
// a typo rather than a healthy network.
func TestOperationalReadsRefuseAnUnknownNetwork(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	missing := ts.URL + "/v1/networks/" + uuid.NewString()
	for _, path := range []string{"/blocklist", "/trust-bundle", "/certificates/expiring", "/replicas"} {
		if code := h.adminReq(t, http.MethodGet, missing+path, nil, nil); code != http.StatusNotFound {
			t.Errorf("GET %s on an unknown network = %d, want 404 — an empty result reads as all-clear",
				path, code)
		}
	}
}
