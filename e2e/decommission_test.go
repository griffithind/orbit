package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// TestDeleteHostRevokesBeforeRemoving is the property that makes deletion
// meaningful.
//
// A decommission that only removed the row would leave the machine holding a
// certificate valid until expiry — a delete weaker than a block. The order in
// store.DeleteHost is what prevents that, and the evidence is that the
// fingerprint is on the distributed blocklist after the host record is gone.
func TestDeleteHostRevokesBeforeRemoving(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	ctx := context.Background()

	host := h.createAndEnroll(t, ts, "doomed", "10.42.9.9", false, false, nil)

	fingerprint := certFingerprint(t, h, host.id)
	if fingerprint == "" {
		t.Fatal("enrolled host has no certificate on record")
	}

	before := h.networkEpochs(t, ts.URL)

	var resp wire.BlockResponse
	if code := h.adminReq(t, http.MethodDelete,
		ts.URL+"/v1/memberships/"+host.id+"?reason=decommissioned", nil, &resp); code != http.StatusOK {
		t.Fatalf("delete host: %d", code)
	}

	// The row is gone.
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/memberships/"+host.id, nil, nil); code != http.StatusNotFound {
		t.Errorf("GET deleted host = %d, want 404", code)
	}

	// The certificate is not.
	var live []string
	if err := h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		live, err = tx.LiveBlocklist(ctx, h.netID, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !contains(live, fingerprint) {
		t.Errorf("deleted host's fingerprint %q is not on the blocklist; its certificate\n"+
			"is still trusted by every peer until it expires", fingerprint)
	}

	// Both epochs move: the blocklist because a certificate was revoked, the
	// config because every other host's rendered view of the mesh changed.
	after := h.networkEpochs(t, ts.URL)
	if after.BlocklistEpoch <= before.BlocklistEpoch {
		t.Errorf("blocklist epoch %d did not advance past %d",
			after.BlocklistEpoch, before.BlocklistEpoch)
	}
	if after.ConfigEpoch <= before.ConfigEpoch {
		t.Errorf("config epoch %d did not advance past %d; peers would keep a "+
			"deleted lighthouse in static_host_map", after.ConfigEpoch, before.ConfigEpoch)
	}
	if resp.BlocklistEpoch != after.BlocklistEpoch {
		t.Errorf("response epoch %d != network epoch %d", resp.BlocklistEpoch, after.BlocklistEpoch)
	}
}

// TestDeleteHostFreesTheName confirms deletion is a decommission and not a
// tombstone: the (network, name) unique constraint must not keep a retired
// name reserved forever.
func TestDeleteHostFreesTheName(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	first := h.createAndEnroll(t, ts, "recycled", "10.42.9.10", false, false, nil)
	if code := h.adminReq(t, http.MethodDelete, ts.URL+"/v1/memberships/"+first.id, nil, nil); code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}

	// Same name, same address, new identity.
	second := h.createAndEnroll(t, ts, "recycled", "10.42.9.10", false, false, nil)
	if second.id == first.id {
		t.Error("reused host id; the replacement must be a distinct identity")
	}
}

// TestDeleteHostAuditRecordsTheName checks that the trail survives the row.
//
// audit_log stores targets as strings and is append-only, so it outlives the
// host. A uuid alone would be useless to whoever reads it later, which is why
// the handler captures the name before deleting.
func TestDeleteHostAuditRecordsTheName(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "audited-away", "10.42.9.11", false, false, nil)
	if code := h.adminReq(t, http.MethodDelete,
		ts.URL+"/v1/memberships/"+host.id+"?reason=hardware+returned", nil, nil); code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}

	var entries []wire.AuditRecordResponse
	if code := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/audit-logs?action="+store.ActionMembershipDeleted+"&target_id="+host.id,
		nil, &entries); code != http.StatusOK {
		t.Fatalf("read audit: %d", code)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries for the deletion, want 1", len(entries))
	}
	meta := string(entries[0].Meta)
	if !strings.Contains(meta, "audited-away") {
		t.Errorf("audit meta %q omits the host name", meta)
	}
	if !strings.Contains(meta, "hardware returned") {
		t.Errorf("audit meta %q omits the operator's reason", meta)
	}
}

// TestDeleteHostRequiresBlockScope: deletion revokes, so a token that may edit
// hosts but not cut them off must not reach the same outcome through DELETE.
func TestDeleteHostRequiresBlockScope(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "scoped", "10.42.9.12", false, false, nil)

	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "editor-" + uuid.NewString()[:8], Scopes: []string{"memberships:write", "memberships:read"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	if code := h.reqAs(t, tok.Token, http.MethodDelete, ts.URL+"/v1/memberships/"+host.id, nil, nil); code != http.StatusForbidden {
		t.Errorf("delete with memberships:write only = %d, want 403", code)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func certFingerprint(t *testing.T, h *harness, membershipID string) string {
	t.Helper()
	id, err := uuid.Parse(membershipID)
	if err != nil {
		t.Fatal(err)
	}
	var fp string
	if err := h.store.Read(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		c, err := tx.LatestCertificate(ctx, id)
		if err != nil {
			return err
		}
		fp = c.Fingerprint
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return fp
}
