package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/adminclient"
	"github.com/griffithind/orbit/internal/wire"
)

// GET /v1/networks/{ref} takes a uuid or a name.
//
// Names are globally unique for networks — UNIQUE (name), not UNIQUE (parent,
// name) as for hosts and roles — so a name identifies exactly one, and every
// client that knows a network by the name its operator uses can resolve it in
// one request instead of listing all of them and filtering.

func TestGetNetworkByIDAndByName(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var byID wire.NetworkResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/networks/"+h.netID.String(), nil, &byID); code != http.StatusOK {
		t.Fatalf("get by id: %d", code)
	}
	if byID.Name != h.netName {
		t.Errorf("name = %q, want %q", byID.Name, h.netName)
	}

	var byName wire.NetworkResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/networks/"+h.netName, nil, &byName); code != http.StatusOK {
		t.Fatalf("get by name: %d", code)
	}
	if byName.ID != byID.ID {
		t.Errorf("name and id resolved to different networks: %s vs %s", byName.ID, byID.ID)
	}
}

func TestGetNetworkUnknownRefIs404(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	for _, ref := range []string{"no-such-network", uuid.NewString()} {
		if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/networks/"+ref, nil, nil); code != http.StatusNotFound {
			t.Errorf("get %q = %d, want 404", ref, code)
		}
	}
}

// TestNetworkSlugAndNameAreDifferentThings covers the identity split.
//
// Migration 0005 once refused a network name shaped like a uuid, because
// GET /v1/networks/{ref} resolved names and a uuid-shaped one would either miss
// or resolve to a different network. That rule is gone, and BOTH halves of why
// are worth asserting:
//
//   - The slug, which is what a script addresses, cannot collide with a uuid at
//     all. The charset caps it at 32 characters and a uuid's canonical form is
//     36, so the two are disjoint by length before a character is compared —
//     there is nothing left for a constraint to enforce.
//   - The name addresses nothing any more, so a uuid-shaped name is merely an
//     unreadable label rather than an ambiguity, and refusing it would be a rule
//     with no failure behind it.
//
// The slug's own rules — the charset, the uniqueness, and the immutability
// trigger — are asserted in internal/store/address_test.go, where they can be
// exercised against the database directly. They belong there rather than here
// because they are database constraints: `orbitd bootstrap` writes networks too,
// so a test that only went through this handler would be testing the handler
// rather than the rule.
func TestNetworkSlugAndNameAreDifferentThings(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	// A uuid-shaped display name is now legal, and that is the visible half of
	// the change: the name addresses nothing, so there is nothing for it to
	// shadow.
	var net wire.NetworkResponse
	if code := h.adminPost(t, ts.URL+"/v1/networks", wire.CreateNetworkRequest{
		Name: uuid.NewString(), CIDRs: []string{"10.58.0.0/16"},
	}, &net); code != http.StatusCreated {
		t.Fatalf("uuid-shaped display name refused with %d; the name is not an "+
			"addressing key any more", code)
	}

	// And the network is still reachable by its id, which is what a caller
	// holding a uuid uses.
	var byID wire.NetworkResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/networks/"+net.ID, nil, &byID); code != http.StatusOK {
		t.Fatalf("get by id after a uuid-shaped name: %d", code)
	}
	if byID.ID != net.ID {
		t.Errorf("a uuid-shaped name shadowed an id: asked for %s, got %s", net.ID, byID.ID)
	}
}

// TestResolveNetworkAcceptsEitherForm exercises the client path the CLI uses.
//
// The performance reason for this route — one request instead of listing every
// network — is visible in ResolveNetwork's source and not worth a counting
// proxy to assert. What is worth asserting is that both forms still resolve to
// the same network, and that a miss still names the alternatives, since the
// fast path deliberately skips the listing that produces them.
func TestResolveNetworkAcceptsEitherForm(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	c := adminclient.New(ts.URL, h.token)
	ctx := context.Background()

	byName, err := c.ResolveNetwork(ctx, h.netName)
	if err != nil {
		t.Fatalf("resolve by name: %v", err)
	}
	byID, err := c.ResolveNetwork(ctx, h.netID.String())
	if err != nil {
		t.Fatalf("resolve by id: %v", err)
	}
	if byName.ID != byID.ID {
		t.Errorf("name and id resolved differently: %s vs %s", byName.ID, byID.ID)
	}

	// A miss must still list the alternatives, which the one-request fast path
	// skips — so the fallback has to fire.
	_, err = c.ResolveNetwork(ctx, "definitely-not-a-network")
	if err == nil {
		t.Fatal("resolving an unknown network succeeded")
	}
	// The listing is previewed rather than dumped, so a deployment with a
	// thousand networks does not print a thousand names. Assert the fallback
	// fired and produced alternatives, not that this network is among the first
	// few shown.
	if !strings.Contains(err.Error(), "available:") {
		t.Errorf("error did not offer any alternatives, so the listing fallback "+
			"did not fire: %v", err)
	}
}
