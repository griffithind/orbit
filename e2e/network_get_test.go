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

// TestNetworkNameCannotLookLikeAUUID is what makes the dual-form route safe.
//
// Without it, a network named after a uuid would parse as an id, be looked up
// as one, and either miss or — worse — resolve to a different network that
// genuinely holds that id. Whichever branch the resolver tries first is wrong
// for somebody, so the overlap is refused instead of disambiguated.
//
// Enforced by the database (migration 0005) rather than by the handler, because
// `orbitd bootstrap` creates networks too and an invariant enforced in one
// handler is enforced in whichever handler someone remembers.
func TestNetworkNameCannotLookLikeAUUID(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	code := h.adminReq(t, http.MethodPost, ts.URL+"/v1/networks", wire.CreateNetworkRequest{
		Name: uuid.NewString(), CIDRs: []string{"10.55.0.0/16"},
	}, nil)
	if code == http.StatusCreated {
		t.Fatal("a network was created with a uuid-shaped name; GET /v1/networks/{ref} " +
			"can no longer tell an id from a name")
	}
	// 400, not 500. The request will never succeed as sent, and an operator who
	// gets "internal error" retries it.
	if code != http.StatusBadRequest {
		t.Errorf("uuid-shaped name rejected with %d, want 400 — a CHECK violation "+
			"is the caller's problem and must say so", code)
	}

	// Something uuid-adjacent but not a uuid stays legal — the constraint must
	// not reject ordinary names that merely contain hex and dashes.
	if code := h.adminReq(t, http.MethodPost, ts.URL+"/v1/networks", wire.CreateNetworkRequest{
		Name: "prod-2026-08-03-" + uuid.NewString()[:8], CIDRs: []string{"10.56.0.0/16"},
	}, nil); code != http.StatusCreated {
		t.Errorf("a legitimate hyphenated name was refused: %d", code)
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
