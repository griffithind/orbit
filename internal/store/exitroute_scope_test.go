package store_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/griffithind/orbit/internal/store"
)

// TestAnExitRouteMustBelongToTheSameNetwork.
//
// SetExitRoute reads the route's network_id and never compares it to the
// membership's. Two networks are separate meshes that never exchange traffic —
// they are even allowed to use the same prefix — so a membership pointed at
// another network's exit node renders a default route through a gateway it has
// no certificate relationship with, and every packet it sends to 0.0.0.0/0 goes
// nowhere. The API accepts a bare uuid and does not check either.
func TestAnExitRouteMustBelongToTheSameNetwork(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	a := newNetwork(t, s, "10.10.0.0/24")
	b := newNetwork(t, s, "10.20.0.0/24")
	member := newHost(t, s, a, "member", "10.10.0.5")
	gateway := newHost(t, s, b, "gateway", "10.20.0.5")

	// A perfectly good exit node — in the OTHER network.
	foreign := store.Route{
		NetworkID:    b.ID,
		MembershipID: gateway.ID,
		Prefix:       netip.MustParsePrefix("0.0.0.0/0"),
		Install:      true,
	}
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.CreateRoute(ctx, &foreign)
	}); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.SetExitRoute(ctx, member.ID, &foreign.ID)
	})
	if err == nil {
		t.Fatal("a membership in one network was given an exit route from another")
	}
	t.Logf("refused with: %v", err)
}

// TestAnExitRouteInTheSameNetworkIsAccepted. The check above must reject the
// foreign route because it is foreign, not because the comparison rejects
// everything — which is the way a scoping fix usually breaks.
func TestAnExitRouteInTheSameNetworkIsAccepted(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.30.0.0/24")
	member := newHost(t, s, net, "member", "10.30.0.5")
	gateway := newHost(t, s, net, "gateway", "10.30.0.6")

	own := store.Route{
		NetworkID:    net.ID,
		MembershipID: gateway.ID,
		Prefix:       netip.MustParsePrefix("0.0.0.0/0"),
		Install:      true,
	}
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.CreateRoute(ctx, &own)
	}); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.SetExitRoute(ctx, member.ID, &own.ID)
	}); err != nil {
		t.Fatalf("a same-network exit node was refused: %v", err)
	}

	// And clearing it still works: the nil path skips the checks entirely.
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.SetExitRoute(ctx, member.ID, nil)
	}); err != nil {
		t.Fatalf("clearing the exit node failed: %v", err)
	}
}
