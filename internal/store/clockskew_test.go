package store_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/store"
)

// Liveness must not depend on two clocks agreeing.
//
// control_plane.last_seen_at is stamped by the DATABASE (`SET last_seen_at =
// now()`), and every caller computed the cutoff from the Go process clock
// (`time.Now().Add(-stale)`). That comparison spans two machines: orbitd and
// Postgres are routinely not the same host, and a Go clock more than the
// staleness window ahead of the database's silently empties the replica list.
// Agents then fall back to the public URL and lose their failover set, with
// nothing in any log to say why.
//
// Found while investigating a flaky e2e (TestEnrollmentAdvertisesLiveReplicas
// seeing an empty list), NOT proven to have caused it — measured skew between
// the Go process and Postgres was ~0.1s at the time, far inside the window, and
// the flake was never reproduced. It is a real defect either way: orbitd and
// Postgres are routinely not the same host, and nothing bounds their drift.
//
// LiveControlPlanes now takes a DURATION and does the arithmetic in SQL, so both
// sides of the comparison come from the same clock and no skew can reach it.
func TestControlPlaneLivenessIsImmuneToClockSkew(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetwork(t, s, "10.77.0.0/16")
	host := newHost(t, s, net, "cp-1", "10.77.0.2")

	if err := s.Register(ctx, net.ID, host.ID, netip.MustParseAddr("10.77.0.2"), 8443); err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		live, err := tx.LiveControlPlanes(ctx, net.ID, 3*time.Minute)
		if err != nil {
			return err
		}
		if len(live) != 1 {
			t.Errorf("a replica registered moments ago is not live: %v", live)
		}
		return nil
	}); err != nil {
		t.Fatalf("query: %v", err)
	}

	// A window of zero must exclude it, or the query is not filtering at all
	// and the assertion above proves nothing.
	if err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		live, err := tx.LiveControlPlanes(ctx, net.ID, 0)
		if err != nil {
			return err
		}
		if len(live) != 0 {
			t.Errorf("a zero staleness window still returned %d replicas", len(live))
		}
		return nil
	}); err != nil {
		t.Fatalf("query: %v", err)
	}
}
