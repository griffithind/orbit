package nebulacfg

import (
	"testing"
	"time"
)

// TestRespondDelayDoesNotRaceTheHandshakeGiveUp.
//
// nebula's initiator gives up at hsTimeout(10, 100ms) = 5500ms
// (third_party/nebula/handshake_manager.go:645, defaults at :23-24). Its
// default punchy.respond_delay is 5000ms, and the responder's clock starts
// LATER — the punch notification travels A→lighthouse→B first — so the
// mechanism had under 500ms to land, minus scheduler wakeup and one RTT.
//
// Orbit enables `respond` against nebula's default of off, which makes the
// value Orbit's responsibility. The number is pinned here because it is
// meaningless on its own: what matters is the margin against 5500ms, and a
// future edit that reads "2s is arbitrary, make it 5s" would silently restore
// the race. See docs/adr/0032-discovery-survives-the-lighthouse.md.
func TestRespondDelayDoesNotRaceTheHandshakeGiveUp(t *testing.T) {
	const giveUp = 5500 * time.Millisecond // hsTimeout(10, 100ms)

	respond, err := time.ParseDuration(defaultPunchyRespondDelay)
	if err != nil {
		t.Fatalf("punchy.respond_delay is not a duration: %v", err)
	}
	if respond >= giveUp {
		t.Fatalf("respond_delay %s fires at or after the initiator gives up at %s", respond, giveUp)
	}
	// A notification through the lighthouse plus a round trip, with room to
	// spare. Half the budget is the line in the sand.
	if margin := giveUp - respond; margin < giveUp/2 {
		t.Errorf("respond_delay %s leaves only %s before the initiator gives up at %s; "+
			"the responder's clock starts after A→lighthouse→B, so this is not the whole budget",
			respond, margin, giveUp)
	}
}
