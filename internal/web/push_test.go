package web

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/notify"
)

// Push has three states and the middle one is why this file exists.
//
// "Not configured" and "working" were always distinguishable. "Configured but
// the listener is not connected right now" was not, because notify only exposed
// Ready(), which stays satisfied across a drop. It is also the only one of the
// three that is a fault: nothing else on the overview changes when the listener
// drops — epochs still advance, convergence still climbs, just slowly — so if
// this badge does not say it, nothing does.

func TestPushStatusDistinguishesDownFromNotConfigured(t *testing.T) {
	s := testServer(t)
	net := uuid.New()

	s.cfg.Notifier = nil
	off := s.pushStatus(net)

	// A notifier that exists but whose Run has never been called is exactly the
	// shape of one whose connection has dropped: configured, and deaf.
	s.cfg.Notifier = notify.New(nil, nil)
	down := s.pushStatus(net)

	if off.Badge.Word == down.Badge.Word {
		t.Errorf("push disabled and push broken render the same badge (%q).\n"+
			"An operator cannot tell a deliberate configuration from an outage.",
			off.Badge.Word)
	}
	if off.Detail == down.Detail {
		t.Error("push disabled and push broken render the same explanation")
	}
	if down.Configured {
		t.Error("a disconnected listener reported as Configured, which makes the " +
			"template print the watcher count — agents parked on a listener that " +
			"cannot hear anything, presented as reassurance")
	}
	if !strings.Contains(strings.ToLower(down.Detail), "poll") {
		t.Errorf("the down explanation does not say what the consequence is: %q", down.Detail)
	}
}
