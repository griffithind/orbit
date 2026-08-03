package notify

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The fan-out is the one piece of shared mutable state on the hot path: every
// watcher subscribes and releases concurrently while dispatch walks the map.
// These tests exist to be run under -race.
//
// They drive dispatch directly rather than through Postgres, deliberately. The
// e2e suite covers the LISTEN path, but it runs a full nebula instance and is
// ~100x slower under race instrumentation — which also makes the propagation
// measurement in e2e/revocation_test.go meaningless, since it would be timing
// the detector. Separating them means the concurrency gets checked and the
// measurement stays honest.

func TestDispatchIsSafeUnderSubscribeChurn(t *testing.T) {
	n := New(nil, nil)
	net := uuid.New()

	var (
		wg      sync.WaitGroup
		stop    atomic.Bool
		woken   atomic.Int64
		waiters = 32
	)

	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Subscribe, wait briefly, release, repeat. This is what a fleet of
			// agents reconnecting looks like, and it is the pattern that finds
			// a map written without the lock held.
			for !stop.Load() {
				ch, release := n.Subscribe(net)
				select {
				case <-ch:
					woken.Add(1)
				case <-time.After(time.Millisecond):
				}
				release()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			n.dispatch(Event{NetworkID: net, Kind: "config", Epoch: 1})
		}
	}()

	time.Sleep(200 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	if woken.Load() == 0 {
		t.Error("no subscriber was ever woken; the fan-out is not delivering")
	}
	if got := n.Subscribers(net); got != 0 {
		t.Errorf("%d subscribers left after every release; the map leaks", got)
	}
}

// TestDispatchNeverBlocks is the property that keeps one stalled agent from
// stopping delivery to everyone else. The channel is a signal, not a queue: a
// subscriber with an unread event gets the new one dropped rather than having
// the publisher wait on it.
func TestDispatchNeverBlocks(t *testing.T) {
	n := New(nil, nil)
	net := uuid.New()

	// Subscribe and never read. The buffer of one fills on the first dispatch.
	_, release := n.Subscribe(net)
	defer release()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			n.dispatch(Event{NetworkID: net, Kind: "config", Epoch: int64(i)})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch blocked on a subscriber that stopped reading; one " +
			"stalled agent would stop delivery to the whole fleet")
	}
}

// TestSubscribersAreIsolatedByNetwork. A dispatch for one network must not wake
// another's watchers, or every agent everywhere re-reads state on every change.
func TestSubscribersAreIsolatedByNetwork(t *testing.T) {
	n := New(nil, nil)
	a, b := uuid.New(), uuid.New()

	chA, releaseA := n.Subscribe(a)
	defer releaseA()
	chB, releaseB := n.Subscribe(b)
	defer releaseB()

	n.dispatch(Event{NetworkID: a, Kind: "blocklist", Epoch: 7})

	select {
	case ev := <-chA:
		if ev.Epoch != 7 {
			t.Errorf("epoch = %d, want 7", ev.Epoch)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber to the dispatched network was not woken")
	}

	select {
	case ev := <-chB:
		t.Errorf("subscriber to a different network was woken with %+v", ev)
	default:
	}
}

// TestObserverSeesListenerState. orbit_epoch_listener_up is the gauge that
// distinguishes "push is working" from "everyone silently fell back to
// polling", so the transitions have to actually fire.
func TestObserverSeesListenerState(t *testing.T) {
	var obs recordingObserver
	n := New(nil, nil).Observe(&obs)

	n.up(true)
	n.up(false)
	n.dispatch(Event{NetworkID: uuid.New(), Kind: "config"})

	if got := obs.states(); len(got) != 2 || !got[0] || got[1] {
		t.Errorf("listener states = %v, want [true false]", got)
	}
}

type recordingObserver struct {
	mu   sync.Mutex
	seen []bool
}

func (o *recordingObserver) ListenerUp(up bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, up)
}

func (o *recordingObserver) EpochNotified(string) {}

func (o *recordingObserver) states() []bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]bool(nil), o.seen...)
}
