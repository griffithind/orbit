package notify

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
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

	// Churn for a while, then keep going until the fan-out has demonstrably
	// delivered — bounded, so a genuine failure still fails.
	//
	// This was a flat 200ms sleep followed by "at least one subscriber was
	// woken". That asserts a scheduling outcome inside one window of wall
	// clock: each subscriber waits 1ms for a wake before releasing, and under
	// -race, where the detector costs five to twenty times, a loaded runner can
	// spend the whole window without ever lining up a dispatch with a waiting
	// receiver. Nothing would be wrong, and the test would say the fan-out is
	// not delivering.
	//
	// The lower bound is what finds the lock bug this test exists for, so it is
	// kept; the upper bound is what makes the assertion about delivery instead
	// of about timing.
	const churn = 200 * time.Millisecond
	start := time.Now()
	deadline := start.Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if woken.Load() > 0 && time.Since(start) >= churn {
			break
		}
		time.Sleep(time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()

	if woken.Load() == 0 {
		t.Errorf("no subscriber was woken in %s of continuous dispatch; "+
			"the fan-out is not delivering", time.Since(start).Round(time.Millisecond))
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

// TestUpTracksTheObservedState is the cheap half of Up: it runs without a
// database, so the property holds in a checkout where Postgres is absent.
func TestUpTracksTheObservedState(t *testing.T) {
	n := New(nil, nil)

	if n.Up() {
		t.Error("a notifier that has never listened reports push as up")
	}
	n.up(true)
	if !n.Up() {
		t.Error("Up did not follow the transition the Observer saw")
	}
	n.up(false)
	if n.Up() {
		t.Error("Up stayed true after the listener went down")
	}
}

// The rest exercise the real LISTEN connection, because the bug they exist to
// pin lives in listen's exit paths and cannot be reached by calling up()
// directly. They need nothing but a reachable Postgres — LISTEN requires no
// privilege and touches no table — so they connect with the admin DSN rather
// than standing up the schema.

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("ORBIT_TEST_DSN")
	if dsn == "" {
		dsn = "postgres://postgres:orbit@localhost:5433/orbit?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres unavailable, skipping listener state tests: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("postgres unavailable, skipping listener state tests: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestUpFollowsTheRealListener(t *testing.T) {
	n := New(testPool(t), discardLog())

	if n.Up() {
		t.Fatal("Up was true before Run was ever called")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = n.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer readyCancel()
	if err := n.Ready(readyCtx); err != nil {
		cancel()
		t.Fatalf("listener never established: %v", err)
	}
	if !n.Up() {
		t.Error("LISTEN is established and Up says push is down")
	}

	// The regression this pins: Run returns on a cancelled context before it
	// reaches the code that reported the listener down, so Up kept answering
	// true for a notifier that had stopped. The pairing now lives in listen's
	// defer, where no exit can skip it.
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return on a cancelled context")
	}
	if n.Up() {
		t.Error("Up still reports push as working after the notifier stopped.\n" +
			"A health probe would say push is fine while every agent is polling.")
	}
}

// TestReadyAndUpAnswerDifferentQuestions. If these two ever agree in every
// state, one of them is redundant and the wrong one will get deleted. Ready is
// "established at least once" — a startup race guard, deliberately sticky. Up is
// "connected right now" — an operational signal. Cancellation is where they part.
func TestReadyAndUpAnswerDifferentQuestions(t *testing.T) {
	n := New(testPool(t), discardLog())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = n.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer readyCancel()
	if err := n.Ready(readyCtx); err != nil {
		cancel()
		t.Fatalf("listener never established: %v", err)
	}

	cancel()
	<-done

	if err := n.Ready(context.Background()); err != nil {
		t.Errorf("Ready stopped being satisfied after shutdown: %v", err)
	}
	if n.Up() {
		t.Error("Up agreed with Ready after shutdown; then Up reports nothing new")
	}
}
