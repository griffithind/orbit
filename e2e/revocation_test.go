package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/wire"
)

// Revocation propagation measurement.
//
// The claim this phase exists to substantiate is that blocking a host removes
// its access faster than the once-a-minute polling the incumbent design implies.
// An unmeasured claim is a marketing claim, so the test below measures the whole
// path end to end and fails the build if it regresses.
//
// What is being timed:
//
//	t0  the block transaction commits
//	 |  NOTIFY delivered on commit, notifier wakes the watcher
//	 |  agent fetches the new generation, validates, installs, SIGHUPs
//	 |  nebula reloads the CA pool with the new blocklist
//	t1  nebula's connection manager tears the tunnel down
//
// t1 is read from nebula's own hostmap, not from anything Orbit believes, so
// the number is what an operator would actually observe.
//
// The floor is not zero. connection_manager.go re-checks certificates on
// timers.connection_alive_interval, 5 seconds by default, so roughly half that
// is unavoidable latency no control plane can remove. Reporting it as part of
// the number rather than quoting only distribution time is the honest choice.

// budget is what the suite asserts. Deliberately generous relative to the
// numbers this actually produces: a tight bound would make the test flaky on a
// loaded CI machine, and the point is to catch a regression from "seconds" to
// "a minute", not to benchmark the host.
const (
	propagationBudgetP50 = 15 * time.Second
	propagationBudgetMax = 45 * time.Second
)

// TestRevocationPropagation measures block-to-teardown across observer hosts.
func TestRevocationPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("propagation measurement takes tens of seconds")
	}

	const observers = 2
	h := setup(t)

	lhPort := freeUDPPort(t)
	lhServer := h.serve(t, lhPort)

	lh := h.createAndEnroll(t, lhServer, "lh-revoke", "10.42.9.1", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})
	lhNode, err := bootNebula(t, lh.dir, lh.addr)
	if err != nil {
		t.Fatalf("boot lighthouse: %v", err)
	}

	// The notifier is the push transport. Start it before anything subscribes.
	notifier := notify.New(h.store.Pool(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	nctx, ncancel := context.WithCancel(context.Background())
	defer ncancel()
	go func() { _ = notifier.Run(nctx) }()
	if err := notifier.Ready(nctx); err != nil {
		t.Fatalf("notifier not ready: %v", err)
	}

	// Serve the agent API on the lighthouse's overlay address, with push.
	overlayURL := h.serveOverlayWithPush(t, lhNode, 8444, lhPort, notifier)

	// The host that will be blocked.
	victimPort := freeUDPPort(t)
	victimServer := h.serve(t, victimPort)
	victim := h.createAndEnroll(t, victimServer, "victim", "10.42.9.5", false, false, nil)
	victimNode, err := bootNebula(t, victim.dir, victim.addr)
	if err != nil {
		t.Fatalf("boot victim: %v", err)
	}

	// Observers: hosts that hold a tunnel to the victim and must drop it.
	type obs struct {
		host *enrolledHost
		node *nebulaNode
		loop *agent.Loop
	}
	var obsList []*obs

	for i := 0; i < observers; i++ {
		port := freeUDPPort(t)
		srv := h.serve(t, port)
		name := fmt.Sprintf("observer-%d", i)
		host := h.createAndEnroll(t, srv, name, fmt.Sprintf("10.42.9.%d", 10+i), false, false, nil)
		node, err := bootNebula(t, host.dir, host.addr)
		if err != nil {
			t.Fatalf("boot %s: %v", name, err)
		}

		st, err := agent.ReadState(host.dir)
		if err != nil {
			t.Fatal(err)
		}
		client := agent.NewClient(overlayURL)
		client.HTTP = overlayHTTPClient(node)

		alog := slog.New(slog.NewTextHandler(io.Discard, nil))
		if debugAgents {
			alog = slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
		}
		layout := agent.DefaultLayout(host.dir)
		loop := &agent.Loop{
			Client: client,
			Applier: &agent.Applier{
				Layout:   layout,
				Reloader: configReloader{c: node.cfg, name: name},
				Log:      alog,
			},
			Policy: agent.DefaultRenewalPolicy(),
			Layout: layout,
			Curve:  cert.Curve_CURVE25519,
			State:  st,
			Log:    alog,
		}
		obsList = append(obsList, &obs{host: host, node: node, loop: loop})
	}

	// Establish tunnels: every observer talks to the victim.
	stop := serveEcho(t, victimNode, 9100, "hello")
	defer stop()
	for _, o := range obsList {
		assertReachable(t, o.node, victim.addr, 9100, "hello")
		if !o.node.HasTunnelTo(victim.addr) {
			t.Fatalf("%s has no tunnel to the victim after a successful dial", o.host.name)
		}
	}

	// Start the agents watching for pushes.
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	for _, o := range obsList {
		go func(o *obs) {
			_ = o.loop.Run(runCtx, agent.RunOptions{
				Push: true, Hold: 20 * time.Second, Interval: 5 * time.Second, Jitter: 0.1,
			})
		}(o)
	}
	// Let the watchers connect before starting the clock, or the measurement
	// includes agent startup rather than propagation.
	time.Sleep(750 * time.Millisecond)

	// ---- t0 ----
	t0 := time.Now()
	var blocked wire.BlockResponse
	if code := h.adminPost(t, lhServer.URL+"/v1/hosts/"+victim.id+"/block", nil, &blocked); code != http.StatusOK {
		t.Fatalf("block: status %d", code)
	}
	t.Logf("blocked victim at epoch %d", blocked.BlocklistEpoch)

	// ---- t1 per observer ----
	type result struct {
		name string
		took time.Duration
	}
	results := make([]result, len(obsList))
	var wg sync.WaitGroup

	for i, o := range obsList {
		wg.Add(1)
		go func(i int, o *obs) {
			defer wg.Done()
			deadline := time.Now().Add(propagationBudgetMax + 15*time.Second)
			for time.Now().Before(deadline) {
				if !o.node.HasTunnelTo(victim.addr) {
					results[i] = result{o.host.name, time.Since(t0)}
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			results[i] = result{o.host.name, -1}
		}(i, o)
	}
	wg.Wait()

	// Report and assert.
	var took []time.Duration
	for _, r := range results {
		if r.took < 0 {
			t.Errorf("%s never dropped its tunnel to the blocked host", r.name)
			continue
		}
		t.Logf("%-12s tunnel torn down after %s", r.name, r.took.Round(10*time.Millisecond))
		took = append(took, r.took)
	}
	if len(took) == 0 {
		t.Fatal("no observer converged")
	}

	sort.Slice(took, func(i, j int) bool { return took[i] < took[j] })
	p50 := took[len(took)/2]
	max := took[len(took)-1]

	t.Logf("propagation: n=%d p50=%s max=%s (incumbent baseline: 60s)",
		len(took), p50.Round(10*time.Millisecond), max.Round(10*time.Millisecond))

	if p50 > propagationBudgetP50 {
		t.Errorf("p50 propagation %s exceeds budget %s", p50, propagationBudgetP50)
	}
	if max > propagationBudgetMax {
		t.Errorf("max propagation %s exceeds budget %s", max, propagationBudgetMax)
	}

	// Convergence must agree with what the data plane did. A number that says
	// "converged" while a tunnel is still up would be worse than no number.
	var conv wire.ConvergenceResponse
	if code := h.adminReq(t, http.MethodGet,
		lhServer.URL+"/v1/networks/"+h.netID.String()+"/convergence", nil, &conv); code != http.StatusOK {
		t.Fatalf("convergence: status %d", code)
	}
	t.Logf("convergence: %d/%d hosts at blocklist epoch %d",
		conv.BlockApplied, conv.HostsTotal, conv.BlocklistEpoch)
	if conv.BlockApplied < len(obsList) {
		t.Errorf("convergence reports %d applied, but %d observers demonstrably applied it",
			conv.BlockApplied, len(obsList))
	}
}

// TestPushBeatsPolling is the comparative claim, isolated.
//
// It measures only the distribution half (block to config-applied) so the
// result is not dominated by nebula's fixed 5-second tunnel check. Push should
// land in well under a second; a 60-second poll obviously cannot.
func TestPushBeatsPolling(t *testing.T) {
	h := setup(t)

	lhPort := freeUDPPort(t)
	lhServer := h.serve(t, lhPort)
	lh := h.createAndEnroll(t, lhServer, "lh-push", "10.42.8.1", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})
	lhNode, err := bootNebula(t, lh.dir, lh.addr)
	if err != nil {
		t.Fatalf("boot lighthouse: %v", err)
	}

	notifier := notify.New(h.store.Pool(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	nctx, ncancel := context.WithCancel(context.Background())
	defer ncancel()
	go func() { _ = notifier.Run(nctx) }()
	if err := notifier.Ready(nctx); err != nil {
		t.Fatal(err)
	}

	overlayURL := h.serveOverlayWithPush(t, lhNode, 8445, lhPort, notifier)

	clientPort := freeUDPPort(t)
	clientServer := h.serve(t, clientPort)
	watcher := h.createAndEnroll(t, clientServer, "watcher", "10.42.8.7", false, false, nil)
	watcherNode, err := bootNebula(t, watcher.dir, watcher.addr)
	if err != nil {
		t.Fatalf("boot watcher: %v", err)
	}

	st, _ := agent.ReadState(watcher.dir)
	client := agent.NewClient(overlayURL)
	client.HTTP = overlayHTTPClient(watcherNode)

	// A host to block, so there is something to distribute.
	victim := h.createAndEnroll(t, clientServer, "push-victim", "10.42.8.9", false, false, nil)

	// Park a watch, then block and time the response.
	type watchResult struct {
		resp *wire.StateResponse
		err  error
		at   time.Time
	}
	done := make(chan watchResult, 1)
	go func() {
		resp, err := client.Watch(context.Background(),
			st.ConfigEpoch, st.BlocklistEpoch, 25*time.Second)
		done <- watchResult{resp, err, time.Now()}
	}()

	// Give the watch time to reach the server and subscribe.
	time.Sleep(500 * time.Millisecond)

	t0 := time.Now()
	var blocked wire.BlockResponse
	if code := h.adminPost(t, lhServer.URL+"/v1/hosts/"+victim.id+"/block", nil, &blocked); code != http.StatusOK {
		t.Fatalf("block: status %d", code)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("watch: %v", r.err)
		}
		if r.resp.Config == "" {
			t.Fatal("watch returned without a new generation despite a block")
		}
		if r.resp.BlocklistEpoch < blocked.BlocklistEpoch {
			t.Errorf("pushed blocklist epoch %d is behind the block's %d",
				r.resp.BlocklistEpoch, blocked.BlocklistEpoch)
		}
		took := r.at.Sub(t0)
		t.Logf("push delivered a new generation %s after the block (poll baseline: up to 60s)",
			took.Round(time.Millisecond))
		if took > 5*time.Second {
			t.Errorf("push took %s; that is not a push", took)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("watch never returned after a block")
	}
}

// TestWatchFallsBackWithoutNotifier proves the degradation is graceful and
// visible. A server with no push must say so, not hang or lie.
func TestWatchFallsBackWithoutNotifier(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t)) // harness.serve configures no notifier

	host := h.createAndEnroll(t, ts, "no-push", "10.42.7.5", false, false, nil)
	st, _ := agent.ReadState(host.dir)

	client := xffClient(t, ts.URL, host.addr)
	_, err := client.Watch(context.Background(), st.ConfigEpoch, st.BlocklistEpoch, time.Second)
	if err == nil {
		t.Fatal("watch succeeded against a server with no notifier")
	}

	var apiErr *agent.APIError
	if !errorsAs(err, &apiErr) || apiErr.Status != http.StatusServiceUnavailable {
		t.Fatalf("watch error = %v, want 503 so the agent knows to poll", err)
	}
}

// debugAgents turns on agent logging for diagnosis. Set ORBIT_DEBUG_AGENTS=1.
var debugAgents = os.Getenv("ORBIT_DEBUG_AGENTS") != ""

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Logf("agent: %s", b)
	return len(b), nil
}
