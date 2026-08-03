package agent

// Loop tests that need a control plane but not a database.
//
// Internal to the package on purpose: the things under test here are the
// pacing decision a watch feeds back into Run, and the report the guard emits.
// Both are unexported, and asserting them through the exported surface would
// mean asserting on timing instead — which is how a test ends up measuring the
// machine rather than the code.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/wire"
)

// fakeControlPlane answers the two endpoints the loop uses here and records
// what it was asked.
type fakeControlPlane struct {
	mu sync.Mutex

	// state is returned from every watch and poll.
	state wire.StateResponse
	// reportStatus is what /agent/v1/report answers with. 204 by default.
	reportStatus int

	watches int
	reports []wire.ReportRequest
}

func (f *fakeControlPlane) serve(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/agent/v1/watch", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.watches++
		state := f.state
		f.mu.Unlock()
		// Answers immediately, exactly as the real server's fast path does
		// whenever the agent's known epoch is behind.
		writeJSON(w, http.StatusOK, state)
	})
	mux.HandleFunc("/agent/v1/state", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		state := f.state
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, state)
	})
	mux.HandleFunc("/agent/v1/report", func(w http.ResponseWriter, r *http.Request) {
		var req wire.ReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.reports = append(f.reports, req)
		status := f.reportStatus
		f.mu.Unlock()
		if status == 0 {
			status = http.StatusNoContent
		}
		w.WriteHeader(status)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeControlPlane) watchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.watches
}

func (f *fakeControlPlane) reported() []wire.ReportRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]wire.ReportRequest(nil), f.reports...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func testLoop(t *testing.T, baseURL string) *Loop {
	t.Helper()
	dir := t.TempDir()
	layout := DefaultLayout(dir)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Loop{
		Client:  NewClient(baseURL),
		Applier: &Applier{Layout: layout, Reloader: NoopReloader{}, Log: log},
		Policy:  DefaultRenewalPolicy(),
		Layout:  layout,
		State:   State{BaseURL: baseURL, HostID: "host-under-test"},
		Log:     log,
	}
}

// writePreviousGeneration gives the applier something to revert to. The files
// are opaque to Revert, which restores bytes and reloads; nothing parses them.
func writePreviousGeneration(t *testing.T, l *Loop) {
	t.Helper()
	dir := l.Applier.PreviousDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{CAName, CertName, KeyName, l.Layout.ConfigName()} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("previous "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestWatchRefusalIsDistinctFromIdle pins a distinction the loop must not
// collapse.
//
// "The hold expired with nothing new" and "the server offered a generation this
// host refuses" were the same false. They are not the same situation: the first
// was paced by the server holding the request, the second is answered
// immediately and will be answered immediately again on every reconnect.
func TestWatchRefusalIsDistinctFromIdle(t *testing.T) {
	cp := &fakeControlPlane{}
	srv := cp.serve(t)
	l := testLoop(t, srv.URL)

	// Nothing new: the server held the request and returned no payload.
	cp.state = wire.StateResponse{ConfigEpoch: 7, BlocklistEpoch: 1}
	got, err := l.watchOnce(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	if got != watchIdle {
		t.Errorf("empty response gave outcome %d, want watchIdle", got)
	}

	// A generation this host has already quarantined.
	l.State.QuarantinedConfigEpoch = 9
	l.State.QuarantinedUntil = time.Now().Add(time.Hour)
	cp.state = wire.StateResponse{ConfigEpoch: 9, BlocklistEpoch: 1, Config: "pki: {}"}

	got, err = l.watchOnce(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	if got != watchRefused {
		t.Errorf("quarantined generation gave outcome %d, want watchRefused", got)
	}
}

// TestWatchDoesNotSpinOnAQuarantinedGeneration is the regression that matters.
//
// The server answers a watch immediately whenever the agent's known epoch is
// behind, and a quarantine keeps it behind for the whole quarantine window. A
// loop that reconnects at once regardless turns a single quarantined host into
// a source of load on the control plane — one notifier subscribe and one state
// read per pass — for thirty minutes, fleet-wide.
//
// Counting requests rather than measuring an interval keeps this honest: a slow
// machine only makes the count smaller, so the test cannot fail by being run
// somewhere slow. Without the backoff the same window produces thousands.
func TestWatchDoesNotSpinOnAQuarantinedGeneration(t *testing.T) {
	cp := &fakeControlPlane{
		state: wire.StateResponse{ConfigEpoch: 9, BlocklistEpoch: 1, Config: "pki: {}"},
	}
	srv := cp.serve(t)

	l := testLoop(t, srv.URL)
	l.State.QuarantinedConfigEpoch = 9
	l.State.QuarantinedUntil = time.Now().Add(time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Interval far longer than the run: after the first refusal the loop must be
	// asleep for the rest of it.
	_ = l.Run(ctx, RunOptions{Push: true, Hold: time.Second, Interval: time.Minute})

	if n := cp.watchCount(); n > 2 {
		t.Errorf("agent sent %d watches while quarantined; it is spinning against the control plane", n)
	}
}

// TestGuardReportsTheRevert covers the gap that made the guard invisible: the
// agent put the previous generation back locally and never said so, leaving the
// control plane counting this host as converged on a configuration it had just
// thrown away — which is the number a CA rotation's convergence gate reads.
func TestGuardReportsTheRevert(t *testing.T) {
	cp := &fakeControlPlane{}
	srv := cp.serve(t)

	l := testLoop(t, srv.URL)
	writePreviousGeneration(t, l)

	now := time.Now()
	l.SetClock(func() time.Time { return now })
	l.Guard = GuardPolicy{ConfirmWithin: time.Minute, MinConfirm: time.Minute, Quarantine: time.Hour}

	// An applied but never confirmed generation 9, over 8.
	l.State.ConfigEpoch, l.State.BlocklistEpoch = 9, 4
	l.State.PrevConfigEpoch, l.State.PrevBlocklistEpoch = 8, 3
	l.markApplied(8, 3)

	now = now.Add(2 * time.Minute) // past ConfirmWithin, nothing confirmed
	l.checkGuard(context.Background())

	reports := cp.reported()
	if len(reports) != 1 {
		t.Fatalf("guard sent %d reports, want exactly 1", len(reports))
	}
	got := reports[0]
	if got.ConfigEpoch != 8 || got.BlocklistEpoch != 3 {
		t.Errorf("reported epochs (%d, %d), want the reverted-to (8, 3)",
			got.ConfigEpoch, got.BlocklistEpoch)
	}
	if got.RevertedFromConfigEpoch != 9 || got.RevertedFromBlocklistEpoch != 4 {
		t.Errorf("reported reverted-from (%d, %d), want (9, 4); without it the server "+
			"keeps the higher epoch and the revert stays invisible",
			got.RevertedFromConfigEpoch, got.RevertedFromBlocklistEpoch)
	}
	if got.QuarantinedConfigEpoch != 9 {
		t.Errorf("reported quarantined epoch %d, want 9: a host that refused a "+
			"generation must not look like a host that is merely slow",
			got.QuarantinedConfigEpoch)
	}
}

// TestGuardRevertsEvenWhenTheReportFails is the ordering property. A revert
// happens precisely when the control plane may be unreachable, so the report is
// the call most likely to fail — and it must not be able to prevent or undo a
// rollback that already put a working generation back on disk.
func TestGuardRevertsEvenWhenTheReportFails(t *testing.T) {
	cp := &fakeControlPlane{reportStatus: http.StatusInternalServerError}
	srv := cp.serve(t)

	l := testLoop(t, srv.URL)
	writePreviousGeneration(t, l)

	now := time.Now()
	l.SetClock(func() time.Time { return now })
	l.Guard = GuardPolicy{ConfirmWithin: time.Minute, MinConfirm: time.Minute, Quarantine: time.Hour}

	l.State.ConfigEpoch, l.State.BlocklistEpoch = 9, 4
	l.State.PrevConfigEpoch, l.State.PrevBlocklistEpoch = 8, 3
	l.markApplied(8, 3)

	now = now.Add(2 * time.Minute)
	l.checkGuard(context.Background())

	if l.State.ConfigEpoch != 8 {
		t.Errorf("config epoch = %d after a failed report, want the reverted 8", l.State.ConfigEpoch)
	}
	if l.State.QuarantinedConfigEpoch != 9 {
		t.Errorf("quarantined epoch = %d, want 9: the failed report undid the quarantine",
			l.State.QuarantinedConfigEpoch)
	}
	if !l.State.UnconfirmedSince.IsZero() {
		t.Error("guard left the reverted generation marked unconfirmed; it would revert again")
	}
	// Persisted, so a restart does not lose the quarantine and re-apply the
	// generation that broke this host — nor lose the fact that the control plane
	// still has to be told.
	st, err := ReadState(l.Layout.Dir)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if st.QuarantinedConfigEpoch != 9 || st.ConfigEpoch != 8 {
		t.Errorf("persisted state = (config %d, quarantined %d), want (8, 9)",
			st.ConfigEpoch, st.QuarantinedConfigEpoch)
	}
	if st.PendingRevertFromConfigEpoch != 9 || st.PendingRevertFromBlocklistEpoch != 4 {
		t.Errorf("persisted pending revert = (%d, %d), want (9, 4): a report lost here "+
			"is lost for good, because a quarantined host applies nothing and so never "+
			"reports again", st.PendingRevertFromConfigEpoch, st.PendingRevertFromBlocklistEpoch)
	}
}

// TestRevertReportIsRetriedUntilItLands is why the pending marker exists.
//
// The report sent immediately after a revert goes out over a data plane that was
// reloaded milliseconds earlier — the same asynchrony MinConfirm exists for — so
// it is more likely to fail than to succeed. And while the quarantine holds, the
// agent applies nothing, so nothing else would ever report: one lost attempt
// would mean the control plane keeps counting this host as converged for the
// whole quarantine window.
func TestRevertReportIsRetriedUntilItLands(t *testing.T) {
	cp := &fakeControlPlane{reportStatus: http.StatusInternalServerError}
	srv := cp.serve(t)

	l := testLoop(t, srv.URL)
	writePreviousGeneration(t, l)

	now := time.Now()
	l.SetClock(func() time.Time { return now })
	l.Guard = GuardPolicy{ConfirmWithin: time.Minute, MinConfirm: time.Minute, Quarantine: time.Hour}

	l.State.ConfigEpoch, l.State.BlocklistEpoch = 9, 4
	l.State.PrevConfigEpoch, l.State.PrevBlocklistEpoch = 8, 3
	l.markApplied(8, 3)

	now = now.Add(2 * time.Minute)
	l.checkGuard(context.Background()) // reverts; the report is refused

	// The control plane comes back. An ordinary poll must carry the correction,
	// even though there is nothing to apply and so nothing that would normally
	// produce a report.
	cp.mu.Lock()
	cp.reportStatus = http.StatusNoContent
	cp.mu.Unlock()

	if err := l.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	reports := cp.reported()
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want 2 (the failed attempt and the retry)", len(reports))
	}
	if got := reports[1]; got.RevertedFromConfigEpoch != 9 || got.ConfigEpoch != 8 {
		t.Errorf("retry reported epoch %d reverted from %d, want 8 from 9",
			got.ConfigEpoch, got.RevertedFromConfigEpoch)
	}

	// Delivered, so it stops being resent: further polls are ordinary reports or
	// none at all.
	if err := l.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n := len(cp.reported()); n != 2 {
		t.Errorf("agent sent %d reports; a delivered revert must not keep being retried", n)
	}
	if st, err := ReadState(l.Layout.Dir); err != nil {
		t.Fatalf("read state: %v", err)
	} else if st.PendingRevertFromConfigEpoch != 0 {
		t.Errorf("pending revert = %d after a successful report, want cleared",
			st.PendingRevertFromConfigEpoch)
	}
}

// TestApplySupersedesAPendingRevert stops the agent describing a state that has
// been overtaken: once a newer generation is installed, the epoch the revert
// named is no longer what the control plane holds, and re-sending it could only
// misreport.
func TestApplySupersedesAPendingRevert(t *testing.T) {
	l := testLoop(t, "http://127.0.0.1:0")
	l.State.PendingRevertFromConfigEpoch = 9
	l.State.PendingRevertFromBlocklistEpoch = 4

	l.markApplied(8, 3)

	if l.State.PendingRevertFromConfigEpoch != 0 || l.State.PendingRevertFromBlocklistEpoch != 0 {
		t.Errorf("pending revert survived an apply: (%d, %d)",
			l.State.PendingRevertFromConfigEpoch, l.State.PendingRevertFromBlocklistEpoch)
	}
	if req := l.reportRequest(); req.RevertedFromConfigEpoch != 0 {
		t.Errorf("report still claims a revert from %d", req.RevertedFromConfigEpoch)
	}
}

// TestReportCarriesTheQuarantineWhileItLasts covers the steady-state half: the
// quarantine is reported on every report, not only on the one following the
// revert, and it stops being reported once it expires.
func TestReportCarriesTheQuarantineWhileItLasts(t *testing.T) {
	cp := &fakeControlPlane{}
	srv := cp.serve(t)

	l := testLoop(t, srv.URL)
	now := time.Now()
	l.SetClock(func() time.Time { return now })
	l.State.ConfigEpoch = 8
	l.State.QuarantinedConfigEpoch = 9
	l.State.QuarantinedUntil = now.Add(30 * time.Minute)

	l.report(context.Background())
	now = now.Add(31 * time.Minute) // quarantine lapsed
	l.report(context.Background())

	reports := cp.reported()
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want 2", len(reports))
	}
	if reports[0].QuarantinedConfigEpoch != 9 {
		t.Errorf("first report carried quarantined epoch %d, want 9", reports[0].QuarantinedConfigEpoch)
	}
	if reports[1].QuarantinedConfigEpoch != 0 {
		t.Errorf("report after the quarantine lapsed still carried epoch %d",
			reports[1].QuarantinedConfigEpoch)
	}
	// Reading the quarantine for a report must not expire it as a side effect;
	// that decision belongs to the apply path.
	if l.State.QuarantinedConfigEpoch != 9 {
		t.Error("reporting cleared the quarantine as a side effect")
	}
}
