package e2e

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/wire"
)

// Liveness and readiness.
//
// Without these endpoints the only signal a load balancer, a systemd readiness
// check, or a monitoring probe has is whether the TCP port accepts a
// connection — which stays green through a total database outage, on a process
// that will fail every request it is handed.

// servePublicWithHealth mirrors what orbitd builds for its public listener,
// plus the health routes.
//
// Written out here rather than reusing servePublicOnly because the two together
// are the assertion: health has to be mountable alongside the authenticated
// surfaces without inheriting their authentication.
func (h *harness) servePublicWithHealth(t *testing.T, nebulaPort int) *httptest.Server {
	t.Helper()

	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      nebulaPort,
	})
	srv := api.New(h.store, svc, api.Config{DisableEnrollLimit: true},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	mux := http.NewServeMux()
	srv.EnrollRoutes(mux)
	srv.AdminRoutes(mux)
	srv.HealthRoutes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// servePublicWithNotifier is servePublicWithHealth carrying a notifier, so
// /readyz has something real to report on.
func (h *harness) servePublicWithNotifier(t *testing.T, nebulaPort int, notifier *notify.Notifier) *httptest.Server {
	t.Helper()

	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      nebulaPort,
	})
	// No Metrics, deliberately: that is the configuration in which the old
	// implementation had nowhere to read the live state from and answered with
	// configured-ness instead.
	srv := api.New(h.store, svc, api.Config{DisableEnrollLimit: true, Notifier: notifier},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	mux := http.NewServeMux()
	srv.HealthRoutes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// probe issues an unauthenticated GET, which is the whole point: a load
// balancer cannot hold a bearer token, and neither can systemd.
func probe(t *testing.T, url string) (int, wire.HealthResponse) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var out wire.HealthResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("GET %s returned %s: %v", url, raw, err)
	}
	return resp.StatusCode, out
}

// TestHealthNeedsNoCredential. Every other route on this listener answers 401
// without a token. These two must not, or nothing that probes for a living can
// use them.
func TestHealthNeedsNoCredential(t *testing.T) {
	h := setup(t)
	ts := h.servePublicWithHealth(t, freeUDPPort(t))

	for _, path := range []string{"/healthz", "/readyz"} {
		code, body := probe(t, ts.URL+path)
		if code != http.StatusOK {
			t.Errorf("unauthenticated GET %s = %d, want 200", path, code)
		}
		if body.Status != "ok" {
			t.Errorf("%s status = %q, want \"ok\" against a live database", path, body.Status)
		}
		if !body.Database {
			t.Errorf("%s reports the database unreachable, but the harness is talking to it", path)
		}
		if body.Version == "" {
			t.Errorf("%s carries no version; an empty string reads as a build predating the field", path)
		}
	}

	// The contrast that gives the above its meaning.
	resp, err := http.Get(ts.URL + "/v1/memberships")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /v1/memberships = %d, want 401 — health must be the exception, "+
			"not the rule on this listener", resp.StatusCode)
	}
}

// TestHealthRevealsNothingBeyondThePortBeingOpen.
//
// The endpoints are reachable by anyone who can open the socket, so what they
// return is a disclosure decision. Three booleans, a build string, and how old
// the database reading is: no hostname, no network names, no host counts, no
// database address, nothing an unauthenticated stranger could turn into
// reconnaissance.
//
// The allowlist is deliberately closed rather than a list of things to exclude.
// A field added to wire.HealthResponse without a disclosure decision fails here,
// which is the point — observed_age_seconds was added later and this test caught
// it. It was then admitted on the reasoning that it says only how recently this
// process checked its own database, which is strictly less useful to an attacker
// than the build version already on the list.
func TestHealthRevealsNothingBeyondThePortBeingOpen(t *testing.T) {
	h := setup(t)
	ts := h.servePublicWithHealth(t, freeUDPPort(t))

	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	allowed := map[string]bool{
		"status": true, "database": true, "push": true, "version": true,
		"observed_age_seconds": true,
	}
	for k := range fields {
		if !allowed[k] {
			t.Errorf("/readyz exposes %q to unauthenticated callers", k)
		}
	}

	// Nothing that names this deployment.
	for _, secret := range []string{h.netName, h.netID.String(), h.token} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("/readyz body leaks %q", secret)
		}
	}
}

// TestReadinessFailsWithoutTheDatabaseWhileLivenessPasses is the distinction
// the two endpoints exist to draw.
//
// A process that is up but cannot reach Postgres will fail every request, so it
// must leave the load balancer's rotation — that is readiness, and it is cheap
// and reversible. It must NOT be restarted: restarting cannot fix a database,
// and a liveness probe wired to Postgres turns one database outage into every
// replica being killed simultaneously, destroying the parked watchers and the
// LISTEN connection that would otherwise let the fleet recover the moment the
// database returns.
func TestReadinessFailsWithoutTheDatabaseWhileLivenessPasses(t *testing.T) {
	h := setup(t)
	ts := h.servePublicWithHealth(t, freeUDPPort(t))

	if code, _ := probe(t, ts.URL+"/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz = %d before the database was closed", code)
	}

	h.store.Close()

	// Polled rather than checked once, because the probe result is cached for a
	// short interval — deliberately, so a fleet of monitors cannot turn health
	// checking into database load. The cache expiring is part of what is being
	// asserted: a stale "ok" that never clears would be worse than no endpoint.
	var (
		deadline = time.Now().Add(15 * time.Second)
		ready    int
		body     wire.HealthResponse
	)
	for time.Now().Before(deadline) {
		ready, body = probe(t, ts.URL+"/readyz")
		if ready == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if ready != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d with no database, want 503 — a replica that cannot serve "+
			"must leave the rotation", ready)
	}
	if body.Database {
		t.Error("/readyz reports database: true with the pool closed")
	}
	if body.Status != "degraded" {
		t.Errorf("/readyz status = %q, want \"degraded\"", body.Status)
	}

	live, liveBody := probe(t, ts.URL+"/healthz")
	if live != http.StatusOK {
		t.Errorf("/healthz = %d with no database, want 200 — restarting this process "+
			"cannot fix Postgres, and killing every replica at once makes the outage worse", live)
	}
	// Liveness still tells the truth in the body; only the status code differs.
	if liveBody.Status != "degraded" {
		t.Errorf("/healthz status = %q, want \"degraded\" so the condition is still visible",
			liveBody.Status)
	}
}

// TestLivenessDoesNotWaitOnTheDatabase.
//
// The status code is only half of it. A liveness probe that blocks for the
// database's timeout is failed by any orchestrator with a probe timeout shorter
// than that, which produces the same restart storm the 200 was meant to
// prevent. So /healthz reads the last observation and performs no I/O at all.
func TestLivenessDoesNotWaitOnTheDatabase(t *testing.T) {
	h := setup(t)
	ts := h.servePublicWithHealth(t, freeUDPPort(t))

	h.store.Close()

	start := time.Now()
	for range 20 {
		if code, _ := probe(t, ts.URL+"/healthz"); code != http.StatusOK {
			t.Fatalf("/healthz = %d with no database", code)
		}
	}
	// Twenty round trips against a dead database. Generous enough not to flake
	// on a loaded machine, and orders of magnitude below what even one blocking
	// connection attempt would cost.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("20 liveness probes took %s against a closed pool; /healthz is reaching "+
			"the database rather than reading the cached observation", elapsed)
	}
}

// TestHealthIsAbsentUnlessMounted.
//
// The routes go on a listener because that listener was given them, not because
// they leak in with something else. The overlay listener in orbitd mounts only
// AgentRoutes today, and a health endpoint appearing there by accident is a
// route nobody decided to expose.
func TestHealthIsAbsentUnlessMounted(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t)) // enroll + admin, no health

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d on a listener that never mounted HealthRoutes, want 404",
				path, resp.StatusCode)
		}
	}
}

// TestHealthReportsPushState. Push being down sends every agent back to
// polling, which converges an order of magnitude slower and is invisible in
// every other channel on a listener with no metrics endpoint. It must not fail
// readiness, though: polling is slow, not broken, and pulling a working replica
// out of rotation for it would be a worse outcome than the degradation.
func TestHealthReportsPushState(t *testing.T) {
	h := setup(t)
	ts := h.servePublicWithHealth(t, freeUDPPort(t))

	code, body := probe(t, ts.URL+"/readyz")
	if code != http.StatusOK {
		t.Fatalf("/readyz = %d", code)
	}
	if body.Push {
		t.Error("push reported up on a server constructed with no notifier")
	}
	if body.Status != "ok" {
		t.Errorf("status = %q with push disabled; a deployment that turned push off "+
			"deliberately must not read as faulty forever", body.Status)
	}
}

// TestHealthReportsPushDownRatherThanConfigured. A notifier that exists but is
// not connected is the case worth getting right, and the case the previous
// implementation got wrong: it read the live state out of the metrics
// collector, so a server built without metrics fell back to reporting push as
// up because push was configured. Configured is not connected. An operator
// staring at a revocation that will not land needs /readyz to say which.
func TestHealthReportsPushDownRatherThanConfigured(t *testing.T) {
	h := setup(t)
	notifier := notify.New(h.store.Pool(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := h.servePublicWithNotifier(t, freeUDPPort(t), notifier)

	// Run has not been called. The notifier is wired but deaf.
	code, body := probe(t, ts.URL+"/readyz")
	if code != http.StatusOK {
		t.Fatalf("/readyz = %d", code)
	}
	if body.Push {
		t.Fatal("push reported up on a notifier that has never connected.\n" +
			"Every agent is on its poll interval and the health endpoint says fine.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = notifier.Run(ctx) }()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer readyCancel()
	if err := notifier.Ready(readyCtx); err != nil {
		t.Fatalf("listener never established: %v", err)
	}

	// The snapshot is cached, so poll rather than assuming the next request
	// recomputes it.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, body := probe(t, ts.URL+"/readyz"); body.Push {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("push never reported up on a connected listener")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// And back down when it stops, which is the transition a stuck "up" hides.
	cancel()
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, body := probe(t, ts.URL+"/readyz"); !body.Push {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("push still reported up after the notifier stopped")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
