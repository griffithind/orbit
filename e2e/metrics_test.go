package e2e

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/griffithind/orbit/internal/metrics"
)

// TestMetricsReflectFleetState checks the gauges are read from the database at
// scrape time rather than from process memory.
//
// The distinction matters operationally: process-local gauges would disagree
// between replicas and reset on restart, so an alert on convergence would fire
// every deploy. The test proves it by scraping a process that has served no
// requests at all — every number here can only have come from Postgres.
func TestMetricsReflectFleetState(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	h.createAndEnroll(t, ts, "counted-1", "10.42.8.1", false, false, nil)
	h.createAndEnroll(t, ts, "counted-2", "10.42.8.2", false, false, nil)

	mx := metrics.New()
	if err := mx.RegisterDB(h.store, slog.Default()); err != nil {
		t.Fatalf("register collector: %v", err)
	}

	body := scrape(t, mx)

	// Two enrolled hosts, neither of which has reported an applied epoch, so
	// both are legitimately un-converged.
	if got := gauge(t, body, "orbit_hosts_total", h.netName); got != 2 {
		t.Errorf("orbit_hosts_total = %v, want 2", got)
	}
	if got := gauge(t, body, "orbit_hosts_config_converged", h.netName); got != 0 {
		t.Errorf("orbit_hosts_config_converged = %v, want 0", got)
	}

	// A host that has never reported must register as lagging since it was
	// created, not as zero: coalescing last_seen_at to created_at is what
	// stops a never-converged fleet reporting perfect health.
	if got := gauge(t, body, "orbit_convergence_lag_seconds", h.netName); got <= 0 {
		t.Errorf("orbit_convergence_lag_seconds = %v, want > 0 for hosts that "+
			"have never reported", got)
	}

	// Certificates were just issued, so the soonest expiry is a full lifetime
	// away and nothing is near renewal.
	if got := gauge(t, body, "orbit_certificate_min_remaining_seconds", h.netName); got <= 0 {
		t.Errorf("orbit_certificate_min_remaining_seconds = %v, want > 0", got)
	}
	if got := gauge(t, body, "orbit_certificates_expiring_soon", h.netName); got != 0 {
		t.Errorf("orbit_certificates_expiring_soon = %v, want 0 for fresh certificates", got)
	}

	if !strings.Contains(body, "orbit_db_scrape_up 1") {
		t.Error("orbit_db_scrape_up is not 1; the collector could not read fleet state")
	}
}

// TestMetricsCountRevocation confirms a block moves the blocklist gauges, which
// is what an operator watches after cutting a host off.
func TestMetricsCountRevocation(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "to-block", "10.42.8.3", false, false, nil)

	mx := metrics.New()
	if err := mx.RegisterDB(h.store, slog.Default()); err != nil {
		t.Fatalf("register collector: %v", err)
	}

	before := gauge(t, scrape(t, mx), "orbit_blocklist_entries", h.netName)

	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+host.id+"/block", nil, nil); code != http.StatusOK {
		t.Fatalf("block: %d", code)
	}

	body := scrape(t, mx)
	if got := gauge(t, body, "orbit_blocklist_entries", h.netName); got != before+1 {
		t.Errorf("orbit_blocklist_entries = %v, want %v", got, before+1)
	}
	if got := gauge(t, body, "orbit_blocklist_epoch", h.netName); got < 2 {
		t.Errorf("orbit_blocklist_epoch = %v, want it to have advanced", got)
	}
}

// TestMetricsSurviveALostDatabase. A control plane that is serving but cannot
// reach Postgres must say so through the endpoint, because no other signal
// distinguishes it from a healthy one.
func TestMetricsSurviveALostDatabase(t *testing.T) {
	h := setup(t)

	mx := metrics.New()
	if err := mx.RegisterDB(h.store, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("register collector: %v", err)
	}
	h.store.Close()

	body := scrape(t, mx)
	if !strings.Contains(body, "orbit_db_scrape_up 0") {
		t.Error("a scrape with no database did not report orbit_db_scrape_up 0")
	}
	// Partial beats nothing: the process-local counters must still be served.
	if !strings.Contains(body, "orbit_enrollments_total") &&
		!strings.Contains(body, "go_goroutines") {
		t.Error("a failed database read suppressed the entire exposition")
	}
}

func scrape(t *testing.T, mx *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	mx.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape returned %d", rec.Code)
	}
	b, _ := io.ReadAll(rec.Body)
	return string(b)
}

// gauge pulls one labelled sample out of the exposition text. Parsing the real
// output rather than reaching into the registry keeps the test honest about
// what Prometheus would actually see.
func gauge(t *testing.T, body, name, network string) float64 {
	t.Helper()
	prefix := name + `{network="` + network + `"}`
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return v
		}
	}
	t.Fatalf("metric %s not found in exposition", prefix)
	return 0
}
