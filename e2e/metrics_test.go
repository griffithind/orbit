package e2e

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

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

// TestTheFourMetricsADR0008CommittedToExist.
//
// Each closes a failure that previously had no metric at all, which is a
// specific thing rather than a general wish for more telemetry:
//
//   - a host converged on paper with nebula not running was counted as healthy
//     by every gauge, because the report said so and nothing recorded it
//   - an expired active signer stops enrolment and renewal for the whole
//     network and had only a log line
//   - a maintenance sweep that has stopped is invisible, and blocklist pruning
//     and expired-CA detection stop with it
//   - renewal failures were logged, so a fleet that had stopped renewing looked
//     like a fleet that had stopped needing to until certificates_expiring_soon
//     tripped weeks later
//
// Presence, and that the DB-derived pair carries the network label a per-network
// alert needs. Behaviour is asserted where it is produced.
func TestTheFourMetricsADR0008CommittedToExist(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	h.createAndEnroll(t, ts, "metric-host", "10.42.9.1", false, false, nil)

	mx := metrics.New()
	if err := mx.RegisterDB(h.store, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("register collector: %v", err)
	}
	// Move both process-level metrics off their zero value so presence is not
	// confused with a metric that exists and has never been touched.
	mx.RenewalFailed()
	mx.MaintenanceSucceeded(time.Now())

	body := scrape(t, mx)

	for _, name := range []string{
		"orbit_hosts_data_plane_down",
		"orbit_ca_min_remaining_seconds",
		"orbit_maintenance_last_success_seconds",
		"orbit_renewals_failed_total",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("%s is not in the scrape; ADR-0008 commits to it", name)
		}
	}

	// The per-network pair must carry the label, or an alert cannot say which
	// network is broken — which is the whole point of alerting on them.
	if got := gauge(t, body, "orbit_hosts_data_plane_down", h.netName); got != 0 {
		t.Errorf("orbit_hosts_data_plane_down = %v, want 0 for a healthy fleet", got)
	}
	if got := gauge(t, body, "orbit_ca_min_remaining_seconds", h.netName); got <= 0 {
		t.Errorf("orbit_ca_min_remaining_seconds = %v, want the active CA's remaining life", got)
	}
}

// TestEveryMetricTheDocsAlertOnExists.
//
// docs/deployment.md alerted on orbit_certificates_issued_total{reason="recover"}
// for as long as that table existed. No code path has ever emitted that label,
// so the rule could not fire — an operator following the runbook had a
// monitoring gap that looked like coverage. It was found by reading, which is
// not a strategy.
//
// Checked against the DECLARATIONS in internal/metrics, not against a scrape.
// A scrape is not the authoritative list: a CounterVec emits nothing until a
// label combination is observed, so orbit_certificates_issued_total and two
// others are registered and absent from a fresh scrape. Reading the declaration
// site avoids a second hand-maintained list, which would drift exactly the way
// the docs did.
func TestEveryMetricTheDocsAlertOnExists(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	h.createAndEnroll(t, ts, "doc-metrics", "10.42.9.9", false, false, nil)

	// Every name the metrics package declares, from both forms it uses:
	// prometheus.*Opts{Name: "..."} for process counters and gauges, and
	// prometheus.NewDesc("...") for the collector that reads Postgres.
	declared := map[string]bool{}
	decl := regexp.MustCompile(`(?:Name:\s*|NewDesc\()"(orbit_[a-z_]+)"`)
	for _, f := range []string{"../internal/metrics/metrics.go", "../internal/metrics/collector.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, m := range decl.FindAllStringSubmatch(string(src), -1) {
			declared[m[1]] = true
		}
	}
	if len(declared) < 15 {
		t.Fatalf("found only %d declared metrics; this test is not reading the package", len(declared))
	}

	// Not metrics, and named in these files for other reasons.
	notMetrics := map[string]bool{
		"orbit_app":   true, // the unprivileged database role
		"orbit_epoch": true, // the Postgres NOTIFY channel, store.go BumpEpoch
	}

	name := regexp.MustCompile(`orbit_[a-z_]+`)
	checked := 0
	for _, doc := range []string{"../docs/deployment.md", "../docs/revocation.md", "../README.md"} {
		text, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		seen := map[string]bool{}
		for _, m := range name.FindAllString(string(text), -1) {
			if seen[m] || notMetrics[m] {
				continue
			}
			seen[m] = true
			checked++
			if !declared[m] {
				t.Errorf("%s names %s, which internal/metrics does not declare. "+
					"An alert on it can never fire.", doc, m)
			}
		}
	}
	if checked < 15 {
		t.Fatalf("only %d metric names found across the docs; this test has stopped reading them", checked)
	}

	// And the LABEL VALUES, which is where the original defect actually lived.
	//
	// orbit_certificates_issued_total is declared and always was; the alert named
	// reason="recover", and nothing has ever passed "recover" to
	// Metrics.CertificateIssued. Checking names alone would have called that
	// table healthy, so this reads the strings the code actually emits.
	emitted := map[string]bool{}
	call := regexp.MustCompile(`(?:CertificateIssued|EnrollAttempt|EpochNotified)\("([a-z_]+)"\)`)
	for _, dir := range []string{"../internal", "../cmd"} {
		_ = filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, m := range call.FindAllStringSubmatch(string(src), -1) {
				emitted[m[1]] = true
			}
			return nil
		})
	}
	if len(emitted) < 4 {
		t.Fatalf("found only %d emitted label values; this test is not reading the call sites", len(emitted))
	}

	label := regexp.MustCompile(`\{(?:reason|result|kind)="([a-z_]+)"\}`)
	for _, doc := range []string{"../docs/deployment.md", "../docs/revocation.md", "../README.md"} {
		text, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range label.FindAllStringSubmatch(string(text), -1) {
			if !emitted[m[1]] {
				t.Errorf("%s alerts on the label value %q, which no call site passes. "+
					"The metric exists; the series does not.", doc, m[1])
			}
		}
	}
}
