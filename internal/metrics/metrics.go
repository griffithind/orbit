// Package metrics exposes Orbit's operational state in Prometheus format.
//
// Two kinds of metric live here, and the difference matters more than it
// usually does:
//
//   - Event counters, incremented in the code path that does the thing. These
//     are process-local and reset when orbitd restarts, which is correct: they
//     answer "what has this process done".
//
//   - State gauges, read from the database when Prometheus scrapes (see
//     dbCollector). These are not process-local, do not reset, and are the same
//     from either replica. Keeping them out of process memory means two
//     replicas cannot disagree about how many hosts are converged, which they
//     inevitably would if each maintained its own copy.
//
// prometheus/client_golang is already in the module graph via nebula, so this
// adds no new dependency to the build.
package metrics

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the event counters. Construct with New and pass it down; a nil
// *Metrics is safe to call on, so tests and code paths without metrics do not
// need to branch.
type Metrics struct {
	reg *prometheus.Registry

	enrollments     *prometheus.CounterVec
	certificates    *prometheus.CounterVec
	pollFallback    prometheus.Counter
	watchers        prometheus.Gauge
	applyReverted   prometheus.Counter
	renewalsFailed  prometheus.Counter
	maintenanceLast prometheus.Gauge
	epochNotifies   *prometheus.CounterVec
	listenerUp      prometheus.Gauge
}

// New builds a registry and the event counters.
//
// The registry is private rather than prometheus.DefaultRegisterer because
// nebula registers its own metrics into the default one, and orbitd runs nebula
// in-process. Sharing would put a lighthouse's tunnel counters on Orbit's
// /metrics under names nobody expects.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,

		enrollments: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orbit_enrollments_total",
			Help: "Enrollment attempts by outcome.",
		}, []string{"result"}),

		certificates: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orbit_certificates_issued_total",
			Help: "Certificates signed, by what prompted the issuance.",
		}, []string{"reason"}),

		// A rise here means agents lost long-poll and fell back to polling,
		// which converges an order of magnitude slower. Nothing else reports
		// that the network path changed underneath the fleet.
		pollFallback: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "orbit_agent_poll_fallback_total",
			Help: "Watch requests refused, sending an agent back to polling.",
		}),

		watchers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "orbit_watch_connections",
			Help: "Agents currently holding a long-poll connection.",
		}),

		applyReverted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "orbit_config_reverts_total",
			Help: "Reverts reported by agents after a pushed config failed to verify.",
		}),

		// Successes are counted by certificates_issued_total{reason="renew"}.
		// Without the failures beside them, a fleet that has stopped renewing
		// looks exactly like a fleet that has stopped needing to, and the first
		// signal is certificates_expiring_soon — weeks later, by design.
		renewalsFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "orbit_renewals_failed_total",
			Help: "Renewal requests that failed, by any cause.",
		}),

		// A sweep that has stopped is invisible: blocklist pruning and
		// expired-CA detection stop with it and neither announces itself. The
		// unix time of the last success rather than a counter, so an alert is
		// "time() - this > an interval" and needs no rate window.
		maintenanceLast: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "orbit_maintenance_last_success_seconds",
			Help: "Unix time of the last successful maintenance sweep. Zero until one completes.",
		}),

		epochNotifies: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orbit_epoch_notifications_total",
			Help: "Epoch change notifications delivered to this process.",
		}, []string{"kind"}),

		// Zero means push is down and every agent is polling. This is the one
		// gauge worth alerting on directly.
		listenerUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "orbit_epoch_listener_up",
			Help: "1 when the Postgres LISTEN connection is established.",
		}),
	}

	reg.MustRegister(
		m.enrollments, m.certificates, m.pollFallback, m.watchers,
		m.applyReverted, m.epochNotifies, m.listenerUp,
		m.renewalsFailed, m.maintenanceLast,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Registry exposes the registry so a caller can register the database
// collector, or its own, alongside these.
func (m *Metrics) Registry() *prometheus.Registry {
	if m == nil {
		return nil
	}
	return m.reg
}

func (m *Metrics) EnrollAttempt(result string) {
	if m != nil {
		m.enrollments.WithLabelValues(result).Inc()
	}
}

func (m *Metrics) CertificateIssued(reason string) {
	if m != nil {
		m.certificates.WithLabelValues(reason).Inc()
	}
}

func (m *Metrics) PollFallback() {
	if m != nil {
		m.pollFallback.Inc()
	}
}

func (m *Metrics) WatcherOpened() {
	if m != nil {
		m.watchers.Inc()
	}
}

func (m *Metrics) WatcherClosed() {
	if m != nil {
		m.watchers.Dec()
	}
}

func (m *Metrics) ConfigReverted() {
	if m != nil {
		m.applyReverted.Inc()
	}
}

// RenewalFailed counts a renewal that did not produce a certificate.
func (m *Metrics) RenewalFailed() {
	if m != nil {
		m.renewalsFailed.Inc()
	}
}

// MaintenanceSucceeded stamps the time of a completed sweep.
func (m *Metrics) MaintenanceSucceeded(at time.Time) {
	if m != nil {
		m.maintenanceLast.Set(float64(at.Unix()))
	}
}

func (m *Metrics) EpochNotified(kind string) {
	if m != nil {
		m.epochNotifies.WithLabelValues(kind).Inc()
	}
}

// ListenerUp records a LISTEN state transition.
//
// It sets the gauge and keeps nothing. A prometheus.Gauge is write-only short
// of rendering the exposition format, so it is tempting to mirror the state in
// an atomic.Bool for callers that answer on the request path — /healthz is the
// one that wants it. Resist that: notify.Notifier.Up() reports its own state,
// and a caller needing the boolean should ask the thing that has it rather than
// a metrics collector that happened to be listening.
func (m *Metrics) ListenerUp(up bool) {
	if m == nil {
		return
	}
	if up {
		m.listenerUp.Set(1)
		return
	}
	m.listenerUp.Set(0)
}

// Handler serves the exposition endpoint.
//
// Bind it to localhost or to the overlay, never to the public listener: the
// output enumerates network names and host counts, which is inventory an
// unauthenticated stranger has no business reading. cmd/orbitd defaults the
// address to 127.0.0.1 for exactly this reason.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{
		// One scrape failing must not take down the endpoint, and a partial
		// scrape is more useful than none: if the database query times out, the
		// event counters still report.
		ErrorHandling: promhttp.ContinueOnError,
	})
}

// ServeMetrics runs the exposition listener until ctx is cancelled.
func (m *Metrics) ServeMetrics(ctx context.Context, addr string, log *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m.Handler())

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("metrics listening", "addr", addr, "path", "/metrics")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
