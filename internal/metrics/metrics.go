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
	"sync/atomic"
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

	enrollments   *prometheus.CounterVec
	certificates  *prometheus.CounterVec
	pollFallback  prometheus.Counter
	watchers      prometheus.Gauge
	applyReverted prometheus.Counter
	epochNotifies *prometheus.CounterVec
	listenerUp    prometheus.Gauge

	// listenerLive mirrors listenerUp somewhere Go can read it. A
	// prometheus.Gauge is write-only short of rendering the exposition format,
	// and /healthz has to answer this question on the request path, where no
	// scrape is happening. See PushUp.
	listenerLive atomic.Bool
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

func (m *Metrics) EpochNotified(kind string) {
	if m != nil {
		m.epochNotifies.WithLabelValues(kind).Inc()
	}
}

func (m *Metrics) ListenerUp(up bool) {
	if m == nil {
		return
	}
	m.listenerLive.Store(up)
	if up {
		m.listenerUp.Set(1)
		return
	}
	m.listenerUp.Set(0)
}

// PushUp reports the last listener state notify pushed here.
//
// The same observation orbit_epoch_listener_up exports, readable from Go, for
// callers that answer on a request rather than on a scrape — /healthz is the
// one that needs it.
//
// False before LISTEN is ever established, which is the correct reading: until
// it is, every agent is polling.
func (m *Metrics) PushUp() bool {
	if m == nil {
		return false
	}
	return m.listenerLive.Load()
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
