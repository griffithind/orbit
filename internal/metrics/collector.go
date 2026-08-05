package metrics

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/griffithind/orbit/internal/store"
)

// dbCollector reports fleet state read from the database at scrape time.
//
// Scrape-time rather than a background ticker, for two reasons. A ticker would
// mean the exported value is stale by up to its period and nobody can tell by
// how much; and two replicas each running one would double the query load for
// numbers that are identical. Collect runs one query, bounded by a timeout well
// under any sane scrape interval, and a slow database degrades into a missing
// gauge rather than a hanging scrape.
type dbCollector struct {
	store   *store.Store
	log     *slog.Logger
	timeout time.Duration

	up             *prometheus.Desc
	scrapeFailures prometheus.Counter

	configEpoch      *prometheus.Desc
	blocklistEpoch   *prometheus.Desc
	membershipsTotal *prometheus.Desc
	configApplied    *prometheus.Desc
	blockApplied     *prometheus.Desc
	lagSeconds       *prometheus.Desc
	certsExpiring    *prometheus.Desc
	certMinRemain    *prometheus.Desc
	blocklistSize    *prometheus.Desc
}

// RegisterDB attaches the database-backed collector to m's registry.
func (m *Metrics) RegisterDB(st *store.Store, log *slog.Logger) error {
	if m == nil {
		return nil
	}
	labels := []string{"network"}
	c := &dbCollector{
		store: st, log: log, timeout: 3 * time.Second,

		up: prometheus.NewDesc("orbit_db_scrape_up",
			"1 when the last scrape read fleet state successfully.", nil, nil),
		scrapeFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "orbit_db_scrape_failures_total",
			Help: "Scrapes that could not read fleet state from Postgres.",
		}),

		configEpoch: prometheus.NewDesc("orbit_config_epoch",
			"Current authoritative config epoch.", labels, nil),
		blocklistEpoch: prometheus.NewDesc("orbit_blocklist_epoch",
			"Current authoritative blocklist epoch.", labels, nil),
		membershipsTotal: prometheus.NewDesc("orbit_hosts_total",
			"Memberships that hold or have held a certificate.", labels, nil),
		configApplied: prometheus.NewDesc("orbit_hosts_config_converged",
			"Memberships that have applied the current config epoch.", labels, nil),
		blockApplied: prometheus.NewDesc("orbit_hosts_blocklist_converged",
			"Memberships that have applied the current blocklist epoch.", labels, nil),
		lagSeconds: prometheus.NewDesc("orbit_convergence_lag_seconds",
			"How long the most stale un-converged host has gone without reporting.", labels, nil),
		certsExpiring: prometheus.NewDesc("orbit_certificates_expiring_soon",
			"Active certificates with under 25% of their lifetime remaining.", labels, nil),
		certMinRemain: prometheus.NewDesc("orbit_certificate_min_remaining_seconds",
			"Time until the soonest active certificate expires.", labels, nil),
		blocklistSize: prometheus.NewDesc("orbit_blocklist_entries",
			"Fingerprints currently distributed in host configuration.", labels, nil),
	}
	m.reg.MustRegister(c.scrapeFailures)
	return m.reg.Register(c)
}

func (c *dbCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.configEpoch
	ch <- c.blocklistEpoch
	ch <- c.membershipsTotal
	ch <- c.configApplied
	ch <- c.blockApplied
	ch <- c.lagSeconds
	ch <- c.certsExpiring
	ch <- c.certMinRemain
	ch <- c.blocklistSize
}

func (c *dbCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	var stats []store.NetworkStats
	err := c.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		stats, err = tx.FleetStats(ctx)
		return err
	})
	if err != nil {
		// Report the failure as a metric rather than only a log line: an
		// alert on orbit_db_scrape_up catches a control plane that is serving
		// but has lost its database, which no other signal here would show.
		c.scrapeFailures.Inc()
		c.log.Warn("metrics scrape could not read fleet state", "error", err)
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1)

	for _, s := range stats {
		g := func(d *prometheus.Desc, v float64) {
			ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, s.Name)
		}
		g(c.configEpoch, float64(s.ConfigEpoch))
		g(c.blocklistEpoch, float64(s.BlocklistEpoch))
		g(c.membershipsTotal, float64(s.MembershipsTotal))
		g(c.configApplied, float64(s.ConfigApplied))
		g(c.blockApplied, float64(s.BlockApplied))
		g(c.lagSeconds, s.LagSeconds)
		g(c.certsExpiring, float64(s.CertsExpiringSoon))
		g(c.certMinRemain, s.MinCertRemainingSeconds)
		g(c.blocklistSize, float64(s.BlocklistSize))
	}
}
