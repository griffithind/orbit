// Package sched runs the control plane's periodic maintenance.
//
// Everything here was previously a store method with no caller: the pruning
// docs/revocation.md describes, and the renewal sweep docs/design.md relies on
// for observability. Written, tested, and never executed — so the blocklist
// grew without bound, spent enrollment credentials accumulated, and nothing
// noticed a host that had quietly stopped renewing.
//
// Jobs are idempotent and safe to run concurrently across replicas. None of
// them coordinate: two control planes pruning the same network race to delete
// the same already-expired rows, which is harmless. Adding leader election here
// would buy nothing and add a failure mode.
package sched

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/griffithind/orbit/internal/store"
)

// Config tunes the maintenance loop.
type Config struct {
	// Interval between sweeps. Maintenance is not latency-sensitive: nothing
	// here affects correctness, only unbounded growth and visibility.
	Interval time.Duration

	// BlocklistGrace keeps revoked fingerprints a while past their
	// certificate's expiry.
	//
	// Not strictly needed — nebula rejects an expired certificate before it
	// consults the blocklist — but clock skew between the control plane and a
	// host means "expired" is fuzzy at the boundary, and a fingerprint costs
	// bytes where a gap costs trust.
	BlocklistGrace time.Duration

	// RenewalOverdueAfter is how far past the renewal midpoint a certificate
	// must be before the sweep reports it.
	RenewalOverdueAfter time.Duration

	// ControlPlaneStale is how long a replica may go without heartbeating
	// before its registration is deleted.
	//
	// Longer than the staleness window agents are filtered on, deliberately: a
	// replica should stop being handed out well before its row is removed, so a
	// brief outage costs it traffic rather than its registration.
	ControlPlaneStale time.Duration
}

func DefaultConfig() Config {
	return Config{
		Interval:            15 * time.Minute,
		BlocklistGrace:      24 * time.Hour,
		ControlPlaneStale:   30 * time.Minute,
		RenewalOverdueAfter: 0,
	}
}

// Stats is one sweep's result, returned so callers (and tests) can assert on
// what actually happened rather than reading logs.
type Stats struct {
	Networks            int
	BlocklistPruned     int64
	CredentialsPruned   int64
	CertificatesOverdue int
	ReplicasPruned      int64
	CAsRetired          int

	// ExpiredActiveCAs is how many networks are nominally signing with a CA
	// that has outlived itself. Reported, never acted on; see Sweep.
	ExpiredActiveCAs int

	// SessionsPruned is expired browser sessions removed. Hygiene only — an
	// expired session is already refused at resolve time, so this reclaims rows
	// rather than closing a hole.
	SessionsPruned int64
}

type Runner struct {
	store *store.Store
	cfg   Config
	log   *slog.Logger

	// onSuccess is stamped after a sweep that completed. A hook rather than an
	// import of internal/metrics: this package has never depended on it, and a
	// scheduler that cannot run without a metrics registry is harder to test
	// than one that reports through a function.
	onSuccess func(time.Time)

	now func() time.Time
}

func New(st *store.Store, cfg Config, log *slog.Logger) *Runner {
	d := DefaultConfig()
	if cfg.Interval <= 0 {
		cfg.Interval = d.Interval
	}
	if cfg.BlocklistGrace <= 0 {
		cfg.BlocklistGrace = d.BlocklistGrace
	}
	if cfg.ControlPlaneStale <= 0 {
		cfg.ControlPlaneStale = d.ControlPlaneStale
	}
	return &Runner{store: st, cfg: cfg, log: log}
}

func (r *Runner) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Run sweeps on an interval until ctx ends.
//
// A failed sweep is logged and retried next interval, never fatal. Maintenance
// falling behind is an operational annoyance; taking the control plane down
// over it would be an outage.
func (r *Runner) Run(ctx context.Context) error {
	// Sweep once at startup. A control plane that has been down for a week
	// should not wait another interval before catching up.
	if _, err := r.Sweep(ctx); err != nil && ctx.Err() == nil {
		r.log.Error("maintenance sweep failed", "error", err)
	} else if err == nil {
		r.succeeded()
	}

	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := r.Sweep(ctx); err != nil && ctx.Err() == nil {
				r.log.Error("maintenance sweep failed", "error", err)
			} else if err == nil {
				r.succeeded()
			}
		}
	}
}

// OnSuccess registers what to call after a sweep that completed.
func (r *Runner) OnSuccess(fn func(time.Time)) { r.onSuccess = fn }

func (r *Runner) succeeded() {
	if r.onSuccess != nil {
		r.onSuccess(r.now())
	}
}

// Sweep performs one pass over every network.
func (r *Runner) Sweep(ctx context.Context) (Stats, error) {
	var stats Stats

	networks, err := r.store.ListNetworkIDs(ctx)
	if err != nil {
		return stats, err
	}
	stats.Networks = len(networks)

	now := r.clock()
	for _, networkID := range networks {
		// One transaction per network, so a failure on one does not abandon the
		// rest.
		err := r.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			// Drop blocklist entries whose certificates expired long enough ago
			// that no peer could still be presenting them. Without this the
			// blocklist grows forever and is shipped, in full, to every host in
			// every configuration.
			n, err := tx.PruneBlocklist(ctx, networkID, now.Add(-r.cfg.BlocklistGrace))
			if err != nil {
				return err
			}
			stats.BlocklistPruned += n

			// Replicas that stopped heartbeating. Deleting the row is the only
			// deregistration path, so a replica that was killed, crashed, or
			// lost its database connection stops being advertised without
			// anyone having to clean up after it.
			r2, err := tx.PruneControlPlanes(ctx, networkID, now.Add(-r.cfg.ControlPlaneStale))
			if err != nil {
				return err
			}
			stats.ReplicasPruned += r2

			// Retire pending and retiring CAs that have outlived their own
			// validity.
			//
			// Safe without counting certificates: nebula enforces
			// leaf.NotAfter <= ca.NotAfter, so once a CA has expired nothing it
			// ever signed can still verify. Leaving it in the trust bundle costs
			// bytes in every host's configuration and can never accept anything.
			//
			// This is the only automatic CA state change, and it deliberately
			// cannot touch the active CA — see store.ExpiredInactiveCAs.
			// Retiring the signer is a rotation step, and rotation belongs to an
			// operator.
			expired, err := tx.ExpiredInactiveCAs(ctx, networkID, now)
			if err != nil {
				return err
			}
			for _, c := range expired {
				if err := tx.ForceRetireCA(ctx, c.ID, networkID); err != nil {
					return err
				}
				stats.CAsRetired++
				r.log.Info("retired an expired certificate authority",
					"network", networkID, "ca", c.Name, "notAfter", c.NotAfter)
			}

			// An active CA past its own NotAfter is left exactly where it is,
			// and shouted about instead.
			//
			// Nothing is salvageable either way: ca.ValidityFor refuses to issue
			// against an expired CA, so enrollment and renewal are already
			// failing. What retiring it would add is a second, quieter failure —
			// the network reports "no active CA" instead of naming the one that
			// expired, and the promotion path back is gone, because ActivateCA
			// accepts only pending and retiring CAs. This is the one state the
			// sweep can see before every host's certificate runs out behind it,
			// so it has to be legible rather than tidied away.
			active, err := tx.GetActiveCA(ctx, networkID)
			switch {
			case errors.Is(err, store.ErrNoActived):
				// Not this sweep's to diagnose: a network with no signer at all
				// is already reported on every enrollment attempt, and a network
				// that has never had one is a normal half-finished bootstrap.
			case err != nil:
				return err
			case !active.NotAfter.After(now):
				stats.ExpiredActiveCAs++
				r.log.Error("active certificate authority has expired; enrollment and renewal are failing until a replacement is activated",
					"network", networkID, "ca", active.Name, "caID", active.ID,
					"notAfter", active.NotAfter,
					"expiredFor", now.Sub(active.NotAfter).Round(time.Minute))
			}

			// Certificates past their renewal point that the agent has not
			// replaced. The control plane cannot renew on a host's behalf (the
			// host holds the private key), so this is purely visibility — but
			// it is the only signal that a fleet has quietly stopped rotating.
			overdue, err := tx.CertificatesDueForRenewal(ctx, networkID,
				now.Add(-r.cfg.RenewalOverdueAfter), 500)
			if err != nil {
				return err
			}
			stats.CertificatesOverdue += len(overdue)

			for _, c := range overdue {
				remaining := c.NotAfter.Sub(now)
				level := slog.LevelInfo
				if remaining < c.NotAfter.Sub(c.NotBefore)/4 {
					// Under a quarter of the lifetime left. Renewal has been
					// failing long enough to be worth an operator's attention.
					level = slog.LevelWarn
				}
				r.log.Log(ctx, level, "certificate is overdue for renewal",
					"network", networkID, "host", c.MembershipID,
					"notAfter", c.NotAfter, "remaining", remaining.Round(time.Minute))
			}
			return nil
		})
		if err != nil {
			r.log.Error("maintenance failed for network", "network", networkID, "error", err)
		}
	}

	// Expired, unredeemed enrollment credentials. Redeemed ones are retained:
	// they are evidence. Not per network, so once for the deployment.
	if err := r.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		n, err := tx.PruneExpiredCredentialsAll(ctx, now)
		if err != nil {
			return err
		}
		stats.CredentialsPruned += n
		return nil
	}); err != nil {
		r.log.Error("credential pruning failed", "error", err)
	}

	// Expired browser sessions. Deployment-wide for the same reason, and in its
	// own transaction so a failure here cannot roll back the credential prune —
	// they are unrelated hygiene and neither is worth losing to the other.
	//
	// Nothing depends on this running: ResolveSession re-checks expiry on every
	// request, so an unpruned row is refused exactly as a pruned one would be.
	// The 12h ceiling on a session guarantees every row eventually qualifies.
	if err := r.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		n, err := tx.PruneUISessions(ctx, now)
		if err != nil {
			return err
		}
		stats.SessionsPruned += n
		return nil
	}); err != nil {
		r.log.Error("session pruning failed", "error", err)
	}

	if stats.BlocklistPruned > 0 || stats.CredentialsPruned > 0 ||
		stats.SessionsPruned > 0 ||
		stats.CertificatesOverdue > 0 || stats.ReplicasPruned > 0 ||
		stats.CAsRetired > 0 || stats.ExpiredActiveCAs > 0 {
		r.log.Info("maintenance sweep complete",
			"networks", stats.Networks,
			"blocklistPruned", stats.BlocklistPruned,
			"credentialsPruned", stats.CredentialsPruned,
			"sessionsPruned", stats.SessionsPruned,
			"certificatesOverdue", stats.CertificatesOverdue,
			"replicasPruned", stats.ReplicasPruned,
			"casRetired", stats.CAsRetired,
			"expiredActiveCAs", stats.ExpiredActiveCAs)
	} else {
		r.log.Debug("maintenance sweep complete, nothing to do", "networks", stats.Networks)
	}
	return stats, nil
}
