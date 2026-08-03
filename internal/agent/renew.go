package agent

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	"github.com/slackhq/nebula/cert"
)

// RenewalPolicy decides when a certificate should be renewed.
//
// The default renews at the midpoint of the certificate's lifetime. That is not
// arbitrary: it leaves the entire second half of the lifetime to recover from a
// failure before the certificate expires and the host falls off the mesh. A
// policy that renews at 90% leaves almost no margin, and one that renews
// immediately doubles the issuance load for no benefit.
type RenewalPolicy struct {
	// Fraction of the lifetime at which to renew. 0.5 by default.
	Fraction float64

	// Jitter spreads renewals as a fraction of the lifetime, applied as
	// ±Jitter. A fleet enrolled together would otherwise renew together
	// forever, turning a routine operation into a periodic thundering herd
	// against the CA backend.
	Jitter float64

	// MinRetry bounds how often a failing renewal is retried, so a persistent
	// failure does not become a hot loop against the control plane.
	MinRetry time.Duration
}

func DefaultRenewalPolicy() RenewalPolicy {
	return RenewalPolicy{Fraction: 0.5, Jitter: 0.1, MinRetry: 5 * time.Minute}
}

// RenewAt reports when renewal should first be attempted.
//
// The jitter offset is derived deterministically from seed (in practice the
// host id), not from a random source. A random offset recomputed on each agent
// start would move the renewal time every restart, and a host that restarts
// frequently could either renew far more often than intended or keep pushing
// its deadline past expiry.
func (p RenewalPolicy) RenewAt(notBefore, notAfter time.Time, seed string) time.Time {
	if p.Fraction <= 0 {
		p.Fraction = 0.5
	}

	lifetime := notAfter.Sub(notBefore)
	if lifetime <= 0 {
		// A malformed window; renew immediately rather than computing a
		// nonsensical instant in the past.
		return notBefore
	}

	at := notBefore.Add(time.Duration(float64(lifetime) * p.Fraction))

	if p.Jitter > 0 {
		// Map the seed onto [-1, 1) and scale by the jitter fraction.
		sum := sha256.Sum256([]byte(seed))
		u := binary.BigEndian.Uint64(sum[:8])
		unit := (float64(u)/float64(1<<63) - 1.0) // [-1, 1)
		at = at.Add(time.Duration(float64(lifetime) * p.Jitter * unit))
	}

	// Never schedule outside the certificate's own window: before NotBefore is
	// meaningless, and at or after NotAfter means the host expires without ever
	// having tried.
	if at.Before(notBefore) {
		at = notBefore
	}
	if !at.Before(notAfter) {
		at = notAfter.Add(-lifetime / 10)
	}
	return at
}

// Urgency describes how close a certificate is to being useless.
type Urgency int

const (
	// NotDue means the renewal time has not arrived.
	NotDue Urgency = iota
	// Due means renewal should be attempted now.
	Due
	// Urgent means more than three quarters of the lifetime has elapsed. A
	// renewal that is still failing here deserves an operator's attention, not
	// just a log line.
	Urgent
	// Expired means the certificate is no longer valid. The host is off the
	// mesh and, because the agent API rides the overlay, cannot renew through
	// it; recovery is the public endpoint.
	Expired
)

func (u Urgency) String() string {
	switch u {
	case Due:
		return "due"
	case Urgent:
		return "urgent"
	case Expired:
		return "expired"
	default:
		return "not-due"
	}
}

// Assess reports how urgently a certificate needs renewing.
func (p RenewalPolicy) Assess(now, notBefore, notAfter time.Time, seed string) Urgency {
	switch {
	case !now.Before(notAfter):
		return Expired
	case !now.Before(notBefore.Add(time.Duration(float64(notAfter.Sub(notBefore)) * 0.75))):
		return Urgent
	case !now.Before(p.RenewAt(notBefore, notAfter, seed)):
		return Due
	default:
		return NotDue
	}
}

// ApplyMode is how a new generation must be delivered to a running nebula.
type ApplyMode int

const (
	// ModeReload signals a running process with SIGHUP. Tunnels survive.
	ModeReload ApplyMode = iota
	// ModeRestart stops and starts the process, dropping every tunnel.
	ModeRestart
)

func (m ApplyMode) String() string {
	if m == ModeRestart {
		return "restart"
	}
	return "reload"
}

// ModeFor decides whether a new certificate can be hot-loaded.
//
// Nebula refuses a reload whose certificate networks or curve differ from the
// running ones (pki.go reloadCerts, "Networks in new cert was different from
// old"). Renewal with a stable address is therefore zero-downtime and is the
// common path; a re-addressed host needs a process restart.
//
// Detecting this here matters because the failure is otherwise silent and
// confusing: nebula logs a reload error and keeps running on the old, soon to
// expire, certificate. The host then drops off the mesh at expiry for reasons
// that look nothing like "its address changed".
func ModeFor(currentPEM, newPEM string) (ApplyMode, error) {
	if currentPEM == "" {
		// First enrollment; nothing is running yet to reload.
		return ModeReload, nil
	}

	cur, _, err := cert.UnmarshalCertificateFromPEM([]byte(currentPEM))
	if err != nil {
		return ModeRestart, fmt.Errorf("parse current certificate: %w", err)
	}
	next, _, err := cert.UnmarshalCertificateFromPEM([]byte(newPEM))
	if err != nil {
		return ModeRestart, fmt.Errorf("parse new certificate: %w", err)
	}

	if cur.Curve() != next.Curve() {
		return ModeRestart, nil
	}
	if !slices.Equal(cur.Networks(), next.Networks()) {
		return ModeRestart, nil
	}
	return ModeReload, nil
}

// CertificateWindow extracts the validity window from a PEM certificate, so the
// agent can schedule renewal from what it actually holds rather than from what
// the control plane last told it.
func CertificateWindow(pemBytes string) (notBefore, notAfter time.Time, err error) {
	c, _, err := cert.UnmarshalCertificateFromPEM([]byte(pemBytes))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return c.NotBefore(), c.NotAfter(), nil
}
