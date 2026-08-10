package generation

import (
	"fmt"
	"slices"

	"github.com/slackhq/nebula/cert"
)

// How a new generation reaches a running nebula.
//
// Kept beside the applier that acts on it: nothing else in the agent ever asked
// which mode a certificate needs, only the code that has to deliver it.

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
