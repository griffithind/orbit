package agent

import (
	"fmt"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/renewal"
)

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

// The renewal policy lives in internal/renewal, which imports only time and a
// hash. These aliases keep the agent's call sites reading as they did — the
// policy is agent behaviour, and the package split exists so internal/api can
// name DefaultRenewalPolicy without linking the data plane, not to make the
// agent talk about a foreign type.
type (
	RenewalPolicy = renewal.Policy
	Urgency       = renewal.Urgency
)

const (
	NotDue  = renewal.NotDue
	Due     = renewal.Due
	Urgent  = renewal.Urgent
	Expired = renewal.Expired
)

// DefaultRenewalPolicy is renewal.DefaultPolicy.
func DefaultRenewalPolicy() RenewalPolicy { return renewal.DefaultPolicy() }
