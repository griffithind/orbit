package store

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Lifecycle states. These mirror the CHECK constraints in
// migrations/0001_schema.sql; adding a value requires changing both.
const (
	CAPending  = "pending"
	CAActive   = "active"
	CARetiring = "retiring"
	CARetired  = "retired"

	HostCreated   = "created"
	HostEnrolled  = "enrolled"
	HostActive    = "active"
	HostSuspended = "suspended"
	HostDeleted   = "deleted"

	CertPending    = "pending"
	CertActive     = "active"
	CertSuperseded = "superseded"
	CertRevoked    = "revoked"

	MethodCode        = "code"
	MethodCloudIID    = "cloud_iid"
	MethodAttestation = "attestation"
)

type Network struct {
	ID             uuid.UUID
	Name           string
	CIDRs          []netip.Prefix
	CertVer        int16
	Curve          string
	CertTTL        time.Duration
	ConfigEpoch    int64
	BlocklistEpoch int64
	CreatedAt      time.Time
}

type CA struct {
	ID          uuid.UUID
	NetworkID   uuid.UUID
	Name        string
	Fingerprint string
	CertPEM     string
	// SignerRef is an opaque locator resolved by internal/ca. It never holds
	// key material: awskms://…, pkcs11://…, file://…
	SignerRef string
	Curve     string
	NotBefore time.Time
	NotAfter  time.Time
	State     string
	CreatedAt time.Time
}

type Role struct {
	ID        uuid.UUID
	NetworkID uuid.UUID
	Name      string
	Groups    []string
	// FirewallRules is stored as jsonb and rendered into the managed config
	// fragment. Nebula appends rules across config files rather than replacing
	// them, so these coexist with whatever the operator maintains.
	FirewallRules []byte
	CreatedAt     time.Time
}

type Host struct {
	ID           uuid.UUID
	NetworkID    uuid.UUID
	Name         string
	RoleID       *uuid.UUID
	Addrs        []netip.Addr
	Tags         []string
	IsLighthouse bool
	IsRelay      bool
	StaticAddrs  []string
	State        string

	// AppliedConfigEpoch and AppliedBlocklistEpoch are reported by the agent
	// after a successful apply, not after a fetch. Convergence is measured from
	// these; measuring from fetch would hide a config that downloaded but never
	// took effect.
	AppliedConfigEpoch    int64
	AppliedBlocklistEpoch int64

	LastSeenAt    *time.Time
	NebulaVersion string
	AgentVersion  string
	CreatedAt     time.Time
}

type Certificate struct {
	ID          uuid.UUID
	HostID      uuid.UUID
	CAID        uuid.UUID
	Fingerprint string
	PEM         string
	CertVer     int16
	NotBefore   time.Time
	NotAfter    time.Time
	State       string
	IssuedAt    time.Time
}

// RenewAt reports when the agent should attempt renewal: the midpoint of the
// certificate's lifetime. Renewing at 50% leaves the remaining half to recover
// from failure before the certificate expires. See docs/enrollment.md 6.1.
func (c Certificate) RenewAt() time.Time {
	return c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore) / 2)
}

type EnrollmentCredential struct {
	ID        uuid.UUID
	NetworkID uuid.UUID
	HostID    *uuid.UUID
	Method    string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedBy string
	CreatedAt time.Time
}

type BlocklistEntry struct {
	ID          uuid.UUID
	NetworkID   uuid.UUID
	Fingerprint string
	Reason      string
	Epoch       int64
	// NotAfter is the revoked certificate's expiry. Once passed the entry can
	// be dropped from distributed config: nebula rejects an expired certificate
	// before consulting the blocklist. See docs/revocation.md 4.1.
	NotAfter  time.Time
	CreatedAt time.Time
}

type AuditEntry struct {
	ActorType  string // user | token | agent | system
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Meta       []byte
	SourceIP   *netip.Addr
}

// TokenIdentity is what an API token resolves to.
type TokenIdentity struct {
	TokenID uuid.UUID
	Scopes  []string
}

// HasScope reports whether the token carries scope. A token holding "*" passes
// every check; reserve it for bootstrap credentials.
func (t TokenIdentity) HasScope(scope string) bool {
	for _, s := range t.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// AgentIdentity is what a source overlay address resolves to on the agent API.
type AgentIdentity struct {
	HostID uuid.UUID
	State  string
}

// RedeemedCredential is the result of atomically consuming an enrollment
// credential. HostID is nil for methods that create the host on redemption.
type RedeemedCredential struct {
	CredentialID uuid.UUID
	NetworkID    uuid.UUID
	HostID       *uuid.UUID
	Method       string
}

// Convergence summarizes how much of a network has applied the current epochs.
// It gates CA rotation (docs/design.md 6) and is the metric behind the
// revocation SLO (docs/revocation.md 5).
type Convergence struct {
	ConfigEpoch    int64
	BlocklistEpoch int64
	HostsTotal     int
	ConfigApplied  int
	BlockApplied   int
	Lagging        []LaggingHost
}

type LaggingHost struct {
	HostID                uuid.UUID
	Name                  string
	AppliedConfigEpoch    int64
	AppliedBlocklistEpoch int64
	LastSeenAt            *time.Time
}
