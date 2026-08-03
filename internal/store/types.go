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

	// MethodCode is the only enrollment method. Cloud instance identity and TPM
	// attestation were sketched into the schema before either was built, which
	// was worse than leaving them out: a CHECK constraint listing a method is a
	// claim the method works. Adding one back is an ALTER and a handler, the
	// same work it always was.
	MethodCode = "code"

	// Config layouts. These mirror the CHECK constraints in
	// migrations/0008_instance_resources.sql.
	//
	// ConfigModeAuthoritative renders one complete nebula.yml that nebula is
	// pointed at directly. ConfigModeFragment renders config.d/50-orbit.yml into
	// a directory nebula merges, which is the escape hatch for a host that
	// genuinely carries operator-authored nebula configuration.
	//
	// The difference is not cosmetic and is why the mode is stored rather than
	// inferred: nebula merges a config DIRECTORY with mergo.WithAppendSlice, so
	// firewall rules across files CONCATENATE. In fragment mode Orbit can
	// neither see nor remove a rule an operator wrote, so any policy it reports
	// is a lower bound. In authoritative mode the rendered file is the whole
	// policy. A caller has to be able to tell which of those it is being handed.
	ConfigModeAuthoritative = "authoritative"
	ConfigModeFragment      = "fragment"
)

type Network struct {
	ID uuid.UUID

	// Slug is the immutable, globally unique, machine-safe identifier. It is a
	// directory name on every managed host in the network
	// (/var/lib/orbit/<slug>/) and the stem tun.dev is derived from, which is
	// why the database refuses to let it change.
	//
	// A network is addressed by ID or by Slug and by nothing else: both are
	// immutable, so automation holding either survives a rename.
	Slug string

	// Name is the display label. Mutable, unique, and deliberately NOT an
	// addressing key — resolving by a mutable string is how a rename silently
	// retargets a script.
	Name string

	CIDRs   []netip.Prefix
	CertVer int16
	Curve   string
	CertTTL time.Duration

	// ListenPort is the nebula UDP port hosts of this network use. nil means
	// the control plane's configured default, which is what keeps a deployment
	// that has never thought about ports working exactly as before.
	//
	// Per network rather than per host because the collision this can actually
	// prevent is between two networks sharing a machine; see the migration.
	ListenPort *int

	// ConfigMode is the layout new hosts of this network inherit.
	ConfigMode string

	// Overrides are nebula settings Orbit does not model, merged into the
	// rendered configuration beneath any per-host overrides. Stored as jsonb.
	Overrides []byte

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

	// ListenPort, TunDev, ConfigMode, and Overrides are this instance's
	// resources. A zero value inherits the network's, and the network's zero
	// value inherits the control plane's default — one rule at three levels, so
	// a deployment that sets none behaves exactly as it did before they existed.
	//
	// They are per (host, network) because orbit.host already is: a machine on
	// two networks holds two rows, and two nebula processes on one kernel cannot
	// share a UDP port or a tun device.
	ListenPort *int
	TunDev     string
	ConfigMode string
	Overrides  []byte

	// RestartRequiredEpoch names a generation this host must RESTART for rather
	// than reload, and 0 means none ever has been.
	//
	// Nebula refuses a certificate reload whose networks changed (pki.go
	// reloadCert), so after an address change the host installs the new
	// certificate, nebula declines it, and the old one keeps running until the
	// process restarts. Waiting does not help; that is what makes this different
	// from every other thing an agent is told to catch up on.
	RestartRequiredEpoch int64

	// AddrChangedAt is when this host's address set last changed, or nil if it
	// never has. Compared against the active certificate's issued_at to pull
	// renewal forward, exactly as role.groups_changed_at is — the addresses are
	// inside the signed certificate, and a host whose address moved is holding
	// one that no longer authorises the packets it is sending.
	AddrChangedAt *time.Time

	LastSeenAt    *time.Time
	NebulaVersion string
	AgentVersion  string
	CreatedAt     time.Time

	// RoleName is the assigned role's name, resolved by the same query that
	// reads the host. Empty when the host carries no role.
	//
	// Denormalized into the read path rather than left to the caller: a client
	// rendering a host shows the name, and resolving RoleID one request per
	// host is what turns a 500-host listing into 501 queries.
	RoleName string
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
	ActorType string // user | token | agent | system
	ActorID   string
	// ActorDisplay is the actor's name as it was when this happened — a token
	// name, or an email once an OIDC subject can authenticate. Captured rather
	// than joined: the record must stay legible after the token is deleted.
	ActorDisplay string
	Action       string
	TargetType   string
	TargetID     string
	Meta         []byte
	SourceIP     *netip.Addr
}

// Actor kinds. These are the values audit_log.actor_type accepts.
const (
	ActorToken  = "token"
	ActorUser   = "user"
	ActorAgent  = "agent"
	ActorSystem = "system"
)

// Identity is an authenticated caller on the admin API.
//
// Deliberately not named for the credential that produced it. Today every
// identity comes from an API token; an OIDC subject would populate the same
// struct with Kind=ActorUser and a Subject that is not a uuid, and no handler
// or audit call site would change. That is the whole reason Subject is a string
// and TokenID is a separate, kind-specific field.
type Identity struct {
	// Kind is how this caller authenticated, and becomes audit actor_type.
	Kind string

	// Subject is the stable identifier recorded in the audit log: a token uuid
	// today, an issuer-qualified subject for OIDC.
	Subject string

	// Display is the human-readable name — a token's name, or an email.
	Display string

	Scopes []string

	// TokenID is set only when Kind is ActorToken. It exists because two
	// operations genuinely need the token itself rather than the identity:
	// recording last_used_at, and noticing that a revocation targets the
	// credential making the request.
	TokenID uuid.UUID

	// ExpiresAt is nil for a credential that does not expire. Carried so a
	// caller can be told how long it has left without a second query — the
	// question a break-glass check exists to answer.
	ExpiresAt *time.Time
}

// HasScope reports whether the caller carries scope. An identity holding "*"
// passes every check; reserve it for bootstrap credentials.
func (i Identity) HasScope(scope string) bool {
	for _, s := range i.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// Audit starts an audit entry attributed to this caller.
//
// A constructor rather than three fields copied at each call site: the actor is
// the part that is always the same and always easy to get subtly wrong, and
// threading it by hand is how an entry ends up attributed to "system".
func (i Identity) Audit(action, targetType, targetID string) AuditEntry {
	return AuditEntry{
		ActorType: i.Kind, ActorID: i.Subject, ActorDisplay: i.Display,
		Action: action, TargetType: targetType, TargetID: targetID,
	}
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
