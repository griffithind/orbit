package store

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Lifecycle states. These mirror the CHECK constraints in
// migrations/0001_initial.sql; adding a value requires changing both.
const (
	CAPending  = "pending"
	CAActive   = "active"
	CARetiring = "retiring"
	CARetired  = "retired"

	// MembershipPending is a membership a device has joined but nobody has
	// authorized yet. It holds no address, no certificate and no reach — it
	// exists so an operator can see the machine asking and decide.
	MembershipPending = "pending"

	MembershipCreated   = "created"
	MembershipEnrolled  = "enrolled"
	MembershipActive    = "active"
	MembershipSuspended = "suspended"
	MembershipDeleted   = "deleted"

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

	// NetworkID is the verifiable identifier: 80 bits of SHA-256 over
	// IdentityPublicKey, in Crockford base32 — `p8k3zj9x2mq4wr7t`.
	//
	// Beside Slug rather than replacing it, because they do different jobs. The
	// slug is the memorable name and the directory on every machine; this is the
	// one a joining machine can CHECK. Derived by CreateNetwork, never supplied.
	NetworkID string

	// IdentityPublicKey is the raw Ed25519 public key the ID commits to. Handed
	// to a joining machine so it can verify both the ID and the proof.
	IdentityPublicKey []byte

	// IdentitySignerRef locates the private half — file://…, and never the key
	// itself. Someone holding that key can convince a JOINING machine that their
	// control plane is this network, so it gets the CA key's custody. A tripwire
	// in migration 0017 fails if a column that could hold it is ever added.
	IdentitySignerRef string

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

	// FirewallSource is where this network's firewall rules come from:
	// FirewallSourceRole (per-role rules, the default and what every network
	// created before migration 0009 is) or FirewallSourcePolicy (the compiled
	// network policy document).
	//
	// One or the other, never both. Nebula's firewall is allow-only and rules
	// across config files concatenate, so rendering two sources could only widen
	// reachability — and what Orbit reported about a host's policy would be a
	// lower bound wearing authoritative mode's guarantee. See store/policy.go.
	FirewallSource string

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
	// key material. Today there is one scheme: db://<uuid>, the vault.
	SignerRef string
	Curve     string

	// UnsafeNetworks are the external prefixes this CA may permit its
	// subordinates to route. A readable copy of what was signed into the
	// certificate — the certificate remains the authority, exactly as it is for
	// Curve.
	//
	// Empty means this CA permits no routes at all, and widening it is a new CA
	// rather than an UPDATE: the constraint is signed, and a signature cannot be
	// edited.
	UnsafeNetworks []string

	NotBefore time.Time
	NotAfter  time.Time
	State     string
	CreatedAt time.Time
}

// Route is one prefix one gateway offers, and the unit of high availability:
// two rows for one prefix is two gateways, which nebula load-balances by weight
// and falls between when one stops answering.
type Route struct {
	ID           uuid.UUID
	NetworkID    uuid.UUID
	MembershipID uuid.UUID

	Prefix netip.Prefix

	// Weight orders gateways offering the SAME prefix. It does not order
	// different prefixes against each other — longest-prefix match does that,
	// automatically, and a knob suggesting otherwise would do nothing.
	Weight int

	Masquerade bool
	Install    bool

	// MTU is nil for "use the tun's".
	MTU *int

	CreatedAt time.Time

	// GatewayAddr is the gateway's overlay address, filled by queries that join
	// the membership. Not stored: it is the membership's address, and copying it
	// here would be a second place for it to be wrong.
	GatewayAddr netip.Addr

	// MembershipName is the gateway's name, carried so a network-wide listing
	// reads without a lookup per row. Empty from the per-membership queries,
	// where the caller already knows whose routes it asked for.
	MembershipName string
}

type Role struct {
	ID        uuid.UUID
	NetworkID uuid.UUID
	Name      string
	Groups    []string
	// FirewallRules is stored as jsonb and rendered into the managed
	// configuration, which Orbit owns whole — so these are the rules, not an
	// addition to somebody else's.
	FirewallRules []byte
	CreatedAt     time.Time
}

// Membership is a device IN a network.
//
// Not a machine — that is Device — and the distinction is the reason this type
// was renamed. The row's definition is literally "this device, in that network"
// (device_id is NOT NULL as of migration 0015), and the old name claimed
// something the row never was, which every reader had to correct for.
//
// What lives here is what depends on BOTH: an overlay address is meaningless
// without a network, a role is a network's concept, and instance settings are
// per membership because a machine on two networks runs two nebula processes
// that cannot share a UDP port or a tun device. What depends only on the
// machine — posture, OS, liveness — lives on Device. See docs/model.md §2.
type Membership struct {
	ID           uuid.UUID
	NetworkID    uuid.UUID
	Name         string
	RoleID       *uuid.UUID
	Addrs        []netip.Addr
	Tags         []string
	IsLighthouse bool
	IsRelay      bool

	// StaticAddrs is DERIVED, not stored: the device's public addresses crossed
	// with this membership's advertised port. Read-only — writing a machine's
	// address means writing device.public_addrs, which fixes every network it is
	// a lighthouse for at once.
	//
	// Kept on this struct because everything that renders or displays a
	// membership wants the joined form, and computing it at each call site is
	// how two of them come to disagree.
	StaticAddrs []string

	// AdvertisePort overrides ListenPort in StaticAddrs. Nil is the common case.
	//
	// It exists for port forwarding: a machine that binds 4242 but is reached on
	// 14242 would otherwise advertise the port it binds rather than the one that
	// reaches it, and nothing could connect.
	AdvertisePort *int
	State         string

	// AppliedConfigEpoch and AppliedBlocklistEpoch are reported by the agent
	// after a successful apply, not after a fetch. Convergence is measured from
	// these; measuring from fetch would hide a config that downloaded but never
	// took effect.
	AppliedConfigEpoch    int64
	AppliedBlocklistEpoch int64

	// ListenPort, TunDev, and Overrides are this instance's
	// resources. A zero value inherits the network's, and the network's zero
	// value inherits the control plane's default — one rule at three levels, so
	// a deployment that sets none behaves exactly as it did before they existed.
	//
	// They are per membership because orbit.membership already is: a machine on
	// two networks holds two rows, and two nebula processes on one kernel cannot
	// share a UDP port or a tun device.
	ListenPort *int
	TunDev     string
	Overrides  []byte

	// RestartRequiredEpoch names a generation this membership must RESTART for rather
	// than reload, and 0 means none ever has been.
	//
	// Nebula refuses a certificate reload whose networks changed (pki.go
	// reloadCert), so after an address change the machine installs the new
	// certificate, nebula declines it, and the old one keeps running until the
	// process restarts. Waiting does not help; that is what makes this different
	// from every other thing an agent is told to catch up on.
	RestartRequiredEpoch int64

	// AddrChangedAt is when this membership's address set last changed, or nil if it
	// never has. Compared against the active certificate's issued_at to pull
	// renewal forward, exactly as role.groups_changed_at is — the addresses are
	// inside the signed certificate, and a membership whose address moved is holding
	// one that no longer authorises the packets it is sending.
	AddrChangedAt *time.Time

	// RoutesChangedAt is when this membership's routes last changed, or nil if
	// they never have. Compared against the certificate's issued_at for the same
	// reason AddrChangedAt is: routes live in the certificate's unsafe networks,
	// so one issued before the change does not authorise the routing the control
	// plane believes is in force.
	RoutesChangedAt *time.Time

	// LastSeenAt, NebulaVersion and AgentVersion are read from the DEVICE, not
	// stored on this row — the columns were dropped in migration 0015.
	//
	// They are properties of a machine, and a machine on three networks has one
	// agent version and one moment it was last heard from. Kept on this struct
	// because everything that renders a membership wants them and resolving the
	// device per membership would be a query per row; the join that reads one
	// supplies them for free.
	//
	// LastSeenAt therefore means "this DEVICE was last heard from", not "this
	// membership's tunnel is up". Those are different facts and the old column
	// conflated them; see migration 0015. A per-membership liveness signal has
	// to come from something that can actually observe one.
	LastSeenAt    *time.Time
	NebulaVersion string
	AgentVersion  string
	CreatedAt     time.Time

	// DeviceID is the machine this membership belongs to.
	//
	// NOT NULL in the database as of migration 0015: a membership is "this
	// device, in that network", so a row naming no machine means nothing.
	//
	// Still a pointer on this struct, and only because CreateHost reads it as
	// one — a Membership value under construction does not have an id to point at
	// until its device row exists. Every value returned by a read has it set.
	DeviceID *uuid.UUID

	// RoleName is the assigned role's name, resolved by the same query that
	// reads the membership. Empty when it carries no role.
	//
	// Denormalized into the read path rather than left to the caller: a client
	// rendering a membership shows the name, and resolving RoleID one request per
	// membership is what turns a 500-machine listing into 501 queries.
	RoleName string
}

type Certificate struct {
	ID           uuid.UUID
	MembershipID uuid.UUID
	CAID         uuid.UUID
	Fingerprint  string
	PEM          string
	CertVer      int16
	NotBefore    time.Time
	NotAfter     time.Time
	State        string
	IssuedAt     time.Time
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

	// MembershipID names an existing membership; Reserved describes one to create.
	// Exactly one, enforced by the database — see migration 0014.
	MembershipID *uuid.UUID
	Reserved     *Reservation
	Method       string
	ExpiresAt    time.Time
	UsedAt       *time.Time
	CreatedBy    string
	CreatedAt    time.Time
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
// Deliberately not named for the credential that produced it. ResolveSession
// returns this same struct for a browser session cookie, populated from the
// token the session references, so nothing downstream of authentication learns
// that sessions exist. An OIDC subject would populate it with Kind=ActorUser
// and a Subject that is not a uuid, and no handler or audit call site would
// change either. That is why Subject is a string and TokenID is a separate,
// kind-specific field.
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
	MembershipID uuid.UUID
	State        string
}

// RedeemedCredential is the result of atomically consuming an enrollment
// credential.
//
// Exactly one of MembershipID and Reserved is set, which the database enforces
// (migration 0014). MembershipID names an existing membership — re-enrolling a machine
// already on the network. Reserved describes a membership that does not exist
// yet and is created at redemption, which is what keeps unattended provisioning
// working now that nothing may pre-create a device-less membership.
type RedeemedCredential struct {
	CredentialID uuid.UUID
	NetworkID    uuid.UUID
	MembershipID *uuid.UUID
	Method       string

	// Reserved is nil unless this credential is a reservation.
	Reserved *Reservation
}

// Reservation is a place held in a network for a machine that has not arrived.
//
// It carries the intent an operator would previously have expressed by
// pre-creating a host: what to call it, where to put it, what it may do. The
// membership is created when a device presents the code, so it names a machine
// from the moment it exists.
type Reservation struct {
	Name string

	// Addr is a specific overlay address, or the zero value to allocate.
	// Naming one is for machines whose address is written into something Orbit
	// does not manage — a static_host_map, a DNS record, someone's firewall.
	Addr netip.Addr

	RoleID *uuid.UUID

	// What the machine will BE, not only what it will be called.
	//
	// Here rather than in a follow-up PATCH because a lighthouse is the topology
	// that most wants to be provisioned unattended — a fixed-address box brought
	// up from a template nobody watches — and it was the one that needed a human
	// at the end. See migration 0020.
	IsLighthouse bool
	IsRelay      bool

	// PublicAddrs is a DEVICE fact carried on the reservation, and the only
	// field here that does not land on the membership.
	//
	// It belongs on the reservation anyway: a lighthouse's public address is
	// known BEFORE the machine exists — that is what makes it a lighthouse, and
	// the operator has already typed it into their cloud provider. Hosts only,
	// no ports, exactly as device.public_addrs stores them.
	//
	// SEEDED, NOT IMPOSED. A device that already has addresses keeps them: it is
	// one machine, its addresses are a machine-wide fact, and letting a
	// per-network reservation overwrite them would let joining network B move
	// where network A believes the machine is.
	PublicAddrs []string

	// AdvertisePort overrides the bound port for a machine behind port
	// forwarding. Nil means derive it, which is right for almost everything.
	AdvertisePort *int
}

// reservedCols is the reservation half of an enrollment_credential row.
//
// A struct rather than a handful of locals because the same columns are read by
// two redemption paths — one on *Store, one on *Tx — and adding a field to one
// and not the other would mean a reservation whose lighthouse flag applies from
// the enrollment endpoint and vanishes from the join endpoint.
type reservedCols struct {
	name          *string
	addr          *netip.Addr
	roleID        *uuid.UUID
	isLighthouse  bool
	isRelay       bool
	publicAddrs   []string
	advertisePort *int
}

// reservedColumns must list the same columns, in the same order, as dest().
const reservedColumns = `reserved_name, reserved_addr, reserved_role_id,
	reserved_is_lighthouse, reserved_is_relay,
	reserved_public_addrs, reserved_advertise_port`

func (c *reservedCols) dest() []any {
	return []any{&c.name, &c.addr, &c.roleID,
		&c.isLighthouse, &c.isRelay, &c.publicAddrs, &c.advertisePort}
}

// reservation returns what was reserved, or nil if this credential names an
// existing membership instead. reserved_name is the discriminator, which is what
// the schema's CHECK constraint enforces.
func (c *reservedCols) reservation() *Reservation {
	if c.name == nil {
		return nil
	}
	r := &Reservation{
		Name: *c.name, RoleID: c.roleID,
		IsLighthouse: c.isLighthouse, IsRelay: c.isRelay,
		PublicAddrs: c.publicAddrs, AdvertisePort: c.advertisePort,
	}
	if c.addr != nil {
		r.Addr = *c.addr
	}
	return r
}

// Convergence summarizes how much of a network has applied the current epochs.
// It gates CA rotation (docs/design.md 6) and is the metric behind the
// revocation SLO (docs/revocation.md 5).
type Convergence struct {
	ConfigEpoch      int64
	BlocklistEpoch   int64
	MembershipsTotal int
	ConfigApplied    int
	BlockApplied     int
	Lagging          []LaggingHost
}

type LaggingHost struct {
	MembershipID          uuid.UUID
	Name                  string
	AppliedConfigEpoch    int64
	AppliedBlocklistEpoch int64
	LastSeenAt            *time.Time
}
