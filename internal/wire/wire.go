// Package wire holds the request and response types shared between the control
// plane and the agent.
//
// They live in their own package so that a change to a field is visibly a
// protocol change, reviewed as one, rather than an incidental edit to a handler
// or a client. Both sides compile against these types, so a breaking change
// fails the build instead of failing in production.
package wire

import (
	"encoding/json"
	"time"
)

// EnrollRequest is posted to the public enroll endpoint.
type EnrollRequest struct {
	// Credential is the plaintext enrollment code.
	Credential string `json:"credential"`

	// PublicKey is the host's raw static public key, base64 standard encoding.
	// The private half is generated on the host and never transmitted; there is
	// no field for it here and no column for it in the database.
	PublicKey string `json:"public_key"`

	// Curve is CURVE25519 or P256 and must match the network's.
	Curve string `json:"curve"`

	AgentVersion  string `json:"agent_version,omitempty"`
	NebulaVersion string `json:"nebula_version,omitempty"`

	// HostInfo is advisory metadata for the admin UI. It is never trusted for
	// any authorization decision.
	HostInfo map[string]string `json:"host_info,omitempty"`
}

// EnrollResponse carries everything a host needs to join.
type EnrollResponse struct {
	HostID   string `json:"host_id"`
	HostName string `json:"host_name"`

	// Certificate is this host's PEM certificate.
	Certificate string `json:"certificate"`
	// CABundle is every CA the host should trust, concatenated. It contains
	// more than the issuing CA during a rotation, which is what lets a CA be
	// published and converged before it starts signing.
	CABundle string `json:"ca_bundle"`
	// Config is the rendered 50-orbit.yml fragment.
	Config string `json:"config"`

	ConfigEpoch    int64 `json:"config_epoch"`
	BlocklistEpoch int64 `json:"blocklist_epoch"`

	// AgentEndpoints are overlay addresses, one per live control-plane replica.
	// From here on the host talks to the control plane over nebula and holds no
	// bearer credential.
	//
	// A list rather than a single value: an agent pinned to one replica loses
	// renewal and revocation when that replica goes away, which makes running a
	// second one redundancy for the database and nothing for the fleet.
	AgentEndpoints []string `json:"agent_endpoints,omitempty"`

	// RenewAfter is the midpoint of the certificate's lifetime. Renewing then
	// leaves the remaining half to recover from failure before expiry.
	RenewAfter time.Time `json:"renew_after"`
	NotAfter   time.Time `json:"not_after"`
}

// StateResponse is what the agent polls for.
type StateResponse struct {
	ConfigEpoch    int64 `json:"config_epoch"`
	BlocklistEpoch int64 `json:"blocklist_epoch"`

	// Config, CABundle, and Certificate are present only when the agent's
	// reported epoch is behind, so a steady-state poll is small.
	Config      string `json:"config,omitempty"`
	CABundle    string `json:"ca_bundle,omitempty"`
	Certificate string `json:"certificate,omitempty"`

	// RenewAfter is the control plane's view of when this host should renew, and
	// NotAfter when its certificate dies.
	//
	// The agent honours RenewAfter only when it is EARLIER than the agent's own
	// schedule, and only within the certificate's window: a control plane that is
	// stale, wrong, or hostile can therefore pull a fleet-wide certificate change
	// forward — from a median of half a certificate lifetime to the length of the
	// agent's spread window — but can never push a host toward expiry by delaying
	// its renewal. Zero means "no opinion", which is the pre-existing behaviour of
	// scheduling purely from the certificate on disk.
	RenewAfter time.Time `json:"renew_after,omitempty"`
	NotAfter   time.Time `json:"not_after,omitempty"`
}

// ReportRequest is what an agent sends after successfully applying a config.
//
// Reported after applying, never after fetching. Reporting on fetch would make
// convergence measure download success and hide the case where a config was
// received but never took effect, which is exactly the failure a CA rotation
// must not advance past.
type ReportRequest struct {
	ConfigEpoch    int64  `json:"config_epoch"`
	BlocklistEpoch int64  `json:"blocklist_epoch"`
	NebulaVersion  string `json:"nebula_version,omitempty"`
	AgentVersion   string `json:"agent_version,omitempty"`

	// RevertedFromConfigEpoch and RevertedFromBlocklistEpoch name the generation
	// this host was running immediately before its unreachable-guard put the
	// previous one back.
	//
	// They exist because reported epochs are otherwise monotonic server-side,
	// and they have to be: a replayed or reordered report that could lower a
	// recorded epoch would make a network look less converged than it is and
	// stall a CA rotation on a number that keeps regressing. But an automatic
	// revert is the one case where a lower epoch is the truth — the host really
	// is no longer running what it last reported — and leaving the control plane
	// believing otherwise means a push that severed the fleet still reads as 100%
	// converged, which is exactly the false data the rotation gate must not act
	// on.
	//
	// Naming the epoch being reverted FROM is what makes lowering safe to accept:
	// the server can require it to match what it currently has, so a stale
	// duplicate of the revert report is a no-op rather than a second regression,
	// and a report that simply carries a smaller number still cannot lower
	// anything. Zero means "not a revert" and leaves the monotonic path untouched.
	RevertedFromConfigEpoch    int64 `json:"reverted_from_config_epoch,omitempty"`
	RevertedFromBlocklistEpoch int64 `json:"reverted_from_blocklist_epoch,omitempty"`

	// QuarantinedConfigEpoch is a generation this host is currently refusing to
	// apply, because applying it already broke this host once.
	//
	// Sent on every report while the quarantine lasts, not only on the revert.
	// Without it, "this host rejected your configuration" and "this host is slow"
	// are the same observation server-side — both are just a host whose applied
	// epoch is behind — and they want opposite responses from an operator. Zero
	// means nothing is quarantined.
	QuarantinedConfigEpoch int64 `json:"quarantined_config_epoch,omitempty"`
}

// RenewRequest asks for a fresh certificate. A new keypair is generated by
// default, so this carries a new public key.
type RenewRequest struct {
	PublicKey string `json:"public_key"`
	Curve     string `json:"curve"`
}

// RecoveryChallengeResponse is the server's half of the proof-of-possession
// exchange for a host whose certificate expired while it was offline.
type RecoveryChallengeResponse struct {
	Nonce           string    `json:"nonce"`
	ServerPublicKey string    `json:"server_public_key"`
	Curve           string    `json:"curve"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// RecoverRequest redeems a challenge.
//
// The host proves possession of the private key from its last certificate by
// deriving the same shared secret the server can, and MACs the NEW public key
// with it. Binding the new key is what makes a captured proof useless to
// anyone else: it cannot be replayed to obtain a certificate for a key the
// attacker controls.
type RecoverRequest struct {
	HostID string `json:"host_id"`
	Nonce  string `json:"nonce"`
	// PublicKey is the new host key, generated locally as at enrollment.
	PublicKey string `json:"public_key"`
	Curve     string `json:"curve"`
	Proof     string `json:"proof"`
}

// CreateHostRequest is the admin API's host creation payload.
type CreateHostRequest struct {
	NetworkID    string   `json:"network_id"`
	Name         string   `json:"name"`
	OverlayAddr  string   `json:"overlay_addr"`
	RoleID       string   `json:"role_id,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	IsLighthouse bool     `json:"is_lighthouse,omitempty"`
	IsRelay      bool     `json:"is_relay,omitempty"`
	StaticAddrs  []string `json:"static_addrs,omitempty"`
}

// UpdateHostRequest changes a host's roles and metadata.
//
// Pointer fields so "not supplied" is distinguishable from "set to false" or
// "set to empty". A PATCH that cannot express "leave this alone" forces callers
// to read-modify-write, which races.
type UpdateHostRequest struct {
	RoleID       *string   `json:"role_id,omitempty"`
	Tags         *[]string `json:"tags,omitempty"`
	IsLighthouse *bool     `json:"is_lighthouse,omitempty"`
	IsRelay      *bool     `json:"is_relay,omitempty"`
	StaticAddrs  *[]string `json:"static_addrs,omitempty"`
}

type HostResponse struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	NetworkID    string   `json:"network_id"`
	OverlayAddrs []string `json:"overlay_addrs"`
	State        string   `json:"state"`
	Tags         []string `json:"tags,omitempty"`
	IsLighthouse bool     `json:"is_lighthouse"`
	IsRelay      bool     `json:"is_relay"`

	// RoleID and RoleName both, and for different readers.
	//
	// RoleID because UpdateHostRequest takes one: a field that can be written
	// and not read makes a safe read-modify-write impossible, and a client that
	// PATCHes tags without being able to see the current role cannot tell
	// whether it just preserved one or cleared it.
	//
	// RoleName because a uuid is not something an operator or a UI can render.
	// It costs nothing extra: the store resolves it in the join that reads the
	// host, so it does not add a query per host to the listing path.
	RoleID   string `json:"role_id,omitempty"`
	RoleName string `json:"role_name,omitempty"`

	// StaticAddrs is settable through PATCH for the same reason RoleID is
	// readable here — and this one is worse if omitted: a lighthouse whose
	// static_addrs a read-modify-write silently drops is one every host in the
	// mesh keeps dialling and none can reach.
	StaticAddrs []string `json:"static_addrs,omitempty"`

	AppliedConfigEpoch    int64      `json:"applied_config_epoch"`
	AppliedBlocklistEpoch int64      `json:"applied_blocklist_epoch"`
	LastSeenAt            *time.Time `json:"last_seen_at,omitempty"`

	// NebulaVersion and AgentVersion are what the host reported on its last
	// successful apply. They are the first question asked of a host that has
	// stopped renewing — an agent too old to know an endpoint, or a nebula that
	// rejects the certificate version the network moved to — and until now the
	// only way to see them was psql.
	NebulaVersion string `json:"nebula_version,omitempty"`
	AgentVersion  string `json:"agent_version,omitempty"`

	CreatedAt time.Time `json:"created_at"`

	// ActiveCertificates is present on the single-host response only.
	//
	// An operator opening a host wants its expiry immediately, and behind a
	// second request that is a question most callers never ask. It is bounded:
	// the partial unique index permits one active certificate per cert_version,
	// so this holds one row, or two mid version-migration.
	//
	// Deliberately absent from the listing, where it would be one query per
	// host — the cost this response's role name exists to avoid.
	ActiveCertificates []CertificateResponse `json:"active_certificates,omitempty"`
}

// HostListResponse is one page of GET /v1/hosts.
//
// An envelope, not a bare array with X-Total-Count and Link headers. Both
// clients this is about — a CLI drawing a table and a UI drawing a list — have
// to know whether another page exists, and in an envelope that fact is part of
// the type both sides compile against, which is the reason this package exists.
// A header is not: it survives neither a `curl | jq` pipeline nor most fetch
// wrappers, and when it is dropped the client concludes it has the whole fleet.
//
// This replaces a bare JSON array and is a breaking change on purpose. Nothing
// is deployed, and the alternative is a listing that silently truncates.
type HostListResponse struct {
	Hosts []HostResponse `json:"hosts"`

	// NextCursor is empty on the last page, and is the only way to ask for the
	// next one: pass it back unmodified as ?cursor=. It is opaque — it encodes
	// a sort key, and a client that parses it has taken a dependency on an
	// ordering this endpoint is free to change.
	NextCursor string `json:"next_cursor,omitempty"`

	// TotalCount is present only when the request asked for it with count=true.
	// A pointer so "not requested" is not reported as zero, which would read as
	// an empty fleet.
	TotalCount *int `json:"total_count,omitempty"`
}

// CertificateResponse is one certificate in a host's history.
//
// No PEM field at all, rather than an empty one: it is the largest thing on the
// row, a host renewing hourly has thousands of rows, and nothing an operator
// reads here needs the bytes.
type CertificateResponse struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`

	// CAID and CAName name the issuer. During a rotation this is the field that
	// says whether a host has moved to the new authority, which is what decides
	// when the old one can be retired.
	CAID   string `json:"ca_id"`
	CAName string `json:"ca_name"`

	CertVersion int       `json:"cert_version"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`

	// RenewAt is the midpoint of the lifetime: when the agent should have
	// renewed. Present because otherwise "overdue" is arithmetic every reader
	// has to redo — a certificate that is still valid but past this is one
	// whose renewal is already failing, and that is the whole warning.
	RenewAt time.Time `json:"renew_at"`

	IssuedAt time.Time `json:"issued_at"`
}

// CertificateListResponse is one page of a host's certificate history. Envelope
// and cursor for the same reasons as HostListResponse; no count, because
// nothing an operator asks of a certificate history is answered by how many
// certificates there have been.
type CertificateListResponse struct {
	Certificates []CertificateResponse `json:"certificates"`
	NextCursor   string                `json:"next_cursor,omitempty"`
}

// EnrollmentCodeResponse returns a freshly minted code. The plaintext appears
// here and nowhere else, ever.
type EnrollmentCodeResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
	EnrollURL string    `json:"enroll_url"`
}

// BlockResponse reports the epoch a block landed in, so an operator (or a test)
// can watch convergence toward it.
type BlockResponse struct {
	BlocklistEpoch int64 `json:"blocklist_epoch"`
}

// ConvergenceResponse backs the rotation gate and the revocation SLO.
type ConvergenceResponse struct {
	ConfigEpoch    int64 `json:"config_epoch"`
	BlocklistEpoch int64 `json:"blocklist_epoch"`
	HostsTotal     int   `json:"hosts_total"`
	ConfigApplied  int   `json:"config_applied"`
	BlockApplied   int   `json:"blocklist_applied"`

	Lagging []LaggingHost `json:"lagging,omitempty"`
}

type LaggingHost struct {
	HostID                string     `json:"host_id"`
	Name                  string     `json:"name"`
	AppliedConfigEpoch    int64      `json:"applied_config_epoch"`
	AppliedBlocklistEpoch int64      `json:"applied_blocklist_epoch"`
	LastSeenAt            *time.Time `json:"last_seen_at,omitempty"`
}

// Error is the uniform error body. Message is safe to show a user; it never
// distinguishes "does not exist" from "you may not see it", because that
// distinction is exactly what a prober is looking for.
type Error struct {
	Error string `json:"error"`
}

// --- Admin: networks, roles, CAs, tokens, audit ---

type CreateNetworkRequest struct {
	Name string `json:"name"`
	// CIDRs are the overlay prefixes. Two networks may overlap: they are
	// separate meshes and never exchange traffic.
	CIDRs []string `json:"cidrs"`
	// CertTTL is the host certificate lifetime. This is the revocation SLA for
	// a partitioned host, not merely a rotation cadence, so the API states it
	// in those terms.
	CertTTL     string `json:"cert_ttl,omitempty"`
	Curve       string `json:"curve,omitempty"`
	CertVersion int    `json:"cert_version,omitempty"`
}

type NetworkResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	CIDRs       []string `json:"cidrs"`
	Curve       string   `json:"curve"`
	CertVersion int      `json:"cert_version"`
	CertTTL     string   `json:"cert_ttl"`

	ConfigEpoch    int64 `json:"config_epoch"`
	BlocklistEpoch int64 `json:"blocklist_epoch"`
}

type CreateRoleRequest struct {
	NetworkID string   `json:"network_id"`
	Name      string   `json:"name"`
	Groups    []string `json:"groups,omitempty"`
	// Firewall is validated strictly before storage: nebula silently ignores
	// keys it does not recognise, so a typo would otherwise become a rule with
	// a different meaning than its author wrote.
	Firewall json.RawMessage `json:"firewall,omitempty"`
}

// UpdateRoleRequest edits a role in place.
//
// Pointer fields for the same reason UpdateHostRequest uses them: "not
// supplied" must be distinguishable from "set to empty". A PATCH that cannot
// express "leave this alone" forces read-modify-write, which races — and for a
// role, losing that race silently rewrites the firewall on every host carrying
// it.
type UpdateRoleRequest struct {
	Name   *string   `json:"name,omitempty"`
	Groups *[]string `json:"groups,omitempty"`
	// Firewall replaces the rule set wholesale rather than merging. Merging
	// would make "remove this rule" inexpressible, and a rule an operator
	// believes they deleted is the worst possible outcome for a firewall.
	Firewall *json.RawMessage `json:"firewall,omitempty"`
}

// RoleUpdateResponse is the body of PATCH /v1/roles/{id}.
//
// It lives here rather than beside its handler because the CLI decodes it, and
// a response type known to only one side is the drift wire exists to prevent: a
// field renamed in the handler would be a silent client regression rather than
// a build failure.
//
// The status code carries information this body does not repeat. 200 means the
// change is fully in force; 202 means the configuration half is live and the
// certificate half is not, because groups are inside the signed certificate and
// every carrying host presents the old set until it reissues.
type RoleUpdateResponse struct {
	RoleResponse

	// Changed is false when the request restated what was already stored. The
	// role is returned unmodified and no epoch was bumped, so no agent is woken.
	Changed bool `json:"changed"`

	// GroupsChanged marks the edit that outlives this request.
	GroupsChanged bool `json:"groups_changed,omitempty"`

	// HostsAwaitingCertificate is how many hosts still present a certificate
	// carrying the old groups.
	HostsAwaitingCertificate int `json:"hosts_awaiting_certificate,omitempty"`

	// CertificatesConvergeBy is when the last of them will have renewed.
	// Computed from live certificate rows and the agent's renewal policy, which
	// is deterministic per host — a deadline, not an estimate.
	CertificatesConvergeBy string `json:"certificates_converge_by,omitempty"`

	// Detail says in words what those two numbers mean, for whoever is reading
	// a terminal rather than parsing JSON.
	Detail string `json:"detail,omitempty"`
}

// LaggingHostsError is the 409 body from POST /v1/cas/{id}/activate.
//
// Typed for the same reason as RoleUpdateResponse, and more urgently: the
// remedy lives in the non-error field. A client that decodes only Error tells
// an operator "some hosts have not converged" without saying which — which is
// the entire question.
type LaggingHostsError struct {
	Error   string        `json:"error"`
	Lagging []LaggingHost `json:"lagging,omitempty"`
}

// RoleInUseError is the 409 body from DELETE /v1/roles/{id}. Same shape, same
// reasoning: ON DELETE RESTRICT refuses the delete, and the useful part of the
// answer is the list of hosts that are blocking it.
type RoleInUseError struct {
	Error string     `json:"error"`
	Hosts []RoleHost `json:"hosts,omitempty"`
}

// RoleHost identifies a host that carries a role.
type RoleHost struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type RoleResponse struct {
	ID        string          `json:"id"`
	NetworkID string          `json:"network_id"`
	Name      string          `json:"name"`
	Groups    []string        `json:"groups,omitempty"`
	Firewall  json.RawMessage `json:"firewall,omitempty"`
}

type CreateCARequest struct {
	NetworkID string `json:"network_id"`
	Name      string `json:"name"`
	// Days is the CA lifetime. Host certificates cannot outlive it, so a short
	// CA forces a rotation cadence.
	Days int `json:"days,omitempty"`
	// Networks and Groups bound what subordinate certificates may claim. Empty
	// means unconstrained, which the API refuses: nebula has no intermediate
	// CAs, so this is the only blast-radius control there is.
	Networks []string `json:"networks,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	// SignerRef locates the signing key: awskms://…, pkcs11://…, file://…
	SignerRef string `json:"signer_ref"`
}

// ActivateCARequest promotes a CA to signing.
//
// Activation is refused while hosts are still behind, because promoting past
// them partitions them off the mesh: they do not yet trust the new CA and their
// next renewal will be signed by it.
type ActivateCARequest struct {
	// AcknowledgeCutoff overrides that refusal.
	//
	// A typed field rather than a query flag, deliberately. This is the
	// emergency path after a signing-key compromise, where cutting off
	// unconverged hosts is the lesser harm — but it should be impossible to
	// take by accident, and it is audited as a distinct action.
	AcknowledgeCutoff bool `json:"acknowledge_cutoff,omitempty"`
}

type CAResponse struct {
	ID          string `json:"id"`
	NetworkID   string `json:"network_id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	// CertPEM is what operators add to a trust bundle during rotation.
	CertPEM string `json:"cert_pem,omitempty"`

	// ActiveCertificates is how many live certificates this CA signed. A
	// retiring CA can be retired once this reaches zero.
	ActiveCertificates int `json:"active_certificates"`
}

type CreateTokenRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
	// ExpiresInDays bounds the token. Zero means no expiry, which the API
	// permits but reports back so it is a visible choice.
	ExpiresInDays int `json:"expires_in_days,omitempty"`
}

type TokenResponse struct {
	ID string `json:"id"`
	// Token is the plaintext, returned exactly once and never stored.
	Token     string   `json:"token,omitempty"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"`
	// LastUsedAt is what makes a listing worth having: after a leak the
	// question is whether the token was used, and when.
	LastUsedAt string `json:"last_used_at,omitempty"`
	// RevokedAt is set on revoked tokens, which stay listed rather than
	// disappearing. A row that vanishes cannot answer "was it used after we
	// revoked it".
	RevokedAt string `json:"revoked_at,omitempty"`
}

// WhoAmIResponse describes the calling credential to itself.
//
// It never contains the token. The point is to answer "which credential am I
// holding, and is it still good" — for a break-glass check, and for the more
// common case of an operator with three tokens in three shells.
type WhoAmIResponse struct {
	// Kind is "token" today, "user" for an OIDC subject.
	Kind string `json:"kind"`
	// ID is the token uuid, or an issuer-qualified subject.
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	Scopes   []string `json:"scopes"`
	Unscoped bool     `json:"unscoped"`
	// ExpiresAt is empty when the credential does not expire.
	ExpiresAt string `json:"expires_at,omitempty"`
	// ExpiresInDays is negative for an already-expired credential, which cannot
	// authenticate — so seeing it here means a clock disagreement worth knowing
	// about.
	ExpiresInDays *int `json:"expires_in_days,omitempty"`
}

type AuditRecordResponse struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	ActorType string    `json:"actor_type"`
	ActorID   string    `json:"actor_id,omitempty"`
	// ActorDisplay is the actor's name as it was at the time — a token name, or
	// an email once OIDC subjects can authenticate. Present so a reader does
	// not have to resolve actor_id against a table the actor may have been
	// deleted from.
	ActorDisplay string          `json:"actor_display,omitempty"`
	Action       string          `json:"action"`
	TargetType   string          `json:"target_type,omitempty"`
	TargetID     string          `json:"target_id,omitempty"`
	Meta         json.RawMessage `json:"meta,omitempty"`
	SourceIP     string          `json:"source_ip,omitempty"`
}
