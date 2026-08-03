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

	// ConfigMode and NetworkSlug tell the agent which layout Config is and which
	// directory it belongs in — see StateResponse for both. They are on the
	// enrollment response as well because the very first write happens here,
	// before any state poll, and an agent that guessed would create the wrong
	// layout once and then keep both.
	ConfigMode  string `json:"config_mode,omitempty"`
	NetworkSlug string `json:"network_slug,omitempty"`
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

	// RestartRequiredEpoch names a generation this host must RESTART nebula for
	// rather than reload. Zero means none ever has been.
	//
	// It exists because one change genuinely cannot be applied hot. Nebula
	// compares the networks in a reloaded certificate against the running one
	// and refuses the whole reload if they differ (pki.go reloadCert, "Networks
	// in new cert was different from old"), so after an address change the agent
	// installs a valid new certificate, nebula declines it, and the process
	// keeps running the OLD one — indefinitely, while reporting a healthy
	// applied epoch. Nothing about that looks wrong from here.
	//
	// AN EPOCH RATHER THAN A FLAG, and the difference is the whole design:
	//
	//   - A flag has to be cleared by somebody. If the agent clears it, a lost
	//     acknowledgement either leaves it set — a host that restarts on every
	//     poll — or clears it early, and the restart never happens. Both are
	//     silent, and both are worse than not having the signal.
	//   - An epoch is compared against what the agent has already done, exactly
	//     as applied_config_epoch is. Nothing is cleared, a replayed response is
	//     a no-op, and an agent that was offline for the change catches up by
	//     arithmetic rather than by being told twice.
	//
	// NOT the network's config epoch, and not a second network-wide counter: an
	// address change on one host requires that ONE host to restart. Every other
	// host in the network re-renders a static_host_map, which is an ordinary hot
	// reload, and a network-wide restart signal would turn a one-host change
	// into a fleet-wide outage.
	//
	// THE AGENT'S CONTRACT. Persist the last value restarted for. After
	// successfully applying a generation, restart nebula when
	// RestartRequiredEpoch is greater than that persisted value AND the applied
	// config epoch has reached RestartRequiredEpoch, then persist the new value.
	// The second condition is what keeps an agent that is still catching up from
	// restarting into a configuration it has not installed yet.
	RestartRequiredEpoch int64 `json:"restart_required_epoch,omitempty"`

	// ConfigMode is "authoritative" (Config is a complete nebula.yml, and nebula
	// is pointed at that file) or "fragment" (Config is a 50-orbit.yml merged
	// with whatever else is in the config directory).
	//
	// On the wire rather than inferred from the file's shape, because the agent
	// has to decide WHERE to write it and what to point nebula at, and guessing
	// from content is how a host ends up with both layouts on disk.
	ConfigMode string `json:"config_mode,omitempty"`

	// NetworkSlug is the immutable per-network directory name under
	// /var/lib/orbit. Sent so the agent never has to derive a path from a value
	// that could change; see nebulacfg for the layout.
	NetworkSlug string `json:"network_slug,omitempty"`
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

	// DataPlaneDown reports that nebula is not running on this host.
	//
	// The agent does NOT restart it — systemd owns that, and two supervisors
	// restarting one process turns a crash loop into two racing ones. But
	// without this the condition is invisible to the control plane: the agent
	// itself is fine, keeps polling, keeps reporting an applied epoch, and
	// convergence shows a healthy host that is carrying no traffic at all.
	DataPlaneDown bool `json:"data_plane_down,omitempty"`

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
	NetworkID string `json:"network_id"`
	Name      string `json:"name"`

	// OverlayAddr is optional. Omit it and the control plane allocates one,
	// which is the normal case: an operator naming addresses by hand is
	// maintaining a spreadsheet the database could maintain for them, and every
	// address chosen that way is one that might already be taken.
	//
	// Supplying one is still supported for the cases that need it — a lighthouse
	// whose address is baked into somebody's runbook, a machine being migrated
	// onto Orbit with an address it already has.
	OverlayAddr string `json:"overlay_addr,omitempty"`

	// OverlayPrefix names which of the network's CIDRs to allocate from. Ignored
	// when OverlayAddr is supplied; empty means the first.
	//
	// Allocation produces ONE address, not one per address family. Dual-stacking
	// by default would double what a later address change disrupts and would
	// silently convert a fleet the moment an IPv6 prefix is added to the
	// network. A host that wants both asks for the second explicitly, and that
	// request is a line in the audit log.
	OverlayPrefix string `json:"overlay_prefix,omitempty"`

	RoleID       string   `json:"role_id,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	IsLighthouse bool     `json:"is_lighthouse,omitempty"`
	IsRelay      bool     `json:"is_relay,omitempty"`
	StaticAddrs  []string `json:"static_addrs,omitempty"`
}

// AddHostAddressRequest claims an additional overlay address.
//
// Either an explicit Addr or an allocation from Prefix; supplying neither
// allocates from the network's first prefix.
type AddHostAddressRequest struct {
	Addr   string `json:"addr,omitempty"`
	Prefix string `json:"prefix,omitempty"`

	// AcknowledgeRestart proceeds past the disruption gate.
	//
	// A typed field rather than a query flag, exactly as ActivateCARequest's
	// acknowledge_cutoff is, and for the same reason: this is the deliberate
	// path, it should be impossible to take by accident, and it is audited as a
	// distinct action rather than as the ordinary one with a flag in metadata.
	AcknowledgeRestart bool `json:"acknowledge_restart,omitempty"`
}

// RemoveHostAddressRequest releases one of a host's addresses.
//
// A body on a DELETE, which is unusual and is the right trade here: the
// acknowledgement must be typed, and a proxy that strips the body fails SAFE —
// the request is refused with the gate's 409 rather than silently performing the
// disruptive change.
type RemoveHostAddressRequest struct {
	AcknowledgeRestart bool `json:"acknowledge_restart,omitempty"`
}

// RestartRequiredError is the 409 body from an address change.
//
// NOT a convergence gate, and the difference is the whole message. CA activation
// refuses because hosts have not caught up, and waiting fixes it. This refuses
// because nebula will not accept a certificate whose networks changed on a
// reload (pki.go reloadCert), so the host must restart — and no amount of
// waiting changes that. Telling an operator to retry later would be advice that
// can never come true.
type RestartRequiredError struct {
	Error string `json:"error"`

	// Detail spells out the consequence in words, worst first.
	Detail string `json:"detail,omitempty"`

	Impact *AddressImpact `json:"impact,omitempty"`
}

// AddressImpact is who else is affected when one host's nebula restarts.
//
// It is a declared type rather than an inline map because the useful half of the
// answer lives here: a client that decodes only Error tells an operator "this
// requires a restart" without saying that the host in question is the only relay
// on the network, which is the entire question.
type AddressImpact struct {
	HostID   string `json:"host_id"`
	HostName string `json:"host_name"`

	IsLighthouse   bool `json:"is_lighthouse,omitempty"`
	IsRelay        bool `json:"is_relay,omitempty"`
	IsControlPlane bool `json:"is_control_plane,omitempty"`

	// The "only" flags are separate fields rather than left to the reader to
	// derive from the counts, because they are the ones that change the
	// decision: one lighthouse of four going away is a blip, the only lighthouse
	// going away stops discovery for the network.
	OnlyLighthouse   bool `json:"only_lighthouse,omitempty"`
	OnlyRelay        bool `json:"only_relay,omitempty"`
	OnlyControlPlane bool `json:"only_control_plane,omitempty"`

	// HostsUsingRelays is how many hosts have use_relays set and could therefore
	// be carrying traffic through this one. Present only when this host relays.
	HostsUsingRelays int `json:"hosts_using_relays,omitempty"`

	HostsInNetwork    int `json:"hosts_in_network"`
	Lighthouses       int `json:"lighthouses,omitempty"`
	Relays            int `json:"relays,omitempty"`
	LiveControlPlanes int `json:"live_control_planes,omitempty"`

	// Consequences are ordered worst first. The relay line leads when this host
	// relays, because that is the one whose damage lands on machines nobody
	// making the change was thinking about.
	Consequences []string `json:"consequences,omitempty"`
}

// HostAddressesResponse is the address set after a change.
type HostAddressesResponse struct {
	HostID       string   `json:"host_id"`
	OverlayAddrs []string `json:"overlay_addrs"`

	// RestartRequiredEpoch is the generation the host must restart for, echoed
	// so a caller can watch for it landing rather than guess.
	RestartRequiredEpoch int64 `json:"restart_required_epoch,omitempty"`
	ConfigEpoch          int64 `json:"config_epoch,omitempty"`

	// Detail says what happens next, in words.
	Detail string `json:"detail,omitempty"`
}

// NetworkCIDRRequest adds a prefix to a network.
type NetworkCIDRRequest struct {
	CIDR string `json:"cidr"`
}

// CIDRInUseError is the 409 body from removing a prefix hosts have addresses in.
//
// Same shape and same reasoning as RoleInUseError: the refusal is not the useful
// part of the answer, the list of who is blocking it is.
type CIDRInUseError struct {
	Error string          `json:"error"`
	Hosts []AddressHolder `json:"hosts,omitempty"`
}

// AddressHolder is a host holding an address inside a prefix.
type AddressHolder struct {
	HostID string `json:"host_id"`
	Name   string `json:"name"`
	Addr   string `json:"addr"`
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

	// The instance's own resources, reported as the EFFECTIVE values rather than
	// as the raw columns: a caller asking "what port is this host listening on"
	// wants the answer, not "nothing is set here, go read the network". Which
	// level supplied the value is visible from the network response.
	ListenPort int    `json:"listen_port,omitempty"`
	TunDev     string `json:"tun_dev,omitempty"`
	ConfigMode string `json:"config_mode,omitempty"`

	// RestartRequiredEpoch is the generation this host must restart nebula for,
	// and 0 means none ever has been. A value greater than
	// applied_config_epoch is a host that has not yet taken an address change —
	// the one change that cannot be applied hot.
	RestartRequiredEpoch int64 `json:"restart_required_epoch,omitempty"`

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

// --- Operational read surfaces ---
//
// These exist because the questions they answer were previously answerable only
// from psql. Each maps to a store method that already existed and was routed
// nowhere.

// BlocklistEntryResponse is one revoked fingerprint still being distributed.
//
// Entries outlive the host they revoke — DeleteHost removes the host row but
// deliberately leaves the blocklist entries, or a decommission would quietly
// un-revoke the machine it decommissioned. So HostName is best-effort and empty
// for a host that no longer exists, which is exactly the case worth seeing.
type BlocklistEntryResponse struct {
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason,omitempty"`
	Epoch       int64  `json:"epoch"`
	// NotAfter is when the revoked certificate expires, and therefore when this
	// entry stops being worth distributing: nebula rejects an expired
	// certificate before it consults the blocklist.
	NotAfter  string `json:"not_after"`
	CreatedAt string `json:"created_at"`
	HostName  string `json:"host_name,omitempty"`
}

// TrustBundleResponse is every CA a host should currently trust.
//
// Fetchable repeatedly, unlike the PEM in a CA creation response, because the
// moment it is needed is a rotation that has gone wrong and the create response
// is long gone.
type TrustBundleResponse struct {
	NetworkID string `json:"network_id"`
	PEM       string `json:"pem"`
	// CAs describes what is in the bundle, so a reader does not have to parse
	// the PEM to answer "which CAs does this include, and what state are they
	// in".
	CAs []CAResponse `json:"cas"`
}

// ExpiringCertificateResponse is a certificate approaching expiry.
//
// The metrics endpoint reports how many; this reports which. During a renewal
// failure the count says something is wrong and only the names say what.
type ExpiringCertificateResponse struct {
	HostID      string `json:"host_id"`
	HostName    string `json:"host_name"`
	Fingerprint string `json:"fingerprint"`
	NotAfter    string `json:"not_after"`
	// RenewAt is when the host should already have renewed. A RenewAt in the
	// past is the actionable signal, not NotAfter.
	RenewAt    string `json:"renew_at"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
}

// ControlPlaneResponse is one live replica serving a network's agent API.
type ControlPlaneResponse struct {
	HostID     string `json:"host_id"`
	Addr       string `json:"addr"`
	AgentPort  int    `json:"agent_port"`
	LastSeenAt string `json:"last_seen_at"`
}

// HealthResponse is the liveness and readiness answer.
//
// Deliberately not on the admin surface and deliberately unauthenticated: a
// load balancer and a systemd readiness check cannot hold a token, and the
// answer reveals nothing an unauthenticated caller could not infer from whether
// the port accepts a connection at all.
type HealthResponse struct {
	// Status is "ok" or "degraded". A process that is serving but cannot reach
	// Postgres is degraded, not down — it will answer nothing useful, and that
	// is worth distinguishing from a refused connection.
	Status   string `json:"status"`
	Database bool   `json:"database"`
	// Push reports whether the LISTEN connection is established. False means
	// every agent has fallen back to polling: correct, an order of magnitude
	// slower, and invisible without this.
	Push    bool   `json:"push"`
	Version string `json:"version,omitempty"`

	// ObservedAgeSeconds is how old the Database reading is.
	//
	// /healthz performs no I/O — restarting a process cannot fix a database, so
	// a liveness probe wired to Postgres would turn one outage into every
	// replica dying at once. It reports the last observation readiness took,
	// which can be arbitrarily old if nothing probes readiness.
	//
	// Without this, that staleness is invisible: a human curling /healthz during
	// an incident reads "database": true off a value taken before the outage
	// began. The status code is still right; the body is not, which is worse
	// than useless when someone is trying to work out what broke.
	//
	// ABSENT means no readiness probe has run yet. The Database value is then
	// inferred from store.Open having succeeded at startup — true a few
	// milliseconds into the process's life and not measured since. Treat an
	// absent age as "unverified", not as "fresh".
	ObservedAgeSeconds *float64 `json:"observed_age_seconds,omitempty"`
}

// Error is the uniform error body. Message is safe to show a user; it never
// distinguishes "does not exist" from "you may not see it", because that
// distinction is exactly what a prober is looking for.
type Error struct {
	Error string `json:"error"`
}

// --- Admin: networks, roles, CAs, tokens, audit ---

type CreateNetworkRequest struct {
	// Slug is the immutable, machine-safe identifier: lowercase alphanumerics
	// and hyphens, 1-32, no leading or trailing hyphen. It becomes a directory
	// name on every managed host in the network and the stem of their tun device
	// names, which is why it can never change.
	//
	// Optional. Left empty it is derived from Name, so a caller with no opinion
	// gets a reasonable one — but a caller that intends to script against this
	// network should choose it, because the derivation follows the name and the
	// name is free to be edited afterwards.
	Slug string `json:"slug,omitempty"`

	// Name is the display label: mutable, unique, and not an addressing key.
	Name string `json:"name"`

	// CIDRs are the overlay prefixes. Two networks may overlap: they are
	// separate meshes and never exchange traffic.
	//
	// An IPv6 prefix requires cert_version 2. Nebula's v1 format cannot carry an
	// IPv6 address at all, so the combination is refused here rather than
	// accepted and then failed at the first issuance.
	CIDRs []string `json:"cidrs"`
	// CertTTL is the host certificate lifetime. This is the revocation SLA for
	// a partitioned host, not merely a rotation cadence, so the API states it
	// in those terms.
	CertTTL     string `json:"cert_ttl,omitempty"`
	Curve       string `json:"curve,omitempty"`
	CertVersion int    `json:"cert_version,omitempty"`

	// ListenPort is the nebula UDP port hosts of this network use. Omitted means
	// the control plane's default. Two networks sharing a machine need different
	// ones, which is the entire reason this is per network rather than a
	// process-wide flag.
	ListenPort int `json:"listen_port,omitempty"`

	// ConfigMode is "authoritative" (default) or "fragment"; see NetworkResponse.
	ConfigMode string `json:"config_mode,omitempty"`
}

// UpdateNetworkRequest edits a network in place.
//
// There is no slug field, and its absence is the design: the slug is immutable
// and the database refuses to change it. Pointer fields for the same reason
// UpdateHostRequest uses them — "not supplied" must be distinguishable from
// "set to empty".
type UpdateNetworkRequest struct {
	// Name is the display label, and the only identifier that may be edited.
	Name *string `json:"name,omitempty"`

	ListenPort *int    `json:"listen_port,omitempty"`
	ConfigMode *string `json:"config_mode,omitempty"`

	// FirewallSource switches the network between "role" and "policy".
	//
	// It rides on this request rather than on a route of its own because it is a
	// column on the network and belongs beside config_mode, the other field here
	// that sets fleet-wide posture. It requires the policy:write scope IN
	// ADDITION to the networks:write this route declares — a token trusted to
	// rename a network must not thereby be able to change what firewall every
	// host in it enforces. The handler checks the second scope; see
	// resources.go's note on why the route table cannot express it.
	FirewallSource *string `json:"firewall_source,omitempty"`

	// AcknowledgeFirewallChange proceeds past the disruption gate.
	//
	// A typed field rather than a query flag, exactly as ActivateCARequest's
	// acknowledge_cutoff and AddHostAddressRequest's acknowledge_restart are, and
	// for the same reasons: this changes the firewall on every host in the
	// network in one request, it should be impossible to take by accident, and it
	// is audited as its own action rather than as an ordinary rename with a flag
	// in metadata.
	//
	// Only consulted when FirewallSource is supplied and the network has live
	// hosts. A switch on a network nobody has enrolled into disrupts nothing, and
	// demanding a confirmation there would teach operators to pass the flag
	// reflexively — which is what makes the confirmation on the dangerous case
	// worthless.
	AcknowledgeFirewallChange bool `json:"acknowledge_firewall_change,omitempty"`
}

// --- Admin: the network policy document ---
//
// THE REQUEST BODY OF PUT AND POST IS THE DOCUMENT ITSELF, raw, with no
// envelope. There is deliberately no PutPolicyRequest type here.
//
// Two reasons. A policy document is a file an operator keeps in git, so
// `curl -X PUT --data-binary @policy.json` and `orbit policy apply policy.json`
// should send the same bytes — an envelope makes the first of those a jq
// invocation. And the document's Go type already exists and is already shared:
// policy.Document, in internal/policy, which both the control plane and the CLI
// parse with policy.Parse. A second declaration of it here would be the drift
// this package exists to prevent, not a defence against it.
//
// The RESPONSES are typed here, because they are Orbit's own and would otherwise
// be known to one side only.

// PolicyResponse is a network's current policy document.
type PolicyResponse struct {
	NetworkID   string `json:"network_id"`
	NetworkSlug string `json:"network_slug"`

	// Version starts at 1 and counts within this network. Quoted during an
	// incident, so it is small and means something about this network rather
	// than about the deployment.
	Version int64 `json:"version"`

	// Document is the stored document. It is NOT byte-identical to what was
	// submitted: it is stored as jsonb, so key order and formatting are
	// normalized away. That normalization is what makes a re-send of an
	// unchanged policy provably a no-op rather than a fleet-wide re-render.
	Document json.RawMessage `json:"document"`

	// ConfigEpoch is the epoch this version produced, and the join between a
	// policy version and what a host reported applying: a host at
	// applied_config_epoch 41 was enforcing the greatest version at or below 41.
	ConfigEpoch int64 `json:"config_epoch"`

	Author    string    `json:"author,omitempty"`
	CreatedAt time.Time `json:"created_at"`

	// FirewallSource is the network's, repeated here because it is the answer to
	// the only question worth asking about a stored policy: whether it is the
	// one hosts are enforcing. A document can exist for a long time before it is
	// switched on, and a reader who assumes otherwise is reading a draft as if
	// it were the firewall.
	FirewallSource string `json:"firewall_source"`
}

// PolicyUpdateResponse is the body of PUT /v1/networks/{ref}/policy.
type PolicyUpdateResponse struct {
	PolicyResponse

	// Changed is false when the submitted document was semantically identical to
	// the stored one — same rules in a different key order, or reformatted. The
	// stored document is returned unmodified, no version was written, and no
	// epoch was bumped, so no agent was woken.
	Changed bool `json:"changed"`

	// PreviousVersion is 0 when this was the network's first document.
	PreviousVersion int64 `json:"previous_version,omitempty"`

	// Detail says in words what happens next, for whoever is reading a terminal
	// rather than parsing JSON — including the case that matters most, which is
	// a document stored while the network is still drawing its firewall from
	// roles and therefore not enforcing any of it.
	Detail string `json:"detail,omitempty"`
}

// PolicyCheckResponse is the body of POST /v1/networks/{ref}/policy/check.
//
// The endpoint validates without storing, and it is worth more than it looks: a
// policy edit is fleet-wide and an operator cannot see its effect before
// applying it, so this is where a typo is found instead of at 400 hosts. A
// refusal is a 400 carrying wire.Error with the fault named; this body is the
// success case.
type PolicyCheckResponse struct {
	// Valid is always true in a 2xx body. Present so a caller that checks a
	// field rather than a status code cannot read a refusal as a pass — the
	// failure mode of a check endpoint whose success body is empty.
	Valid bool `json:"valid"`

	NetworkID   string `json:"network_id"`
	NetworkSlug string `json:"network_slug"`

	// CurrentVersion is the version stored now, or 0 when the network has none.
	// It answers "am I about to change anything" before the change is made.
	CurrentVersion int64 `json:"current_version,omitempty"`

	// WouldChange is false when this document is semantically what is already
	// stored, so applying it would write nothing and wake no agent.
	WouldChange bool `json:"would_change"`

	// FirewallSource is the network's current source. A valid document checked
	// against a network still in "role" mode is a document that would be stored
	// and enforce nothing, and that is worth saying before the operator concludes
	// their change is live.
	FirewallSource string `json:"firewall_source"`

	// Host is the host named by ?host=, when one was named, resolved to what the
	// compiler will be given for it. Absent when no host was named.
	Host *PolicyCheckHost `json:"host,omitempty"`

	// Compiled is exactly what this host would render: the real compiler, the
	// current fleet, and the management floor included. Absent when no host was
	// named, because there is no such thing as a network-wide rule set — the
	// entire design compiles selectors to per-host addresses.
	Compiled *PolicyRuleset `json:"compiled,omitempty"`
}

// PolicyRuleset is one host's compiled firewall.
//
// Declared here rather than reusing policy.Ruleset directly, and that is not
// duplication for its own sake: this is the JSON shape of an HTTP response, and
// policy.Ruleset is an internal type whose field names the compiler is free to
// change. Pinning the wire names here is what stops a rename in the compiler
// from silently renaming a field every client reads.
type PolicyRuleset struct {
	Inbound  []PolicyRule `json:"inbound"`
	Outbound []PolicyRule `json:"outbound"`
}

// PolicyRule is one compiled nebula firewall rule.
//
// Four fields, matching what the compiler can emit. There is no host, groups, or
// ca_name: compiling to ADDRESSES is the entire point of the policy document —
// it is what makes an edit config-only instead of a certificate reissue — and a
// field that is always empty is one every reader has to check.
type PolicyRule struct {
	Proto string `json:"proto"`
	Port  string `json:"port"`
	CIDR  string `json:"cidr"`

	// LocalCIDR is present only when the rule names a subnet this host routes
	// rather than an address it owns. Empty is the ordinary case and is
	// meaningfully different from absent-because-unset, which is why it is
	// omitempty rather than always rendered.
	LocalCIDR string `json:"local_cidr,omitempty"`
}

// PolicyCheckHost is the host a check was scoped to.
//
// It carries the inputs a selector is resolved against — addresses, groups, the
// role — rather than a rendered rule set, because those are what an operator
// actually gets wrong: a selector that matches nothing matches nothing because
// the host's tags or addresses are not what the author assumed.
type PolicyCheckHost struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	OverlayAddrs []string `json:"overlay_addrs"`
	Tags         []string `json:"tags,omitempty"`
	RoleName     string   `json:"role_name,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	State        string   `json:"state"`
}

// FirewallSourceChangeError is the 409 body from switching a network's firewall
// source without acknowledging it.
//
// Typed for the same reason LaggingHostsError is, and the remedy is likewise not
// in the Error field: what an operator needs to see is how many hosts are about
// to have their entire rule set replaced, and that is HostsAffected.
//
// NOT a convergence gate. CA activation refuses because hosts have not caught up
// and waiting fixes it; this refuses because the change is large and
// irreversible-in-the-moment, and waiting changes nothing. Retrying with the
// acknowledgement is the only way through, which is why the message says so
// rather than suggesting a retry later.
type FirewallSourceChangeError struct {
	Error string `json:"error"`

	// From and To are the current and requested sources, so a client can render
	// the direction without inferring it.
	From string `json:"from"`
	To   string `json:"to"`

	// HostsAffected is how many enrolled or active hosts re-render their firewall
	// when this proceeds. Hosts that have never enrolled are excluded: they have
	// no configuration to replace.
	HostsAffected int `json:"hosts_affected"`

	// Detail spells out the consequence in words, worst first.
	Detail string `json:"detail,omitempty"`
}

// NetworkUpdateResponse is the body of PATCH /v1/networks/{ref}.
//
// NetworkResponse plus what only an edit knows, in the shape RoleUpdateResponse
// established. It embeds rather than restates, so a client decoding the network
// fields keeps working and a field renamed on the server is a build failure
// here rather than a silent regression.
type NetworkUpdateResponse struct {
	NetworkResponse

	// FirewallSourceChanged is false when the network was already drawing from
	// the requested source. Nothing was written and no epoch was bumped.
	FirewallSourceChanged bool `json:"firewall_source_changed"`

	// HostsAffected is how many hosts re-render on their next poll.
	HostsAffected int `json:"hosts_affected,omitempty"`

	Detail string `json:"detail,omitempty"`
}

type NetworkResponse struct {
	ID string `json:"id"`

	// Slug is how this network should be addressed in a script: immutable, so a
	// rename cannot retarget it. Name is for people.
	Slug string `json:"slug"`
	Name string `json:"name"`

	CIDRs       []string `json:"cidrs"`
	Curve       string   `json:"curve"`
	CertVersion int      `json:"cert_version"`
	CertTTL     string   `json:"cert_ttl"`

	// ListenPort is 0 when the network defers to the control plane's default.
	ListenPort int `json:"listen_port,omitempty"`

	// ConfigMode is what hosts of this network get by default. "authoritative"
	// means Orbit renders the complete nebula configuration and what it reports
	// about a host's policy is the whole of it; "fragment" means Orbit renders
	// one file into a directory nebula merges, so any policy it reports is a
	// lower bound.
	ConfigMode string `json:"config_mode,omitempty"`

	// FirewallSource is where this network's firewall rules come from: "role"
	// (per-role firewall_rules, the default) or "policy" (the compiled network
	// policy document).
	//
	// Reported rather than left implicit because it changes what every other
	// firewall-shaped field on this API MEANS. In policy mode a role's
	// `firewall` still has a value and that value is not being enforced
	// anywhere, so a client that renders a role without knowing this is showing
	// an operator rules that do nothing.
	FirewallSource string `json:"firewall_source,omitempty"`

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
