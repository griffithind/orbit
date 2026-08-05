package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/jackc/pgx/v5"
)

// ErrSlugRequired is returned when a network's slug can be neither supplied nor
// derived. It names the parameter because the caller can fix exactly one thing.
var ErrSlugRequired = errors.New("slug is required and could not be derived from the name")

// Slugify derives a machine-safe slug from a display name.
//
// A SUGGESTION, applied only when a caller supplies no slug of its own. The two
// values are deliberately independent afterwards: the slug never changes and
// the name is free to, so deriving one from the other on every write would
// quietly reintroduce the coupling that splitting them removed.
//
// Anything outside [a-z0-9] becomes a hyphen, runs collapse, and the ends are
// trimmed — so "Prod (EU)" yields "prod-eu" and "Zürich" yields "z-rich", which
// is ugly enough to make an operator supply a better one and still valid enough
// to not fail a bootstrap at three in the morning. Truncation is to 32 with a
// second trim, because cutting mid-word can leave a trailing hyphen the charset
// constraint would then refuse.
func Slugify(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			if b.Len() > 0 && b.String()[b.Len()-1] != '-' {
				b.WriteByte('-')
			}
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 32 {
		s = strings.TrimRight(s[:32], "-")
	}
	return s
}

// CreateNetwork inserts a network.
//
// The slug is derived from the name when the caller leaves it empty, so that
// every existing creation path — POST /v1/networks, `orbitd bootstrap`, the
// test fixtures — keeps working without restating a value it has no opinion
// about. A caller that does have an opinion passes one, and it is stored
// verbatim; the database refuses anything the charset forbids.
func (t *Tx) CreateNetwork(ctx context.Context, n *Network) error {
	if n.CertVer == 0 {
		n.CertVer = 2
	}
	if n.Curve == "" {
		n.Curve = "CURVE25519"
	}
	if n.CertTTL == 0 {
		n.CertTTL = 24 * time.Hour
	}
	if n.ConfigMode == "" {
		n.ConfigMode = ConfigModeAuthoritative
	}
	if len(n.Overrides) == 0 {
		n.Overrides = []byte(`{}`)
	}
	if n.Slug == "" {
		n.Slug = Slugify(n.Name)
	}
	if n.Slug == "" {
		return fmt.Errorf("create network: %w", ErrSlugRequired)
	}
	// A network is always created drawing its firewall from roles, whatever the
	// caller put in the struct, and the column is deliberately absent from the
	// INSERT below so the database's default is the single answer.
	//
	// It cannot be otherwise: a network in policy mode renders the compiled
	// policy document, a network that does not exist yet cannot have one, and
	// nebula's firewall is default-deny — so creating one in policy mode would
	// produce a network whose every host drops all traffic from its first boot.
	// Migration 0009 refuses the insert too; this keeps the Go side from
	// silently pretending the field was honoured.
	n.FirewallSource = FirewallSourceRole

	// The network ID is DERIVED here, not accepted from the caller.
	//
	// A caller that could supply both a key and an ID could supply a pair that
	// does not correspond — and every machine that then joined by that ID would
	// verify against a key the control plane does not hold, failing in a way
	// whose cause is two fields disagreeing in a row nobody looks at. One
	// derivation, at the only moment both are in hand.
	if len(n.IdentityPublicKey) == 0 {
		return fmt.Errorf("create network: %w", ErrNoNetworkIdentity)
	}
	if n.IdentitySignerRef == "" {
		return fmt.Errorf("create network: the network identity key needs a signer ref; " +
			"the private half is never stored in the database")
	}
	networkID, err := ca.NetworkIDFor(n.IdentityPublicKey)
	if err != nil {
		return fmt.Errorf("create network: %w", err)
	}
	n.NetworkID = networkID

	err = t.tx.QueryRow(ctx, `
		INSERT INTO orbit.network (slug, name, cidrs, cert_version, curve, cert_ttl,
		                           listen_port, config_mode, config_overrides,
		                           identity_public_key, network_id, identity_signer_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, config_epoch, blocklist_epoch, created_at`,
		n.Slug, n.Name, nonNil(n.CIDRs), n.CertVer, n.Curve, n.CertTTL,
		n.ListenPort, n.ConfigMode, n.Overrides,
		n.IdentityPublicKey, n.NetworkID, n.IdentitySignerRef,
	).Scan(&n.ID, &n.ConfigEpoch, &n.BlocklistEpoch, &n.CreatedAt)
	if err != nil {
		return mapErr(err, "create network")
	}
	return nil
}

const networkCols = `id, slug, name, cidrs, cert_version, curve, cert_ttl,
	listen_port, config_mode, config_overrides, firewall_source,
	config_epoch, blocklist_epoch, created_at,
	identity_public_key, network_id, identity_signer_ref`

func scanNetwork(row interface{ Scan(...any) error }) (*Network, error) {
	var n Network
	err := row.Scan(&n.ID, &n.Slug, &n.Name, &n.CIDRs, &n.CertVer, &n.Curve, &n.CertTTL,
		&n.ListenPort, &n.ConfigMode, &n.Overrides, &n.FirewallSource,
		&n.ConfigEpoch, &n.BlocklistEpoch, &n.CreatedAt,
		&n.IdentityPublicKey, &n.NetworkID, &n.IdentitySignerRef)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func (t *Tx) GetNetwork(ctx context.Context, id uuid.UUID) (*Network, error) {
	n, err := scanNetwork(t.tx.QueryRow(ctx,
		`SELECT `+networkCols+` FROM orbit.network WHERE id = $1`, id))
	if err != nil {
		return nil, mapErr(err, "get network")
	}
	return n, nil
}

// GetNetworkBySlug resolves a network by its slug.
//
// The slug is the only string a network may be addressed by, and it is safe to
// address by because it is immutable: a script that memorised one still names
// the same network after a rename. Its predecessor, GetNetworkByName, resolved a
// MUTABLE string — which meant renaming a network for readability silently
// retargeted every caller that had memorised the old label, with no error
// anywhere.
//
// A slug can never be confused with a uuid: the charset caps it at 32
// characters and a uuid's canonical form is 36, so the two are disjoint by
// length before a character is compared. That is why the shared
// /v1/networks/{ref} route needs no constraint to keep them apart.
// GetNetworkByNetworkID resolves a network by its verifiable ID.
//
// The ID is normalised first, because it arrives from a human: Crockford base32
// is case-insensitive and treats I/L as 1 and O as 0, and people add hyphens to
// make it readable. Looking up the raw string would turn a correctly-read ID
// into "no such network".
func (t *Tx) GetNetworkByNetworkID(ctx context.Context, id string) (*Network, error) {
	norm, err := ca.ParseNetworkID(id)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, err)
	}
	n, err := scanNetwork(t.tx.QueryRow(ctx,
		`SELECT `+networkCols+` FROM orbit.network WHERE network_id = $1`, norm))
	if err != nil {
		return nil, mapErr(err, "get network by id")
	}
	return n, nil
}

func (t *Tx) GetNetworkBySlug(ctx context.Context, slug string) (*Network, error) {
	n, err := scanNetwork(t.tx.QueryRow(ctx,
		`SELECT `+networkCols+` FROM orbit.network WHERE slug = $1`, slug))
	if err != nil {
		return nil, mapErr(err, "get network by slug")
	}
	return n, nil
}

func (t *Tx) ListNetworks(ctx context.Context) ([]Network, error) {
	rows, err := t.tx.Query(ctx, `SELECT `+networkCols+` FROM orbit.network ORDER BY name`)
	if err != nil {
		return nil, mapErr(err, "list networks")
	}
	defer rows.Close()

	var out []Network
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, mapErr(err, "scan network")
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

// UpdateNetworkName changes the display label and nothing else.
//
// Safe precisely because the label addresses nothing: the id and the slug are
// what resolve, both are immutable, and neither moves here. That is the whole
// point of having three columns instead of two.
func (t *Tx) UpdateNetworkName(ctx context.Context, id uuid.UUID, name string) (*Network, error) {
	n, err := scanNetwork(t.tx.QueryRow(ctx,
		`UPDATE orbit.network SET name = $2 WHERE id = $1 RETURNING `+networkCols, id, name))
	if err != nil {
		return nil, mapErr(err, "rename network")
	}
	// No epoch bump. The name appears in no rendered configuration — renderFor
	// never reads it — so waking every agent in the network to re-fetch a
	// byte-identical fragment would make renaming a network fleet-wide work.
	return n, nil
}

// UpdateNetworkInstanceDefaults changes the per-network listen port and config
// mode. A nil field is left alone.
//
// BOTH REQUIRE A RESTART, on every host in the network, which is why this does
// more than write two columns. Nebula binds its UDP listener at startup and
// points at its config path at startup; neither moves on a reload. So a host
// handed a new port would render it, reload, and go on listening where it always
// did — with the control plane reporting a port nothing is bound to. Marking
// every live host restart-required is the same mechanism an address change uses,
// and for the same reason: the alternative is a change that silently does not
// take effect.
//
// Nothing is marked when nothing changed. A PATCH that restates the current
// values must not restart a fleet, which is the same argument RoleChange.Changed
// makes about waking one.
func (t *Tx) UpdateNetworkInstanceDefaults(ctx context.Context, id uuid.UUID, listenPort *int, configMode *string) (*Network, error) {
	before, err := t.GetNetwork(ctx, id)
	if err != nil {
		return nil, err
	}

	port := before.ListenPort
	if listenPort != nil {
		port = listenPort
	}
	mode := before.ConfigMode
	if configMode != nil {
		mode = *configMode
	}

	after, err := scanNetwork(t.tx.QueryRow(ctx, `
		UPDATE orbit.network SET listen_port = $2, config_mode = $3
		 WHERE id = $1
		   AND (listen_port, config_mode) IS DISTINCT FROM ($2::int, $3::text)
		RETURNING `+networkCols, id, port, mode))
	if errors.Is(err, pgx.ErrNoRows) {
		return before, nil // unchanged; no epoch bump, no fleet-wide restart
	}
	if err != nil {
		return nil, mapErr(err, "update network instance defaults")
	}

	epoch, err := t.BumpEpoch(ctx, id, EpochConfig)
	if err != nil {
		return nil, err
	}
	if _, err := t.tx.Exec(ctx, `
		UPDATE orbit.membership SET restart_required_epoch = $2
		 WHERE network_id = $1 AND state IN ('enrolled', 'active')`, id, epoch); err != nil {
		return nil, mapErr(err, "mark hosts restart required")
	}
	after.ConfigEpoch = epoch
	return after, nil
}

// ContainsAddr reports whether addr falls inside one of the network's prefixes.
// Used to validate a requested overlay address before allocating it.
func (n *Network) ContainsAddr(addr netip.Addr) bool {
	for _, p := range n.CIDRs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// PrefixFor returns the network prefix containing addr.
//
// The FIRST match, which is the same rule enroll.certNetworks applies when it
// decides the prefix length to embed in a certificate. The two must agree: the
// prefix length is what tells nebula whether a host can reach the overlay
// directly or treats every peer as off-net, so a disagreement here produces a
// host that enrolls and then cannot route.
func (n *Network) PrefixFor(addr netip.Addr) (netip.Prefix, bool) {
	for _, p := range n.CIDRs {
		if p.Contains(addr) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

//------------------------------------------------------------------------------
// Network prefixes
//------------------------------------------------------------------------------

// ErrCIDRInUse is returned when a prefix cannot be removed because hosts hold
// addresses inside it.
var ErrCIDRInUse = errors.New("hosts hold addresses in this prefix")

// ErrCIDROverlap is returned when a prefix would overlap one the network
// already has.
var ErrCIDROverlap = errors.New("prefix overlaps one this network already has")

// ErrLastCIDR is returned when removing a prefix would leave a network with
// none.
var ErrLastCIDR = errors.New("a network must keep at least one prefix")

// AddNetworkCIDR appends a prefix.
//
// Overlap is refused. enroll.certNetworks pairs each host address with the
// FIRST network prefix that contains it, so two overlapping prefixes make the
// certificate a host is issued depend on array order — 10.42.0.7/16 and
// 10.42.0.7/24 are materially different certificates, and the difference
// decides whether the host routes to the rest of the overlay or treats every
// peer as off-net. Nothing about that would fail loudly; it would surface as
// one host that enrolled fine and cannot reach anything.
//
// NO CONFIG EPOCH BUMP, and this was checked rather than assumed: renderFor
// builds nebulacfg.Input out of the topology, the blocklist, the trust bundle
// and the host's role, and the network's prefixes appear in none of them. They
// reach a host only through the certificate, and only at issuance. Bumping
// would wake every agent in the network to re-render a byte-identical file.
func (t *Tx) AddNetworkCIDR(ctx context.Context, id uuid.UUID, p netip.Prefix) (*Network, error) {
	net, err := t.GetNetwork(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, existing := range net.CIDRs {
		if existing == p {
			return net, nil // idempotent
		}
		if existing.Overlaps(p) {
			return nil, fmt.Errorf("%w: %s overlaps %s", ErrCIDROverlap, p, existing)
		}
	}

	out, err := scanNetwork(t.tx.QueryRow(ctx,
		`UPDATE orbit.network SET cidrs = cidrs || $2::cidr WHERE id = $1
		 RETURNING `+networkCols, id, p))
	if err != nil {
		return nil, mapErr(err, "add network cidr")
	}
	return out, nil
}

// AddressHolder is a host holding an address inside some prefix.
type AddressHolder struct {
	MembershipID uuid.UUID
	Name         string
	Addr         netip.Addr
}

// CIDRHolders lists the hosts with an address inside a prefix.
//
// Answers the only question an operator has when a removal is refused. Deleted
// hosts are included for the same reason RoleHosts includes them: their
// membership_address rows still exist and still block the removal, so a blocker list
// that omitted them would report an empty set for a refusal.
func (t *Tx) CIDRHolders(ctx context.Context, networkID uuid.UUID, p netip.Prefix) ([]AddressHolder, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT a.membership_id, h.name, a.addr
		  FROM orbit.membership_address a
		  JOIN orbit.membership h ON (h.network_id, h.id) = (a.network_id, a.membership_id)
		 WHERE a.network_id = $1 AND a.addr <<= $2::cidr
		 ORDER BY h.name, a.addr`, networkID, p)
	if err != nil {
		return nil, mapErr(err, "cidr holders")
	}
	defer rows.Close()

	var out []AddressHolder
	for rows.Next() {
		var h AddressHolder
		if err := rows.Scan(&h.MembershipID, &h.Name, &h.Addr); err != nil {
			return nil, mapErr(err, "scan cidr holder")
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RemoveNetworkCIDR drops a prefix no host has an address in.
//
// Refused while any host holds one, because removing it does not take the
// address away — the membership_address row survives, the host keeps answering on it,
// and the damage appears at the host's NEXT RENEWAL, when certNetworks can no
// longer pair the address with a prefix and issuance fails. That is hours after
// the request that caused it, on a host nobody is looking at.
//
// Also refused when it is the last prefix: a network with no address space can
// hold no host that can be issued a certificate.
func (t *Tx) RemoveNetworkCIDR(ctx context.Context, id uuid.UUID, p netip.Prefix) (*Network, error) {
	net, err := t.GetNetwork(ctx, id)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(net.CIDRs, p) {
		return nil, fmt.Errorf("remove network cidr: %w: %s", ErrNotFound, p)
	}
	if len(net.CIDRs) == 1 {
		return nil, fmt.Errorf("%w: %s is the only prefix of network %s", ErrLastCIDR, p, net.Slug)
	}

	holders, err := t.CIDRHolders(ctx, id, p)
	if err != nil {
		return nil, err
	}
	if len(holders) > 0 {
		return nil, fmt.Errorf("%w: %d host(s) inside %s", ErrCIDRInUse, len(holders), p)
	}

	out, err := scanNetwork(t.tx.QueryRow(ctx,
		`UPDATE orbit.network SET cidrs = array_remove(cidrs, $2::cidr) WHERE id = $1
		 RETURNING `+networkCols, id, p))
	if err != nil {
		return nil, mapErr(err, "remove network cidr")
	}
	// No epoch bump, for the same reason AddNetworkCIDR does not bump: prefixes
	// reach a host through its certificate and nowhere else, and by the check
	// above no host has one issued out of this prefix.
	return out, nil
}

//------------------------------------------------------------------------------
// Certificate authorities
//------------------------------------------------------------------------------

// CreateCA records a CA and publishes it to every host's trust bundle.
//
// Inserted 'pending': it is distributed but not yet signing. That split is the
// whole point of rotation — hosts must trust a CA before it starts issuing, or
// promoting it cuts off everyone who has not caught up.
//
// The config epoch bump is not optional and is why this is not a plain INSERT.
// Without it a pending CA sits in the database, never reaches a single trust
// bundle, and convergence reports 100% because nothing changed. An operator
// would then promote it and partition the entire fleet — the exact failure the
// pending state exists to prevent.
func (t *Tx) CreateCA(ctx context.Context, c *CA) error {
	if c.State == "" {
		c.State = CAPending
	}
	err := t.tx.QueryRow(ctx, `
		INSERT INTO orbit.ca (network_id, name, fingerprint, cert_pem,
		                      signer_ref, curve, not_before, not_after, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at`,
		c.NetworkID, c.Name, c.Fingerprint, c.CertPEM,
		c.SignerRef, c.Curve, c.NotBefore, c.NotAfter, c.State,
	).Scan(&c.ID, &c.CreatedAt)
	if err != nil {
		return mapErr(err, "create ca")
	}

	_, err = t.BumpEpoch(ctx, c.NetworkID, EpochConfig)
	return err
}

const caCols = `id, network_id, name, fingerprint, cert_pem, signer_ref,
	curve, not_before, not_after, state, created_at`

func (t *Tx) scanCA(row interface{ Scan(...any) error }) (*CA, error) {
	var c CA
	err := row.Scan(&c.ID, &c.NetworkID, &c.Name, &c.Fingerprint,
		&c.CertPEM, &c.SignerRef, &c.Curve, &c.NotBefore, &c.NotAfter, &c.State, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// GetActiveCA returns the CA currently signing for a network.
//
// Returns ErrNoActived rather than ErrNotFound when a network exists but has no
// active CA, because those demand different operator responses: the first means
// rotation is incomplete or overdue, the second means a bad id.
func (t *Tx) GetActiveCA(ctx context.Context, networkID uuid.UUID) (*CA, error) {
	c, err := t.scanCA(t.tx.QueryRow(ctx,
		`SELECT `+caCols+` FROM orbit.ca WHERE network_id = $1 AND state = 'active'`,
		networkID))
	if err != nil {
		mapped := mapErr(err, "get active ca")
		if errors.Is(mapped, ErrNotFound) {
			return nil, ErrNoActived
		}
		return nil, mapped
	}
	return c, nil
}

// ListCAs returns every CA for a network, newest first. The trust bundle
// distributed to hosts is built from all CAs that are not yet retired, which is
// what makes rotation overlap safe.
func (t *Tx) ListCAs(ctx context.Context, networkID uuid.UUID) ([]CA, error) {
	rows, err := t.tx.Query(ctx,
		`SELECT `+caCols+` FROM orbit.ca WHERE network_id = $1 ORDER BY created_at DESC`,
		networkID)
	if err != nil {
		return nil, mapErr(err, "list cas")
	}
	defer rows.Close()

	var out []CA
	for rows.Next() {
		c, err := t.scanCA(rows)
		if err != nil {
			return nil, mapErr(err, "scan ca")
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// TrustBundlePEM returns the concatenated PEM of every CA a host should trust:
// everything except retired. Publishing a new CA here and waiting for
// convergence is step 2 of rotation (docs/design.md 6).
func (t *Tx) TrustBundlePEM(ctx context.Context, networkID uuid.UUID) (string, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT cert_pem FROM orbit.ca
		 WHERE network_id = $1 AND state <> 'retired'
		 ORDER BY created_at`, networkID)
	if err != nil {
		return "", mapErr(err, "trust bundle")
	}
	defer rows.Close()

	var bundle string
	for rows.Next() {
		var pem string
		if err := rows.Scan(&pem); err != nil {
			return "", mapErr(err, "scan ca pem")
		}
		bundle += pem
	}
	return bundle, rows.Err()
}

// ActivateCA promotes a CA to active, demoting any currently-active CA in the
// same network to 'retiring', and bumps the config epoch.
//
// Demotion and promotion are one statement pair in one transaction because the
// partial unique index ca_one_active_per_network would otherwise reject the
// promotion. That constraint is deliberate: two CAs simultaneously believing
// they are the signer is a state from which issuance is ambiguous.
//
// This does NOT check convergence. The gate belongs at the API layer, where an
// emergency rotation after a key compromise can consciously override it; a
// store method that refused would make that override impossible to express.
func (t *Tx) ActivateCA(ctx context.Context, networkID, caID uuid.UUID) error {
	if _, err := t.tx.Exec(ctx, `
		UPDATE orbit.ca SET state = 'retiring'
		 WHERE network_id = $1 AND state = 'active' AND id <> $2`,
		networkID, caID); err != nil {
		return mapErr(err, "demote active ca")
	}

	tag, err := t.tx.Exec(ctx, `
		UPDATE orbit.ca SET state = 'active'
		 WHERE id = $1 AND network_id = $2 AND state IN ('pending', 'retiring')`,
		caID, networkID)
	if err != nil {
		return mapErr(err, "activate ca")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	_, err = t.BumpEpoch(ctx, networkID, EpochConfig)
	return err
}

//------------------------------------------------------------------------------
// Roles
//------------------------------------------------------------------------------

func (t *Tx) CreateRole(ctx context.Context, r *Role) error {
	if len(r.FirewallRules) == 0 {
		r.FirewallRules = []byte(`{}`)
	}
	err := t.tx.QueryRow(ctx, `
		INSERT INTO orbit.role (network_id, name, groups, firewall_rules)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at`,
		r.NetworkID, r.Name, nonNil(r.Groups), r.FirewallRules,
	).Scan(&r.ID, &r.CreatedAt)
	return mapErr(err, "create role")
}

func (t *Tx) GetRole(ctx context.Context, id uuid.UUID) (*Role, error) {
	var r Role
	err := t.tx.QueryRow(ctx, `
		SELECT id, network_id, name, groups, firewall_rules, created_at
		  FROM orbit.role WHERE id = $1`, id,
	).Scan(&r.ID, &r.NetworkID, &r.Name, &r.Groups, &r.FirewallRules, &r.CreatedAt)
	if err != nil {
		return nil, mapErr(err, "get role")
	}
	return &r, nil
}

// Audit actions for role edits.
//
// Declared beside the role store functions rather than with their siblings in
// audit.go for the same reason ActionConfigReverted is declared in host.go:
// what matters about them is the split, and the split is only legible next to
// the code that explains it.
//
// RoleGroupsChangedAt reports when a role's groups last changed, or nil if they
// never have.
//
// Read on the agent's state poll, so it is one indexed primary-key lookup and
// nothing more. The value it feeds is a renewal hint, not an authorization
// decision: being wrong makes a host renew sooner than it needed to, which
// costs one signature.
func (t *Tx) RoleGroupsChangedAt(ctx context.Context, roleID uuid.UUID) (*time.Time, error) {
	var at *time.Time
	err := t.tx.QueryRow(ctx,
		`SELECT groups_changed_at FROM orbit.role WHERE id = $1`, roleID).Scan(&at)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapErr(err, "role groups changed at")
	}
	return at, nil
}

// ActionRoleGroupsChanged is not ActionRoleUpdated with a flag in the metadata.
// A firewall edit is live within seconds; a group edit is not in force until
// every host has renewed its certificate, which is hours. "Which policy changes
// were not yet in force at time T" is the question an incident review asks, and
// it should be a WHERE clause rather than a scan through metadata. Same
// reasoning as ca.force_activated being distinct from ca.activated.
const (
	ActionRoleUpdated       = "role.updated"
	ActionRoleGroupsChanged = "role.groups_changed"
	ActionRoleDeleted       = "role.deleted"
)

// RoleUpdate is a partial edit to a role. A nil field is left as it is.
//
// Absolute values rather than a delta, so two concurrent edits cannot compose
// into a state neither operator asked for. That also makes an edit that
// restates the current value a no-op rather than a change, which is what
// UpdateRole reports.
type RoleUpdate struct {
	Name   *string
	Groups *[]string
	// Firewall replaces the rule set wholesale. Merging would make "remove
	// this rule" inexpressible, and a rule an operator believes they deleted is
	// the worst possible outcome for a firewall.
	Firewall *[]byte
}

// RoleChange describes what an edit actually did.
type RoleChange struct {
	Before Role
	After  Role

	// Changed is false when the supplied values already matched what was
	// stored. The caller must not bump the config epoch in that case: a bump
	// wakes every agent in the network to fetch and re-render a fragment, so a
	// no-op PATCH that bumped would make the safest thing an operator can do —
	// re-run a reconcile loop, retry a request that may not have landed —
	// fleet-wide work. Same reasoning as SetHostRoles.
	Changed bool

	// GroupsChanged is reported separately from Changed because it costs
	// something entirely different.
	//
	// Firewall rules are configuration: they reach every host on its next poll
	// and converge in seconds. Groups are embedded in the signed certificate
	// (enroll.issueAndRender reads them from the role at issuance), so every
	// host carrying this role keeps the OLD set until it happens to renew, on
	// its own schedule, at the midpoint of its certificate's lifetime. Nothing
	// here shortens that. A caller that presents the two as one operation is
	// telling an operator a policy change has taken effect when it has not.
	GroupsChanged bool
}

// UpdateRole applies a partial edit and reports what it did.
//
// The row is locked for the read so Before and After describe one transition
// rather than two that interleaved. Without it a concurrent edit landing
// between the read and the write would make GroupsChanged report on a
// transition that never happened.
//
// The write itself is conditional — `IS DISTINCT FROM` — rather than
// unconditional plus a comparison in Go. That matters for firewall_rules
// specifically: the column is jsonb, so the database compares it semantically,
// and a client that re-sends the same rules with different key order or
// whitespace is correctly recognised as changing nothing. A []byte comparison
// in Go would call that an edit and bump the epoch for it.
func (t *Tx) UpdateRole(ctx context.Context, id uuid.UUID, u RoleUpdate) (*RoleChange, error) {
	var before Role
	err := t.tx.QueryRow(ctx, `
		SELECT id, network_id, name, groups, firewall_rules, created_at
		  FROM orbit.role WHERE id = $1 FOR UPDATE`, id,
	).Scan(&before.ID, &before.NetworkID, &before.Name, &before.Groups,
		&before.FirewallRules, &before.CreatedAt)
	if err != nil {
		return nil, mapErr(err, "get role for update")
	}

	after := before
	if u.Name != nil {
		after.Name = *u.Name
	}
	if u.Groups != nil {
		after.Groups = *u.Groups
	}
	if u.Firewall != nil {
		after.FirewallRules = *u.Firewall
	}
	if len(after.FirewallRules) == 0 {
		after.FirewallRules = []byte(`{}`)
	}

	var stored []byte
	err = t.tx.QueryRow(ctx, `
		UPDATE orbit.role
		   SET name = $2, groups = $3, firewall_rules = $4,
		       -- Stamped only when the groups themselves move, in the same
		       -- statement that moves them so the two cannot disagree. This is
		       -- what enroll.Service.State compares a certificate's issued_at
		       -- against to decide whether to pull a host's renewal forward:
		       -- groups live inside the signed certificate, so a host holding
		       -- one issued before this instant is presenting a group set the
		       -- role no longer has.
		       groups_changed_at = CASE
		           WHEN groups IS DISTINCT FROM $3::text[] THEN now()
		           ELSE groups_changed_at END
		 WHERE id = $1
		   AND (name, groups, firewall_rules)
		       IS DISTINCT FROM ($2::text, $3::text[], $4::jsonb)
		RETURNING firewall_rules`,
		id, after.Name, nonNil(after.Groups), after.FirewallRules,
	).Scan(&stored)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Nothing to write. Return the stored row unchanged so the caller
		// reports what is actually there rather than the request it was sent.
		return &RoleChange{Before: before, After: before}, nil
	case err != nil:
		return nil, mapErr(err, "update role")
	}
	after.FirewallRules = stored

	// Order-sensitive, deliberately. Nebula treats groups as a set, so a
	// reorder is semantically nothing — but normalizing here would disagree
	// with what CreateRole stored, and every read-modify-write client echoes
	// back the order it was given, so the exact comparison has no false
	// positives in practice and needs no normalization rule to explain.
	return &RoleChange{
		Before: before, After: after, Changed: true,
		GroupsChanged: !slices.Equal(before.Groups, after.Groups),
	}, nil
}

// RoleHost is a host carrying a role, with the certificate it is currently
// presenting.
type RoleHost struct {
	ID    uuid.UUID
	Name  string
	State string

	// CertNotBefore and CertNotAfter are the window of the certificate the host
	// leads with, and are zero when it holds none. A host that has not enrolled
	// yet has no stale groups to carry: it will be issued the role's current
	// ones the first time it asks.
	CertNotBefore time.Time
	CertNotAfter  time.Time
}

// RoleHosts returns every host carrying a role.
//
// Two callers with one query, because they need the same rows for opposite
// reasons: an edit that changes groups needs to know how many certificates are
// now stale and when the last of them renews, and a delete needs to know which
// hosts the schema's ON DELETE RESTRICT will refuse it for.
//
// Deleted hosts are included. They still hold role_id, so they still block a
// delete, and a blocker list that omitted them would report an empty set for a
// delete the database then refuses.
func (t *Tx) RoleHosts(ctx context.Context, roleID uuid.UUID) ([]RoleHost, error) {
	// The highest cert_version is the one the host leads with, matching what
	// enroll.State reports as its renewal deadline. A host mid-migration holds
	// a v1 and a v2 certificate and both carry the role's groups, but both are
	// reissued by the same renewal, so the leading one dates the convergence.
	rows, err := t.tx.Query(ctx, `
		SELECT h.id, h.name, h.state, c.not_before, c.not_after
		  FROM orbit.membership h
		  LEFT JOIN LATERAL (
		      SELECT not_before, not_after
		        FROM orbit.certificate
		       WHERE membership_id = h.id AND state = 'active'
		       ORDER BY cert_version DESC
		       LIMIT 1
		  ) c ON true
		 WHERE h.role_id = $1
		 ORDER BY h.name`, roleID)
	if err != nil {
		return nil, mapErr(err, "role hosts")
	}
	defer rows.Close()

	var out []RoleHost
	for rows.Next() {
		var (
			h      RoleHost
			nb, na *time.Time
		)
		if err := rows.Scan(&h.ID, &h.Name, &h.State, &nb, &na); err != nil {
			return nil, mapErr(err, "scan role host")
		}
		if nb != nil && na != nil {
			h.CertNotBefore, h.CertNotAfter = *nb, *na
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ErrRoleInUse is returned when a role still has hosts assigned to it.
var ErrRoleInUse = errors.New("role is still assigned to hosts")

// DeleteRole removes a role that no host carries.
//
// The schema already refuses the dangerous case: host.role_id is ON DELETE
// RESTRICT, so a role in use cannot be deleted no matter what this function
// does. The check here exists because of what the refusal would otherwise look
// like — mapErr renders a foreign key violation as ErrNotFound, which would
// tell an operator the role does not exist when the truth is that fourteen
// hosts are using it. Re-role those hosts first.
func (t *Tx) DeleteRole(ctx context.Context, id uuid.UUID) error {
	hosts, err := t.RoleHosts(ctx, id)
	if err != nil {
		return err
	}
	if len(hosts) > 0 {
		return fmt.Errorf("%w: %d host(s) still carry it", ErrRoleInUse, len(hosts))
	}

	tag, err := t.tx.Exec(ctx, `DELETE FROM orbit.role WHERE id = $1`, id)
	if err != nil {
		return mapErr(err, "delete role")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

//------------------------------------------------------------------------------
// Topology
//------------------------------------------------------------------------------

// TopologyHost is a lighthouse or relay other hosts need to know about.
type TopologyHost struct {
	ID           uuid.UUID
	Name         string
	Addrs        []netip.Addr
	IsLighthouse bool
	IsRelay      bool

	// The pieces StaticAddrs is made of, kept apart because the port's default
	// is resolved outside this package. See NetworkTopology.
	PublicAddrs       []string
	AdvertisePort     *int
	ListenPort        *int
	NetworkListenPort *int
}

// StaticAddrs is what other machines dial to reach this one: every public
// address of the DEVICE, paired with the port of THIS membership.
//
// defaultPort is the control plane's own default, the last of four levels:
// the membership's advertise_port, its listen_port, the network's, then this.
// Resolving it here rather than in SQL keeps one implementation — an agent that
// dialled a port the lighthouse never bound would fail with no error anywhere,
// just a mesh that does not form.
//
// AdvertisePort wins outright when set: it exists for the machine behind
// port-forwarding, where the port that reaches it is deliberately not the port
// it binds.
func (h TopologyHost) StaticAddrs(defaultPort int) []string {
	port := defaultPort
	switch {
	case h.AdvertisePort != nil:
		port = *h.AdvertisePort
	case h.ListenPort != nil:
		port = *h.ListenPort
	case h.NetworkListenPort != nil:
		port = *h.NetworkListenPort
	}
	out := make([]string, 0, len(h.PublicAddrs))
	for _, a := range h.PublicAddrs {
		// JoinHostPort, not concatenation: a bare IPv6 address needs brackets
		// and nebula rejects the form without them.
		out = append(out, net.JoinHostPort(a, strconv.Itoa(port)))
	}
	return out
}

// NetworkTopology returns only the lighthouses and relays in a network.
//
// Every agent poll needs this to render a configuration, so it must not be
// ListHosts with a filter applied in Go: that would transfer the entire host
// table on every request and make a large network quadratically expensive to
// operate. Lighthouses and relays are a small, slowly-changing subset.
func (t *Tx) NetworkTopology(ctx context.Context, networkID uuid.UUID) ([]TopologyHost, error) {
	// The ADDRESSES and the PORT come back separately and are joined in Go.
	//
	// They have to be: the port is a three-level default — the membership's, the
	// network's, then the control plane's — and the last of those is a flag this
	// package cannot see. Deriving in SQL would resolve two levels and silently
	// produce nothing for a lighthouse relying on the third.
	rows, err := t.tx.Query(ctx, `
		SELECT h.id, h.name, d.public_addrs, h.advertise_port, h.listen_port, n.listen_port,
		       h.is_lighthouse, h.is_relay,
		       coalesce(array(SELECT a.addr FROM orbit.membership_address a
		                       WHERE a.membership_id = h.id ORDER BY a.addr), '{}')
		  FROM orbit.membership h
		  JOIN orbit.device d ON d.id = h.device_id
		  JOIN orbit.network n ON n.id = h.network_id
		 WHERE h.network_id = $1
		   AND (h.is_lighthouse OR h.is_relay)
		   AND h.state IN ('enrolled', 'active')
		 ORDER BY h.name`, networkID)
	if err != nil {
		return nil, mapErr(err, "network topology")
	}
	defer rows.Close()

	var out []TopologyHost
	for rows.Next() {
		var h TopologyHost
		if err := rows.Scan(&h.ID, &h.Name, &h.PublicAddrs,
			&h.AdvertisePort, &h.ListenPort, &h.NetworkListenPort,
			&h.IsLighthouse, &h.IsRelay, &h.Addrs); err != nil {
			return nil, mapErr(err, "scan topology host")
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ListRoles returns every role in a network.
func (t *Tx) ListRoles(ctx context.Context, networkID uuid.UUID) ([]Role, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT id, network_id, name, groups, firewall_rules, created_at
		  FROM orbit.role WHERE network_id = $1 ORDER BY name`, networkID)
	if err != nil {
		return nil, mapErr(err, "list roles")
	}
	defer rows.Close()

	var out []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.NetworkID, &r.Name, &r.Groups, &r.FirewallRules, &r.CreatedAt); err != nil {
			return nil, mapErr(err, "scan role")
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetCA fetches one certificate authority by id.
func (t *Tx) GetCA(ctx context.Context, id uuid.UUID) (*CA, error) {
	c, err := t.scanCA(t.tx.QueryRow(ctx, `SELECT `+caCols+` FROM orbit.ca WHERE id = $1`, id))
	if err != nil {
		return nil, mapErr(err, "get ca")
	}
	return c, nil
}

//------------------------------------------------------------------------------
// Control plane registry
//------------------------------------------------------------------------------

// ControlPlane is one replica serving the agent API on a network.
type ControlPlane struct {
	MembershipID uuid.UUID
	Addr         netip.Addr
	AgentPort    int
	LastSeenAt   time.Time
}

// RegisterControlPlane records or refreshes this replica's agent endpoint.
//
// Upsert on (network_id, addr): a replica restarting on the same address
// refreshes its row rather than colliding, and two replicas cannot claim one
// address because the membership_address constraint already stopped them earlier.
func (t *Tx) RegisterControlPlane(ctx context.Context, networkID, membershipID uuid.UUID, addr netip.Addr, agentPort int) error {
	_, err := t.tx.Exec(ctx, `
		INSERT INTO orbit.control_plane (network_id, membership_id, addr, agent_port)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (network_id, addr) DO UPDATE
		   SET last_seen_at = now(), agent_port = EXCLUDED.agent_port,
		       membership_id = EXCLUDED.membership_id`,
		networkID, membershipID, addr, agentPort)
	return mapErr(err, "register control plane")
}

// LiveControlPlanes returns replicas that have heartbeated recently.
//
// Ordered by address rather than recency so every agent receives the same list
// in the same order. Agents then rotate through it themselves, which spreads
// load without the control plane having to coordinate anything.
func (t *Tx) LiveControlPlanes(ctx context.Context, networkID uuid.UUID, since time.Time) ([]ControlPlane, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT membership_id, addr, agent_port, last_seen_at
		  FROM orbit.control_plane
		 WHERE network_id = $1 AND last_seen_at > $2
		 ORDER BY addr`, networkID, since)
	if err != nil {
		return nil, mapErr(err, "live control planes")
	}
	defer rows.Close()

	var out []ControlPlane
	for rows.Next() {
		var c ControlPlane
		if err := rows.Scan(&c.MembershipID, &c.Addr, &c.AgentPort, &c.LastSeenAt); err != nil {
			return nil, mapErr(err, "scan control plane")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PruneControlPlanes removes replicas that stopped heartbeating.
func (t *Tx) PruneControlPlanes(ctx context.Context, networkID uuid.UUID, before time.Time) (int64, error) {
	tag, err := t.tx.Exec(ctx,
		`DELETE FROM orbit.control_plane WHERE network_id = $1 AND last_seen_at < $2`,
		networkID, before)
	if err != nil {
		return 0, mapErr(err, "prune control planes")
	}
	return tag.RowsAffected(), nil
}

// ActiveCertificateCount reports how many live certificates a CA signed.
//
// Retirement is safe only when this is zero: retiring drops the CA from every
// trust bundle, and a host still presenting a certificate it signed would stop
// verifying against its peers.
func (t *Tx) ActiveCertificateCount(ctx context.Context, caID uuid.UUID) (int, error) {
	var n int
	err := t.tx.QueryRow(ctx, `
		SELECT count(*) FROM orbit.certificate
		 WHERE ca_id = $1 AND state = 'active'`, caID).Scan(&n)
	if err != nil {
		return 0, mapErr(err, "count active certificates")
	}
	return n, nil
}

// ErrCAInUse is returned when a CA still has live certificates.
var ErrCAInUse = errors.New("certificate authority still has active certificates")

// RetireCA removes a CA from distribution, completing a rotation.
//
// Refuses while any certificate it signed is still active. That check is the
// difference between finishing a rotation and silently invalidating whichever
// hosts had not yet renewed.
func (t *Tx) RetireCA(ctx context.Context, caID uuid.UUID) error {
	c, err := t.GetCA(ctx, caID)
	if err != nil {
		return err
	}
	if c.State == CARetired {
		return nil // idempotent
	}
	if c.State == CAActive {
		return fmt.Errorf("%w: %s is the active CA; promote a replacement first", ErrCAInUse, c.Name)
	}

	n, err := t.ActiveCertificateCount(ctx, caID)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: %d certificate(s) signed by %s are still active", ErrCAInUse, n, c.Name)
	}

	if _, err := t.tx.Exec(ctx,
		`UPDATE orbit.ca SET state = 'retired' WHERE id = $1`, caID); err != nil {
		return mapErr(err, "retire ca")
	}

	// Retirement changes the trust bundle, so every host needs the new one.
	_, err = t.BumpEpoch(ctx, c.NetworkID, EpochConfig)
	return err
}

// ExpiredInactiveCAs returns pending and retiring CAs past their own NotAfter.
//
// These are provably safe to retire without counting certificates: nebula
// enforces leaf.NotAfter <= ca.NotAfter (cert/ca_pool.go checkCAConstraints),
// so once a CA has expired nothing it ever signed can still be valid. Keeping
// it in the trust bundle costs bytes in every host's configuration and can
// never accept anything.
//
// The active CA is excluded even when it has expired, which is why this is not
// the shorter `state <> 'retired'`. Retiring the signer is a rotation step, not
// cleanup, and doing it automatically is unsafe in both directions. If the CA
// really has expired, retiring it buys nothing — issuance already fails at
// ca.ValidityFor — but it erases which CA was signing, and ActivateCA promotes
// only from 'pending' or 'retiring', so no API call undoes it. If it only looks
// expired, because this process's clock is wrong, the sweep drops a live signer
// out of every host's trust bundle and partitions the fleet. RetireCA refuses
// the same transition for the same reason. sched.Sweep reports the state
// instead and leaves the decision to an operator.
func (t *Tx) ExpiredInactiveCAs(ctx context.Context, networkID uuid.UUID, now time.Time) ([]CA, error) {
	rows, err := t.tx.Query(ctx,
		`SELECT `+caCols+` FROM orbit.ca
		  WHERE network_id = $1 AND state IN ('pending', 'retiring') AND not_after < $2`,
		networkID, now)
	if err != nil {
		return nil, mapErr(err, "expired inactive cas")
	}
	defer rows.Close()

	var out []CA
	for rows.Next() {
		c, err := t.scanCA(rows)
		if err != nil {
			return nil, mapErr(err, "scan ca")
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ForceRetireCA retires a CA without the active-certificate check.
//
// Only for CAs that have expired, where the check is redundant. Not exported to
// the API: an operator who wants to drop a live CA should promote a replacement
// and let the certificates roll.
func (t *Tx) ForceRetireCA(ctx context.Context, caID, networkID uuid.UUID) error {
	if _, err := t.tx.Exec(ctx,
		`UPDATE orbit.ca SET state = 'retired' WHERE id = $1`, caID); err != nil {
		return mapErr(err, "force retire ca")
	}
	_, err := t.BumpEpoch(ctx, networkID, EpochConfig)
	return err
}
