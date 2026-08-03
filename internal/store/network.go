package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateNetwork inserts a network.
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

	err := t.tx.QueryRow(ctx, `
		INSERT INTO orbit.network (name, cidrs, cert_version, curve, cert_ttl)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, config_epoch, blocklist_epoch, created_at`,
		n.Name, nonNil(n.CIDRs), n.CertVer, n.Curve, n.CertTTL,
	).Scan(&n.ID, &n.ConfigEpoch, &n.BlocklistEpoch, &n.CreatedAt)
	if err != nil {
		return mapErr(err, "create network")
	}
	return nil
}

const networkCols = `id, name, cidrs, cert_version, curve, cert_ttl,
	config_epoch, blocklist_epoch, created_at`

func (t *Tx) GetNetwork(ctx context.Context, id uuid.UUID) (*Network, error) {
	var n Network
	err := t.tx.QueryRow(ctx,
		`SELECT `+networkCols+` FROM orbit.network WHERE id = $1`, id,
	).Scan(&n.ID, &n.Name, &n.CIDRs, &n.CertVer, &n.Curve, &n.CertTTL,
		&n.ConfigEpoch, &n.BlocklistEpoch, &n.CreatedAt)
	if err != nil {
		return nil, mapErr(err, "get network")
	}
	return &n, nil
}

func (t *Tx) ListNetworks(ctx context.Context) ([]Network, error) {
	rows, err := t.tx.Query(ctx, `SELECT `+networkCols+` FROM orbit.network ORDER BY name`)
	if err != nil {
		return nil, mapErr(err, "list networks")
	}
	defer rows.Close()

	var out []Network
	for rows.Next() {
		var n Network
		if err := rows.Scan(&n.ID, &n.Name, &n.CIDRs, &n.CertVer, &n.Curve,
			&n.CertTTL, &n.ConfigEpoch, &n.BlocklistEpoch, &n.CreatedAt); err != nil {
			return nil, mapErr(err, "scan network")
		}
		out = append(out, n)
	}
	return out, rows.Err()
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
		  FROM orbit.host h
		  LEFT JOIN LATERAL (
		      SELECT not_before, not_after
		        FROM orbit.certificate
		       WHERE host_id = h.id AND state = 'active'
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
	StaticAddrs  []string
	IsLighthouse bool
	IsRelay      bool
}

// NetworkTopology returns only the lighthouses and relays in a network.
//
// Every agent poll needs this to render a configuration, so it must not be
// ListHosts with a filter applied in Go: that would transfer the entire host
// table on every request and make a large network quadratically expensive to
// operate. Lighthouses and relays are a small, slowly-changing subset.
func (t *Tx) NetworkTopology(ctx context.Context, networkID uuid.UUID) ([]TopologyHost, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT h.id, h.name, h.static_addrs, h.is_lighthouse, h.is_relay,
		       coalesce(array(SELECT a.addr FROM orbit.host_address a
		                       WHERE a.host_id = h.id ORDER BY a.addr), '{}')
		  FROM orbit.host h
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
		if err := rows.Scan(&h.ID, &h.Name, &h.StaticAddrs,
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
	HostID     uuid.UUID
	Addr       netip.Addr
	AgentPort  int
	LastSeenAt time.Time
}

// RegisterControlPlane records or refreshes this replica's agent endpoint.
//
// Upsert on (network_id, addr): a replica restarting on the same address
// refreshes its row rather than colliding, and two replicas cannot claim one
// address because the host_address constraint already stopped them earlier.
func (t *Tx) RegisterControlPlane(ctx context.Context, networkID, hostID uuid.UUID, addr netip.Addr, agentPort int) error {
	_, err := t.tx.Exec(ctx, `
		INSERT INTO orbit.control_plane (network_id, host_id, addr, agent_port)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (network_id, addr) DO UPDATE
		   SET last_seen_at = now(), agent_port = EXCLUDED.agent_port,
		       host_id = EXCLUDED.host_id`,
		networkID, hostID, addr, agentPort)
	return mapErr(err, "register control plane")
}

// LiveControlPlanes returns replicas that have heartbeated recently.
//
// Ordered by address rather than recency so every agent receives the same list
// in the same order. Agents then rotate through it themselves, which spreads
// load without the control plane having to coordinate anything.
func (t *Tx) LiveControlPlanes(ctx context.Context, networkID uuid.UUID, since time.Time) ([]ControlPlane, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT host_id, addr, agent_port, last_seen_at
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
		if err := rows.Scan(&c.HostID, &c.Addr, &c.AgentPort, &c.LastSeenAt); err != nil {
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
