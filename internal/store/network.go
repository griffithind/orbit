package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
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

// ExpiredRetiringCAs returns CAs past their own NotAfter that are not yet
// retired.
//
// These are provably safe to retire without counting certificates: nebula
// enforces leaf.NotAfter <= ca.NotAfter (cert/ca_pool.go checkCAConstraints),
// so once a CA has expired nothing it ever signed can still be valid. Keeping
// it in the trust bundle costs bytes in every host's configuration and can
// never accept anything.
func (t *Tx) ExpiredRetiringCAs(ctx context.Context, networkID uuid.UUID, now time.Time) ([]CA, error) {
	rows, err := t.tx.Query(ctx,
		`SELECT `+caCols+` FROM orbit.ca
		  WHERE network_id = $1 AND state <> 'retired' AND not_after < $2`,
		networkID, now)
	if err != nil {
		return nil, mapErr(err, "expired retiring cas")
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
