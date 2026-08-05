package store

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Routes: prefixes a gateway offers that are not in the overlay.
//
// The table is intent; the certificate is authority. Nebula requires a
// gateway's certificate to carry the prefix in its unsafe networks, so a row
// here reaches nobody until a certificate signed by a CA that permits it says
// the same thing. See migration 0024 and internal/ca.
//
// Nothing in this file checks that. It cannot: the CA constraint is enforced at
// signing time by internal/ca.Issuer, which is where it belongs — one place,
// holding the key, refusing rather than reporting. A route stored here that the
// CA will not permit is a legible mistake (the enrollment fails and says so),
// not a silent one.

const routeCols = `r.id, r.network_id, r.membership_id, r.prefix, r.weight,
	r.masquerade, r.install, r.mtu, r.created_at`

// CreateRoute records that a membership offers a prefix.
//
// Bumps the config epoch, because every other machine's rendered configuration
// changes: a new gateway is a new `via` entry in their unsafe_routes. Adding a
// route nobody is told about would be a row that does nothing.
func (t *Tx) CreateRoute(ctx context.Context, r *Route) error {
	if r.Weight == 0 {
		r.Weight = 1
	}
	err := t.tx.QueryRow(ctx, `
		INSERT INTO orbit.route (network_id, membership_id, prefix, weight,
		                         masquerade, install, mtu)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		r.NetworkID, r.MembershipID, r.Prefix, r.Weight,
		r.Masquerade, r.Install, r.MTU,
	).Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return mapErr(err, "create route")
	}
	_, err = t.BumpEpoch(ctx, r.NetworkID, EpochConfig)
	return err
}

// DeleteRoute withdraws a prefix from a gateway.
//
// Returns ErrNotFound when nothing matched, so a caller can tell "withdrawn"
// from "was never there" — the difference between a successful revocation and a
// typo that left a route in place.
func (t *Tx) DeleteRoute(ctx context.Context, id uuid.UUID) error {
	var networkID uuid.UUID
	err := t.tx.QueryRow(ctx,
		`DELETE FROM orbit.route WHERE id = $1 RETURNING network_id`, id).Scan(&networkID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return ErrNotFound
		}
		return mapErr(err, "delete route")
	}
	_, err = t.BumpEpoch(ctx, networkID, EpochConfig)
	return err
}

// NetworkRoutes lists every route in a network, with the gateway's overlay
// address, ready to render.
//
// The join is what makes this one query rather than N: a rendered
// unsafe_routes entry needs the gateway's ADDRESS, and the route table stores a
// membership id. Ordered by prefix then address so two control planes rendering
// the same network produce identical bytes — the configuration is signed, and a
// nondeterministic order would change its digest on every poll and re-apply a
// configuration that had not changed.
//
// Only enrolled and active gateways, the same filter NetworkTopology uses. A
// gateway that has not finished enrolling has no certificate, so naming it as a
// `via` would point every machine at something that cannot answer.
func (t *Tx) NetworkRoutes(ctx context.Context, networkID uuid.UUID) ([]Route, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT `+routeCols+`, a.addr
		  FROM orbit.route r
		  JOIN orbit.membership h ON h.id = r.membership_id
		  JOIN LATERAL (
		      SELECT ma.addr FROM orbit.membership_address ma
		       WHERE ma.membership_id = h.id ORDER BY ma.addr LIMIT 1
		  ) a ON true
		 WHERE r.network_id = $1
		   AND h.state IN ('enrolled', 'active')
		 ORDER BY r.prefix, a.addr`, networkID)
	if err != nil {
		return nil, mapErr(err, "network routes")
	}
	defer rows.Close()

	var out []Route
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.ID, &r.NetworkID, &r.MembershipID, &r.Prefix,
			&r.Weight, &r.Masquerade, &r.Install, &r.MTU, &r.CreatedAt,
			&r.GatewayAddr); err != nil {
			return nil, mapErr(err, "scan route")
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MembershipRoutes lists the prefixes one gateway offers.
//
// This is what goes into that gateway's CERTIFICATE, so the order is fixed and
// the result is what enrollment hands to internal/ca as UnsafeNetworks.
func (t *Tx) MembershipRoutes(ctx context.Context, membershipID uuid.UUID) ([]Route, error) {
	// The gateway's address comes back too, so a listing can show what other
	// machines actually dial. LEFT, unlike NetworkRoutes: a membership with no
	// address yet is half-enrolled, and a listing that dropped its routes would
	// suggest they were never added.
	rows, err := t.tx.Query(ctx,
		`SELECT `+routeCols+`, a.addr
		   FROM orbit.route r
		   LEFT JOIN LATERAL (
		       SELECT ma.addr FROM orbit.membership_address ma
		        WHERE ma.membership_id = r.membership_id ORDER BY ma.addr LIMIT 1
		   ) a ON true
		  WHERE r.membership_id = $1 ORDER BY r.prefix`, membershipID)
	if err != nil {
		return nil, mapErr(err, "membership routes")
	}
	defer rows.Close()

	var out []Route
	for rows.Next() {
		var (
			r    Route
			addr *netip.Addr
		)
		if err := rows.Scan(&r.ID, &r.NetworkID, &r.MembershipID, &r.Prefix,
			&r.Weight, &r.Masquerade, &r.Install, &r.MTU, &r.CreatedAt, &addr); err != nil {
			return nil, mapErr(err, "scan route")
		}
		if addr != nil {
			r.GatewayAddr = *addr
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RoutePrefixes is MembershipRoutes reduced to what a certificate carries.
func RoutePrefixes(rs []Route) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Prefix)
	}
	return out
}

// ParsePrefixes turns stored text into prefixes, refusing host bits.
//
// Used for the CA's recorded constraint, which is text[] rather than cidr[]
// because Postgres has no cidr array ordering worth relying on and the value is
// only ever read back whole.
func ParsePrefixes(raw []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("unsafe network %q: %w", s, err)
		}
		if p.Addr() != p.Masked().Addr() {
			return nil, fmt.Errorf("unsafe network %q has bits set below the prefix length; write %s",
				s, p.Masked())
		}
		out = append(out, p)
	}
	return out, nil
}
