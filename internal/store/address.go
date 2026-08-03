package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Overlay address allocation.
//
// Every path here holds to one rule: the PRIMARY KEY (network_id, addr) is the
// arbiter, never an application-level "is this taken?" check. A check-then-
// insert has a window between the two statements, and the loser of that race is
// a host that cannot communicate — which is precisely the failure the schema's
// primary key exists to make impossible. So candidate selection and the insert
// are one statement, and a collision is something we RETRY rather than something
// we try to avoid.

var (
	// ErrAddressExhausted means the prefix has no address left to hand out. It
	// is a 409 naming the prefix, never a timeout and never a 500: the request
	// is well-formed and the answer is a fact about the address space.
	ErrAddressExhausted = errors.New("no free address in prefix")

	// ErrLastAddress means a removal would leave a host with no overlay address.
	//
	// Refused because such a host cannot be issued a certificate at all:
	// enroll.certNetworks returns "host has no overlay address" and every
	// renewal, recovery, and re-enrollment fails from then on. The host does not
	// degrade, it becomes unissuable, and nothing about the removal that caused
	// it would have said so.
	ErrLastAddress = errors.New("a host must keep at least one overlay address")

	// ErrAddrOutOfRange means the address is not inside any of the network's
	// prefixes.
	ErrAddrOutOfRange = errors.New("address is not within any of the network's prefixes")
)

// addrScanHostBits is the largest host space this will enumerate.
//
// Below it, allocation SCANS for the lowest free address: an operator reading
// 10.42.0.1, .2, .3 down a list can tell at a glance what the fleet looks like,
// and the scan is lazy — generate_series feeds a LIMIT 1, so the cost is one
// index probe per CONSECUTIVE occupied address, not one per address in the
// prefix.
//
// Above it, allocation picks at RANDOM. This is not a preference, it is the only
// option: an IPv6 /64 holds 2^64 addresses, which is not a large number to
// enumerate, it is a number no enumeration finishes. There is nothing to scan,
// nothing to page, and no "lowest free" to compute without materialising a set
// the size of the address space. Random selection with retry-on-conflict needs
// none of that — the space is so much larger than the fleet that a first probe
// collides with probability (hosts / 2^64), and the primary key catches the
// case where it does.
//
// 20 bits is a million candidates: every IPv4 prefix down to /12 and every IPv6
// prefix down to /108 is scanned, which covers every deployment that wants
// readable addresses, and everything wider falls to random.
const addrScanHostBits = 20

// Retry budgets. The two paths fail for opposite reasons, so one number would be
// wrong for both.
const (
	// scanAttempts bounds the scanning path, and is deliberately large.
	//
	// A retry there means another writer committed the address we picked — and
	// because the next scan skips every address that is now taken, EVERY LOST
	// RACE CORRESPONDS TO ANOTHER ALLOCATION SUCCEEDING. The loop is therefore
	// self-limiting: it ends either with an address or with a candidate query
	// that returns nothing, which is exhaustion reported exactly.
	//
	// A small budget breaks that. Twelve attempts against a /28 — fourteen
	// assignable addresses — gives up while the prefix still has room, and
	// reports contention as a failure to a caller who did nothing wrong. That is
	// not hypothetical; it is what forty concurrent allocators against a /28
	// produce. The cap exists only so a pathological case is bounded rather than
	// a hang, not as a contention limit.
	scanAttempts = 1024

	// probeAttempts bounds the random path, and is deliberately small.
	//
	// A retry there is a collision in a space of at least a million addresses.
	// A dozen consecutive collisions is not contention, it is a prefix that is
	// effectively full, and retrying a thousand times would turn that into a
	// slow request rather than an answer.
	probeAttempts = 12
)

// AllocateHostAddress claims a free address for a host from one of its
// network's prefixes.
//
// prefix selects which one; the zero value takes the network's first, and
// deliberately allocates ONE address rather than one per address family.
// Dual-stacking every host by default would double what an address change
// disrupts, would silently make a fleet dual-stack the moment someone adds an
// IPv6 prefix to an existing network, and is not required by anything: nebula's
// v2 rule that an IPv6 unsafe network needs an IPv6 address assignment
// (cert/cert_v2.go) never binds, because Orbit renders no unsafe networks at
// all. A host that genuinely wants both families asks for the second address
// explicitly, which is one call and is visible in the audit log as a decision.
func (t *Tx) AllocateHostAddress(ctx context.Context, net *Network, hostID uuid.UUID, prefix netip.Prefix) (netip.Addr, error) {
	if len(net.CIDRs) == 0 {
		return netip.Addr{}, fmt.Errorf("allocate address: network %s has no prefix", net.Slug)
	}
	if !prefix.IsValid() {
		prefix = net.CIDRs[0]
	} else if !containsPrefix(net.CIDRs, prefix) {
		return netip.Addr{}, fmt.Errorf("allocate address: %w: prefix %s is not one of %v",
			ErrNotFound, prefix, net.CIDRs)
	}
	prefix = prefix.Masked()

	lo, hi, ok := allocRange(prefix)
	if !ok {
		return netip.Addr{}, fmt.Errorf("%w: %s has no assignable address", ErrAddressExhausted, prefix)
	}

	if hi-lo < 1<<addrScanHostBits {
		return t.allocateByScan(ctx, net.ID, hostID, prefix, lo, hi)
	}
	return t.allocateByProbe(ctx, net.ID, hostID, prefix)
}

// allocRange is the inclusive offset window inside a prefix that may be handed
// out, as offsets from the prefix's base address.
//
// IPv4 skips the network address and the directed broadcast: both are legal to
// configure and neither works, and a host handed .0 or .255 of its own /24
// enrolls, gets a certificate, and then finds that half the stacks on the mesh
// will not talk to it. /31 is the documented exception (RFC 3021 point-to-point
// links have no network or broadcast address) and /32 is a single host.
//
// IPv6 has no broadcast address and no network address to reserve, but offset 0
// is the subnet-router anycast address and is not a host address, so it is
// skipped too.
func allocRange(p netip.Prefix) (lo, hi uint64, ok bool) {
	bits := p.Addr().BitLen()
	hostBits := bits - p.Bits()
	if hostBits < 0 {
		return 0, 0, false
	}

	var size uint64
	if hostBits >= 64 {
		size = ^uint64(0) // saturate; nothing needs the exact 2^64
	} else {
		size = uint64(1) << uint(hostBits)
	}

	if p.Addr().Is4() {
		switch {
		case hostBits <= 1:
			// /31 and /32: every address in the prefix is assignable.
			return 0, size - 1, true
		default:
			return 1, size - 2, true
		}
	}
	if hostBits == 0 {
		return 0, 0, true
	}
	return 1, size - 1, true
}

// allocateByScan takes the lowest free address in the window.
//
// One statement, and that is the whole point. The candidate subquery and the
// insert cannot interleave with another transaction's insert in a way that
// produces two hosts on one address, because the insert is what decides:
// ON CONFLICT DO NOTHING returns no row when someone else got there first, which
// leaves the transaction usable and the retry cheap. A candidate of NULL means
// something entirely different — the window really is full — and returning both
// values is what lets the caller tell exhaustion from contention without
// guessing.
func (t *Tx) allocateByScan(ctx context.Context, networkID, hostID uuid.UUID, p netip.Prefix, lo, hi uint64) (netip.Addr, error) {
	const q = `
		WITH candidate AS (
			SELECT (host(network($3::cidr) + g))::inet AS addr
			  FROM generate_series($4::bigint, $5::bigint) AS g
			 WHERE NOT EXISTS (
			           SELECT 1 FROM orbit.host_address a
			            WHERE a.network_id = $1
			              AND a.addr = (host(network($3::cidr) + g))::inet)
			 LIMIT 1
		), ins AS (
			INSERT INTO orbit.host_address (network_id, host_id, addr)
			SELECT $1, $2, c.addr FROM candidate c
			ON CONFLICT DO NOTHING
			RETURNING addr
		)
		SELECT (SELECT addr FROM candidate), (SELECT addr FROM ins)`

	for range scanAttempts {
		var candidate, inserted *netip.Addr
		if err := t.tx.QueryRow(ctx, q, networkID, hostID, p, lo, hi).
			Scan(&candidate, &inserted); err != nil {
			return netip.Addr{}, mapErr(err, "allocate overlay address")
		}
		if candidate == nil {
			return netip.Addr{}, fmt.Errorf("%w: every address in %s is assigned", ErrAddressExhausted, p)
		}
		if inserted != nil {
			return *inserted, nil
		}
		// Lost the race for that address. The next round sees the winner's row
		// and picks the next free one.
	}
	return netip.Addr{}, fmt.Errorf(
		"allocate overlay address in %s: lost %d races in a row, which means %d other "+
			"allocations committed while this one was running",
		p, scanAttempts, scanAttempts)
}

// allocateByProbe takes a random address and lets the primary key referee.
//
// Used where the host space cannot be enumerated at all. Exhaustion is the one
// thing this cannot prove: a prefix this wide is not full in any real sense, so
// a run of collisions is reported as what it is rather than dressed up as a
// certainty.
func (t *Tx) allocateByProbe(ctx context.Context, networkID, hostID uuid.UUID, p netip.Prefix) (netip.Addr, error) {
	for range probeAttempts {
		addr, err := randomAddrIn(p)
		if err != nil {
			return netip.Addr{}, err
		}

		var inserted *netip.Addr
		err = t.tx.QueryRow(ctx, `
			INSERT INTO orbit.host_address (network_id, host_id, addr)
			VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING
			RETURNING addr`, networkID, hostID, addr).Scan(&inserted)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			continue // taken; probe again
		case err != nil:
			return netip.Addr{}, mapErr(err, "allocate overlay address")
		}
		return *inserted, nil
	}
	return netip.Addr{}, fmt.Errorf(
		"%w: %d random probes into %s all collided, so it is effectively full",
		ErrAddressExhausted, probeAttempts, p)
}

// randomAddrIn returns a uniformly random address inside p, never the base
// address (the subnet-router anycast address in IPv6, the network address in
// IPv4).
//
// crypto/rand rather than math/rand: not because an overlay address is a secret,
// but because a predictable allocation sequence is one an outsider can use to
// guess which addresses exist, and the cost of the stronger source at this
// volume is nothing.
func randomAddrIn(p netip.Prefix) (netip.Addr, error) {
	base := p.Masked().Addr().AsSlice()
	r := make([]byte, len(base))

	for attempt := 0; attempt < 4; attempt++ {
		if _, err := rand.Read(r); err != nil {
			return netip.Addr{}, fmt.Errorf("random address: %w", err)
		}
		out := make([]byte, len(base))
		nonZero := false
		for i := range base {
			var mask byte
			for j := range 8 {
				if i*8+j >= p.Bits() {
					mask |= 1 << (7 - j)
				}
			}
			hostPart := r[i] & mask
			if hostPart != 0 {
				nonZero = true
			}
			out[i] = base[i] | hostPart
		}
		if !nonZero {
			continue // drew the base address; vanishingly rare, and not a host address
		}
		addr, ok := netip.AddrFromSlice(out)
		if !ok {
			return netip.Addr{}, fmt.Errorf("random address: %d bytes is not an address", len(out))
		}
		return addr, nil
	}
	return netip.Addr{}, fmt.Errorf("random address in %s: drew the base address repeatedly", p)
}

func containsPrefix(ps []netip.Prefix, p netip.Prefix) bool {
	for _, x := range ps {
		if x == p.Masked() || x == p {
			return true
		}
	}
	return false
}

//------------------------------------------------------------------------------
// Explicit add and remove
//------------------------------------------------------------------------------

// ClaimHostAddress claims one specific address for a host.
//
// The in-range check is here rather than left to issuance for the same reason
// handleCreateHost has always done it: the database would happily store an
// address outside every prefix, and the failure would surface much later as a
// certificate the CA refuses to sign.
func (t *Tx) ClaimHostAddress(ctx context.Context, net *Network, hostID uuid.UUID, addr netip.Addr) error {
	if !net.ContainsAddr(addr) {
		return fmt.Errorf("%w: %s is outside %v", ErrAddrOutOfRange, addr, net.CIDRs)
	}
	_, err := t.tx.Exec(ctx, `
		INSERT INTO orbit.host_address (network_id, host_id, addr)
		VALUES ($1, $2, $3)`, net.ID, hostID, addr)
	return mapErr(err, "claim overlay address")
}

// RemoveHostAddress releases one of a host's addresses, refusing to remove the
// last.
//
// The host row is locked first, and that lock is what makes "a host always has
// an address" true rather than merely likely. Counting and then deleting in two
// statements would let two concurrent removals each observe two addresses and
// each delete one, leaving zero — the check would have passed in both
// transactions and the invariant would still be broken. There is no primary key
// to referee a deletion the way there is for an insert, so the host row stands
// in for one. Address changes are rare enough that serialising them per host
// costs nothing.
func (t *Tx) RemoveHostAddress(ctx context.Context, networkID, hostID uuid.UUID, addr netip.Addr) error {
	var locked uuid.UUID
	if err := t.tx.QueryRow(ctx,
		`SELECT id FROM orbit.host WHERE id = $1 AND network_id = $2 FOR UPDATE`,
		hostID, networkID).Scan(&locked); err != nil {
		return mapErr(err, "lock host for address removal")
	}

	var total, matching int
	if err := t.tx.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE addr = $2)
		  FROM orbit.host_address WHERE host_id = $1`, hostID, addr,
	).Scan(&total, &matching); err != nil {
		return mapErr(err, "count host addresses")
	}
	if matching == 0 {
		return fmt.Errorf("remove host address: %w: %s", ErrNotFound, addr)
	}
	if total <= 1 {
		return fmt.Errorf("%w: %s is its only one", ErrLastAddress, addr)
	}

	_, err := t.tx.Exec(ctx,
		`DELETE FROM orbit.host_address WHERE network_id = $1 AND host_id = $2 AND addr = $3`,
		networkID, hostID, addr)
	return mapErr(err, "remove host address")
}

//------------------------------------------------------------------------------
// The restart signal
//------------------------------------------------------------------------------

// MarkAddressChanged records that a host's address set moved, and returns the
// config epoch the change produced.
//
// Two effects, and they are separate because the agent needs them separately.
//
// addr_changed_at pulls the host's RENEWAL forward. The addresses live inside
// the signed certificate and nebula's firewall checks on every packet that a
// peer's source address appears in its certificate, so a host whose address
// moved is holding one that no longer authorises the traffic it is about to
// send. Waiting for the ordinary midpoint renewal is not latency, it is outage.
//
// restart_required_epoch tells the agent that applying that certificate is not
// enough. Nebula refuses a certificate reload whose networks changed (pki.go
// reloadCert: "Networks in new cert was different from old"), so the host will
// install the new certificate, watch nebula decline it, and keep running the old
// one — indefinitely, and while reporting a perfectly healthy applied epoch.
//
// Both are set only for a host in 'enrolled' or 'active'. A host in 'created'
// has no certificate and no running nebula: there is nothing to pull forward and
// nothing to restart, and marking it would make the agent restart once,
// pointlessly, immediately after its first enrollment.
//
// The epoch bump is conditional on the same thing, and for a reason that is
// about everyone else: a host outside those states does not appear in
// NetworkTopology, so nothing any other host renders changes, and bumping would
// wake the whole network to re-fetch a byte-identical fragment.
func (t *Tx) MarkAddressChanged(ctx context.Context, networkID, hostID uuid.UUID) (int64, error) {
	var state string
	if err := t.tx.QueryRow(ctx,
		`SELECT state FROM orbit.host WHERE id = $1 AND network_id = $2`,
		hostID, networkID).Scan(&state); err != nil {
		return 0, mapErr(err, "read host state")
	}
	if state != HostEnrolled && state != HostActive {
		return 0, nil
	}

	epoch, err := t.BumpEpoch(ctx, networkID, EpochConfig)
	if err != nil {
		return 0, err
	}
	if _, err := t.tx.Exec(ctx, `
		UPDATE orbit.host
		   SET restart_required_epoch = $2, addr_changed_at = now()
		 WHERE id = $1`, hostID, epoch); err != nil {
		return 0, mapErr(err, "mark address changed")
	}
	return epoch, nil
}

//------------------------------------------------------------------------------
// Blast radius
//------------------------------------------------------------------------------

// AddressImpact is what restarting one host's nebula costs the rest of the
// network.
//
// It exists because the cost is NOT the same for every host, and the response to
// an address change is only useful if it says which case this is. An operator
// who reads "the host will restart" about a relay has been told the least
// important half of the truth.
type AddressImpact struct {
	HostID   uuid.UUID
	HostName string
	State    string

	// HasCertificate is what makes the difference between a disruption and a
	// bookkeeping change: without one there is no running nebula to disrupt.
	HasCertificate bool

	IsLighthouse   bool
	IsRelay        bool
	IsControlPlane bool

	// Counts of the live fleet, so the response can say "the only" rather than
	// "a". Scoped to enrolled and active hosts, exactly as NetworkTopology is,
	// because a host in any other state is not carrying traffic for anyone.
	Lighthouses  int
	Relays       int
	RelayClients int
	Hosts        int

	// LiveControlPlanes counts replicas currently advertised to agents. One
	// means every agent on this network loses renewal and revocation for the
	// duration of the restart.
	LiveControlPlanes int
}

// Disruptive reports whether changing this host's addresses interrupts anything.
//
// False for a host that has never enrolled and for one on its way out: the gate
// exists to warn about disruption, and there is none to warn about. Gating them
// anyway would train operators to send the acknowledgement reflexively, which is
// the failure mode that makes a gate worse than none.
func (i AddressImpact) Disruptive() bool {
	return i.HasCertificate && (i.State == HostEnrolled || i.State == HostActive)
}

// OnlyLighthouse reports that this host is the network's sole lighthouse, which
// is a materially different answer from being one of several: with another
// lighthouse up, discovery continues; without one, every host that does not
// already hold a tunnel to its peer cannot find it until this process is back.
func (i AddressImpact) OnlyLighthouse() bool { return i.IsLighthouse && i.Lighthouses <= 1 }

// OnlyRelay reports that this host is the network's sole relay.
func (i AddressImpact) OnlyRelay() bool { return i.IsRelay && i.Relays <= 1 }

// OnlyControlPlane reports that this replica is the only live one on the
// network.
func (i AddressImpact) OnlyControlPlane() bool { return i.IsControlPlane && i.LiveControlPlanes <= 1 }

// AddressChangeImpact gathers everything the gate needs in one query.
//
// One round trip because the gate runs on the request path and every count here
// is a question the operator would otherwise have to ask by hand, one endpoint
// at a time, while deciding whether to proceed.
//
// controlPlaneSince bounds what counts as a live replica; pass the same
// staleness window the agent endpoint list uses, or a zero time to count every
// registered replica.
func (t *Tx) AddressChangeImpact(ctx context.Context, hostID uuid.UUID, controlPlaneSince time.Time) (*AddressImpact, error) {
	var i AddressImpact
	i.HostID = hostID

	var since any
	if !controlPlaneSince.IsZero() {
		since = controlPlaneSince
	}

	err := t.tx.QueryRow(ctx, `
		SELECT h.name, h.state, h.is_lighthouse, h.is_relay,
		       EXISTS (SELECT 1 FROM orbit.certificate c
		                WHERE c.host_id = h.id AND c.state = 'active'),
		       EXISTS (SELECT 1 FROM orbit.control_plane cp
		                WHERE (cp.network_id, cp.host_id) = (h.network_id, h.id)),
		       (SELECT count(*) FROM orbit.host x
		         WHERE x.network_id = h.network_id AND x.is_lighthouse
		           AND x.state IN ('enrolled', 'active')),
		       (SELECT count(*) FROM orbit.host x
		         WHERE x.network_id = h.network_id AND x.is_relay
		           AND x.state IN ('enrolled', 'active')),
		       -- Hosts that would USE a relay. renderFor sets use_relays on
		       -- every host that is not itself a relay, so this is the population
		       -- whose traffic can be riding through the host being restarted.
		       (SELECT count(*) FROM orbit.host x
		         WHERE x.network_id = h.network_id AND NOT x.is_relay
		           AND x.state IN ('enrolled', 'active')),
		       (SELECT count(*) FROM orbit.host x
		         WHERE x.network_id = h.network_id
		           AND x.state IN ('enrolled', 'active')),
		       (SELECT count(*) FROM orbit.control_plane cp
		         WHERE cp.network_id = h.network_id
		           AND ($2::timestamptz IS NULL OR cp.last_seen_at > $2))
		  FROM orbit.host h
		 WHERE h.id = $1`, hostID, since,
	).Scan(&i.HostName, &i.State, &i.IsLighthouse, &i.IsRelay,
		&i.HasCertificate, &i.IsControlPlane,
		&i.Lighthouses, &i.Relays, &i.RelayClients, &i.Hosts, &i.LiveControlPlanes)
	if err != nil {
		return nil, mapErr(err, "address change impact")
	}
	return &i, nil
}

// Audit actions for address changes.
//
// Declared here rather than beside their siblings in audit.go for the same
// reason ActionConfigReverted and ActionRoleGroupsChanged are: what matters
// about them is the SPLIT, and the split is only legible next to the code that
// explains it.
//
// The acknowledged path gets its own action rather than the ordinary one with a
// flag in the metadata. "Which changes knowingly restarted a running host, and
// which of those were relays" is the question asked after an unexplained gap in
// a graph, and it should be a WHERE clause rather than a scan through jsonb.
// Same reasoning as ca.force_activated being distinct from ca.activated.
const (
	ActionHostAddressAdded   = "host.address_added"
	ActionHostAddressRemoved = "host.address_removed"

	ActionHostAddressAddedWithRestart   = "host.address_added_with_restart"
	ActionHostAddressRemovedWithRestart = "host.address_removed_with_restart"

	ActionNetworkCIDRAdded   = "network.cidr_added"
	ActionNetworkCIDRRemoved = "network.cidr_removed"
	ActionNetworkRenamed     = "network.renamed"
)
