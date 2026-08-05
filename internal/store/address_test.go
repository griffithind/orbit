package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/griffithind/orbit/internal/store"
)

// These tests cover the things that actually break: a race for one address, a
// prefix that runs out, a /64 that cannot be enumerated, a host left with no
// address, a prefix removed while hosts are inside it, an IPv6 prefix on a v1
// network, and an attempt to change a slug.
//
// All of them are database behaviour, which is why none of them is a handler
// test. Two paths create networks and hosts — the admin API and `orbitd
// bootstrap` — so an invariant proved through one handler is proved for one
// handler.

func newNetworkFull(t *testing.T, s *store.Store, n store.Network) *store.Network {
	t.Helper()
	if n.Slug == "" {
		n.Slug = "t" + strings.ReplaceAll(uuid.NewString()[:12], "-", "")
	}
	if n.Name == "" {
		n.Name = "net " + uuid.NewString()[:8]
	}
	withIdentity(t, &n)
	err := s.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return tx.CreateNetwork(ctx, &n)
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	return &n
}

func newBareHost(t *testing.T, s *store.Store, net *store.Network, name string) *store.Membership {
	t.Helper()
	h := store.Membership{NetworkID: net.ID, Name: name, State: store.MembershipActive}
	err := s.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return insertHost(ctx, tx, &h)
	})
	if err != nil {
		t.Fatalf("CreateHost %s: %v", name, err)
	}
	return &h
}

// TestConcurrentAllocationHasExactlyOneWinnerPerAddress runs the allocator in
// parallel against a prefix with far fewer addresses than there are callers.
//
// The property is not "nobody errors" — with more callers than addresses some
// must fail — it is that NO ADDRESS IS EVER HANDED OUT TWICE. That is the whole
// reason allocation is a single statement arbitrated by the primary key: a
// check-then-insert would pass the check in several transactions at once and the
// losers would be hosts that cannot communicate.
func TestConcurrentAllocationHasExactlyOneWinnerPerAddress(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	// /28 = 14 assignable addresses, contested by 40 callers.
	net := newNetworkFull(t, s, store.Network{CIDRs: []netip.Prefix{netip.MustParsePrefix("10.31.0.0/28")}})

	const callers = 40
	hosts := make([]*store.Membership, callers)
	for i := range hosts {
		hosts[i] = newBareHost(t, s, net, fmt.Sprintf("racer-%02d", i))
	}

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		won   []netip.Addr
		fails int
	)
	start := make(chan struct{})
	for i := range hosts {
		wg.Add(1)
		go func(h *store.Membership) {
			defer wg.Done()
			<-start
			var addr netip.Addr
			err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
				var err error
				addr, err = tx.AllocateHostAddress(ctx, net, h.ID, netip.Prefix{})
				return err
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fails++
				if !errors.Is(err, store.ErrAddressExhausted) {
					t.Errorf("allocation failed with something other than exhaustion: %v", err)
				}
				return
			}
			won = append(won, addr)
		}(hosts[i])
	}
	close(start)
	wg.Wait()

	if len(won) != 14 {
		t.Errorf("allocated %d addresses from a /28, want 14 (network and broadcast are skipped)", len(won))
	}
	if fails != callers-len(won) {
		t.Errorf("%d winners and %d failures do not account for %d callers", len(won), fails, callers)
	}

	seen := map[netip.Addr]bool{}
	for _, a := range won {
		if seen[a] {
			t.Fatalf("address %s was allocated twice; the primary key did not arbitrate", a)
		}
		seen[a] = true
		if a.String() == "10.31.0.0" || a.String() == "10.31.0.15" {
			t.Errorf("allocated the network or broadcast address %s", a)
		}
	}
}

// TestExhaustionOfASlashThirty proves the refusal is a clear, named conflict
// rather than a timeout or a 500.
//
// A /30 has exactly two assignable addresses; the third request must fail, must
// be ErrAddressExhausted, and must name the prefix — an operator reading "no
// free address" without knowing which prefix ran out has to go and find it.
func TestExhaustionOfASlashThirty(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetworkFull(t, s, store.Network{CIDRs: []netip.Prefix{netip.MustParsePrefix("10.32.0.0/30")}})

	for i := range 2 {
		h := newBareHost(t, s, net, fmt.Sprintf("fill-%d", i))
		if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			_, err := tx.AllocateHostAddress(ctx, net, h.ID, netip.Prefix{})
			return err
		}); err != nil {
			t.Fatalf("allocation %d into a /30: %v", i, err)
		}
	}

	h := newBareHost(t, s, net, "one-too-many")
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.AllocateHostAddress(ctx, net, h.ID, netip.Prefix{})
		return err
	})
	if !errors.Is(err, store.ErrAddressExhausted) {
		t.Fatalf("third allocation into a /30 = %v, want ErrAddressExhausted", err)
	}
	if !strings.Contains(err.Error(), "10.32.0.0/30") {
		t.Errorf("exhaustion error does not name the prefix that ran out: %v", err)
	}
}

// TestIPv6AllocationInASlashSixtyFour is the case that forces random selection.
//
// A /64 holds 2^64 addresses. There is no scan, no "lowest free", and no
// enumeration that terminates — so the allocator probes at random and lets the
// primary key catch a collision. What this asserts is that it works at all, that
// the addresses land inside the prefix, and that repeated allocations do not
// collide.
func TestIPv6AllocationInASlashSixtyFour(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	prefix := netip.MustParsePrefix("fd00:dead:beef::/64")
	net := newNetworkFull(t, s, store.Network{
		CIDRs:   []netip.Prefix{prefix},
		CertVer: 2, // required: nebula's v1 format cannot carry an IPv6 address
	})

	seen := map[netip.Addr]bool{}
	for i := range 16 {
		h := newBareHost(t, s, net, fmt.Sprintf("v6-%02d", i))
		var addr netip.Addr
		if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			var err error
			addr, err = tx.AllocateHostAddress(ctx, net, h.ID, netip.Prefix{})
			return err
		}); err != nil {
			t.Fatalf("allocate in a /64: %v", err)
		}
		if !addr.Is6() {
			t.Fatalf("allocated %s, which is not an IPv6 address", addr)
		}
		if !prefix.Contains(addr) {
			t.Fatalf("allocated %s, which is outside %s", addr, prefix)
		}
		if addr == prefix.Addr() {
			t.Errorf("allocated the subnet-router anycast address %s", addr)
		}
		if seen[addr] {
			t.Fatalf("allocated %s twice", addr)
		}
		seen[addr] = true
	}
}

// TestRemovingTheLastAddressIsRefused.
//
// Not a warning and not something an acknowledgement overrides: a host with no
// overlay address cannot be issued a certificate at all — enroll.certNetworks
// returns "host has no overlay address" — so the result is not a host that is
// briefly down, it is a host that can never come back on its own.
func TestRemovingTheLastAddressIsRefused(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetworkFull(t, s, store.Network{CIDRs: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/24")}})
	h := newBareHost(t, s, net, "solo")

	var first, second netip.Addr
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		if first, err = tx.AllocateHostAddress(ctx, net, h.ID, netip.Prefix{}); err != nil {
			return err
		}
		second, err = tx.AllocateHostAddress(ctx, net, h.ID, netip.Prefix{})
		return err
	}); err != nil {
		t.Fatalf("allocate two: %v", err)
	}

	// Removing one of two is fine.
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RemoveHostAddress(ctx, net.ID, h.ID, second)
	}); err != nil {
		t.Fatalf("remove one of two: %v", err)
	}

	// Removing the last is not.
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RemoveHostAddress(ctx, net.ID, h.ID, first)
	})
	if !errors.Is(err, store.ErrLastAddress) {
		t.Fatalf("removing the only address = %v, want ErrLastAddress", err)
	}

	var after *store.Membership
	if err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		after, err = tx.GetHost(ctx, h.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(after.Addrs) != 1 {
		t.Errorf("host has %d addresses after a refused removal, want 1", len(after.Addrs))
	}
}

// TestRemoveCIDRInUseIsRefusedAndNamesTheHosts.
//
// Removing a prefix does not take the addresses away — the membership_address rows
// survive and the hosts keep answering — it breaks their NEXT renewal, hours
// later, when certNetworks can no longer pair the address with a prefix. So the
// refusal has to name who is blocking it, or an operator is left scanning a host
// list by hand.
func TestRemoveCIDRInUseIsRefusedAndNamesTheHosts(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	a := netip.MustParsePrefix("10.34.0.0/24")
	b := netip.MustParsePrefix("10.35.0.0/24")
	net := newNetworkFull(t, s, store.Network{CIDRs: []netip.Prefix{a, b}})

	h := newBareHost(t, s, net, "resident")
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.AllocateHostAddress(ctx, net, h.ID, b)
		return err
	}); err != nil {
		t.Fatalf("allocate in b: %v", err)
	}

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.RemoveNetworkCIDR(ctx, net.ID, b)
		return err
	})
	if !errors.Is(err, store.ErrCIDRInUse) {
		t.Fatalf("removing an occupied prefix = %v, want ErrCIDRInUse", err)
	}

	var holders []store.AddressHolder
	if err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		holders, err = tx.CIDRHolders(ctx, net.ID, b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(holders) != 1 || holders[0].Name != "resident" {
		t.Errorf("CIDRHolders = %+v, want the one resident host", holders)
	}

	// The empty prefix goes, and the last one may not.
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.RemoveNetworkCIDR(ctx, net.ID, a)
		return err
	}); err != nil {
		t.Fatalf("removing an empty prefix: %v", err)
	}
	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.RemoveNetworkCIDR(ctx, net.ID, b)
		return err
	})
	if !errors.Is(err, store.ErrLastCIDR) {
		t.Errorf("removing the last prefix = %v, want ErrLastCIDR", err)
	}
}

// TestOverlappingCIDRIsRefused.
//
// enroll.certNetworks pairs an address with the FIRST prefix that contains it,
// so two overlapping prefixes make the certificate a host is issued depend on
// the order the array happens to be in — and a /16 versus a /24 in a certificate
// is the difference between reaching the overlay and treating every peer as
// off-net.
func TestOverlappingCIDRIsRefused(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetworkFull(t, s, store.Network{CIDRs: []netip.Prefix{netip.MustParsePrefix("10.36.0.0/16")}})

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.AddNetworkCIDR(ctx, net.ID, netip.MustParsePrefix("10.36.7.0/24"))
		return err
	})
	if !errors.Is(err, store.ErrCIDROverlap) {
		t.Fatalf("adding an overlapping prefix = %v, want ErrCIDROverlap", err)
	}

	// A disjoint one is fine, and adds no config epoch: prefixes reach a host
	// through its certificate and appear in no rendered configuration, so
	// bumping would wake every agent to re-render an identical file.
	var before, after *store.Network
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		if before, err = tx.GetNetwork(ctx, net.ID); err != nil {
			return err
		}
		after, err = tx.AddNetworkCIDR(ctx, net.ID, netip.MustParsePrefix("10.37.0.0/16"))
		return err
	}); err != nil {
		t.Fatalf("adding a disjoint prefix: %v", err)
	}
	if len(after.CIDRs) != 2 {
		t.Errorf("network has %d prefixes, want 2", len(after.CIDRs))
	}
	if after.ConfigEpoch != before.ConfigEpoch {
		t.Errorf("adding a prefix bumped the config epoch %d -> %d; nothing rendered changed",
			before.ConfigEpoch, after.ConfigEpoch)
	}
}

// TestIPv6RequiresCertVersionTwo.
//
// nebula's v1 certificate format refuses an IPv6 network outright
// (cert/cert_v1.go: "certificate may not contain IPv6 networks"), so a v1
// network holding an IPv6 prefix is not degraded, it is one where issuance
// fails — and it fails long after the request that caused it, at the first
// enrollment, with an enrollment code already spent.
//
// Enforced by the database because `orbitd bootstrap` creates networks too, so
// this cannot be a handler test.
func TestIPv6RequiresCertVersionTwo(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		n := store.Network{
			Slug: "v1v6" + uuid.NewString()[:8], Name: "v1 with v6 " + uuid.NewString()[:8],
			CIDRs:   []netip.Prefix{netip.MustParsePrefix("fd00:1::/64")},
			CertVer: 1,
		}
		withIdentity(t, &n)
		return tx.CreateNetwork(ctx, &n)
	})
	if !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("creating a v1 network with an IPv6 prefix = %v, want ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), "network_ipv6_requires_cert_v2") {
		t.Errorf("refusal does not name the constraint, so no handler can explain it: %v", err)
	}

	// And the same rule holds on the editing path, which is the easier mistake:
	// adding an IPv6 prefix to a network someone created as v1 a month ago is a
	// one-field request with no hint that the certificate version is involved.
	v1 := newNetworkFull(t, s, store.Network{
		CIDRs:   []netip.Prefix{netip.MustParsePrefix("10.38.0.0/16")},
		CertVer: 1,
	})
	err = s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.AddNetworkCIDR(ctx, v1.ID, netip.MustParsePrefix("fd00:2::/64"))
		return err
	})
	if !errors.Is(err, store.ErrInvalid) {
		t.Errorf("adding an IPv6 prefix to a v1 network = %v, want ErrInvalid", err)
	}

	// A v2 network takes it.
	v2 := newNetworkFull(t, s, store.Network{
		CIDRs:   []netip.Prefix{netip.MustParsePrefix("10.39.0.0/16")},
		CertVer: 2,
	})
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.AddNetworkCIDR(ctx, v2.ID, netip.MustParsePrefix("fd00:3::/64"))
		return err
	}); err != nil {
		t.Errorf("adding an IPv6 prefix to a v2 network: %v", err)
	}
}

// TestNetworkSlugIsImmutable.
//
// The slug is a directory name on every managed host in the network. Changing it
// would not rename anything — it would strand the old directory and make every
// agent create a second one beside it — so the database refuses, and refuses in
// a way a handler can turn into a 400 rather than a 500.
func TestNetworkSlugIsImmutable(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetworkFull(t, s, store.Network{CIDRs: []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16")}})

	// Through a raw connection as the application role, because there is no store
	// method that changes a slug — which is itself the point. The trigger has to
	// hold against anything that reaches the table, not against the one function
	// that declines to offer it.
	conn, err := pgx.Connect(ctx, appDSN())
	if err != nil {
		t.Skipf("cannot open a direct connection: %v", err)
	}
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, `UPDATE orbit.network SET slug = $2 WHERE id = $1`,
		net.ID, "renamed"+uuid.NewString()[:8])
	if err == nil {
		t.Fatal("a slug was changed; every managed host in this network has the old one on disk")
	}
	if !strings.Contains(err.Error(), "immutable") {
		t.Errorf("refusal does not say why: %v", err)
	}

	// The display name moves freely, which is the entire point of splitting them.
	var renamed *store.Network
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		renamed, err = tx.UpdateNetworkName(ctx, net.ID, "Renamed "+uuid.NewString()[:8])
		return err
	}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if renamed.Slug != net.Slug {
		t.Errorf("slug moved with the name: %q -> %q", net.Slug, renamed.Slug)
	}

	// And the network still resolves by the slug a script memorised.
	var found *store.Network
	if err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		found, err = tx.GetNetworkBySlug(ctx, net.Slug)
		return err
	}); err != nil {
		t.Fatalf("GetNetworkBySlug after a rename: %v", err)
	}
	if found.ID != net.ID {
		t.Errorf("slug resolved to %s, want %s", found.ID, net.ID)
	}
}

// TestSlugCharsetIsEnforcedByTheDatabase.
func TestSlugCharsetIsEnforcedByTheDatabase(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	for _, bad := range []string{
		"Has-Capitals",
		"has_underscore",  // not valid in an interface name
		"has.period",      // ambiguous in a path, a separator in a hostname
		"-leading-hyphen", // and trailing, below
		"trailing-hyphen-",
		strings.Repeat("a", 33), // 32 is the cap that keeps a slug from ever looking like a uuid
	} {
		err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			n := store.Network{
				Slug: bad, Name: "bad slug " + uuid.NewString()[:8],
				CIDRs: []netip.Prefix{netip.MustParsePrefix("10.41.0.0/16")},
			}
			return tx.CreateNetwork(ctx, &n)
		})
		if err == nil {
			t.Errorf("slug %q was accepted", bad)
		}
	}

	// 32 is legal, and 32 < 36: a slug can never be mistaken for a uuid, which
	// is why no constraint has to say so.
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		n := store.Network{
			Slug: strings.Repeat("a", 24) + uuid.NewString()[:8], Name: "long slug " + uuid.NewString()[:8],
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		}
		withIdentity(t, &n)
		return tx.CreateNetwork(ctx, &n)
	}); err != nil {
		t.Errorf("a 32-character slug was refused: %v", err)
	}
	if len(uuid.NewString()) <= 32 {
		t.Error("a uuid now fits in a slug; the two forms are no longer disjoint by length")
	}

	// An omitted slug is derived from the name, which is what keeps every
	// existing creation path working without restating a value it has no opinion
	// about. A name with nothing usable in it is refused by name, rather than
	// producing a NOT NULL violation nobody can act on.
	derived := store.Network{
		Name:  "Prod EU " + uuid.NewString()[:8],
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")},
	}
	withIdentity(t, &derived)
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.CreateNetwork(ctx, &derived)
	}); err != nil {
		t.Fatalf("creating a network with no slug: %v", err)
	}
	if !strings.HasPrefix(derived.Slug, "prod-eu-") {
		t.Errorf("derived slug = %q, want it derived from the name", derived.Slug)
	}

	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		n := store.Network{Name: "!!!", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.46.0.0/16")}}
		return tx.CreateNetwork(ctx, &n)
	})
	if !errors.Is(err, store.ErrSlugRequired) {
		t.Errorf("a name with no slug-safe characters = %v, want ErrSlugRequired", err)
	}
}

// TestAddressChangeMarksRestartAndPullsRenewalForward.
//
// The two effects are separate on purpose. addr_changed_at makes the host
// reissue, because the addresses are inside the signed certificate.
// restart_required_epoch makes it restart, because nebula refuses a certificate
// reload whose networks changed and would otherwise go on running the old one
// while reporting a healthy applied epoch.
//
// And neither is set for a host that has never enrolled: there is nothing
// running to disrupt, and marking it would make the agent restart once,
// pointlessly, immediately after its first enrollment.
func TestAddressChangeMarksRestartAndPullsRenewalForward(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetworkFull(t, s, store.Network{CIDRs: []netip.Prefix{netip.MustParsePrefix("10.43.0.0/24")}})

	// A host that has never enrolled.
	fresh := store.Membership{NetworkID: net.ID, Name: "fresh", State: store.MembershipCreated}
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return insertHost(ctx, tx, &fresh)
	}); err != nil {
		t.Fatal(err)
	}
	var epoch int64
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		epoch, err = tx.MarkAddressChanged(ctx, net.ID, fresh.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if epoch != 0 {
		t.Errorf("a host in 'created' produced epoch %d; nothing is running to disrupt", epoch)
	}

	// A live one.
	live := newBareHost(t, s, net, "live") // created MembershipActive
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		epoch, err = tx.MarkAddressChanged(ctx, net.ID, live.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if epoch == 0 {
		t.Fatal("a live host produced no epoch, so no agent is told to restart")
	}

	var after *store.Membership
	if err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		after, err = tx.GetHost(ctx, live.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if after.RestartRequiredEpoch != epoch {
		t.Errorf("restart_required_epoch = %d, want the epoch the change produced (%d)",
			after.RestartRequiredEpoch, epoch)
	}
	if after.AddrChangedAt == nil {
		t.Error("addr_changed_at is unset, so renewal is not pulled forward and the host " +
			"keeps a certificate that no longer authorises its traffic")
	}
}

// TestAddressChangeImpactIsRoleAware.
//
// The gate's whole value is that it distinguishes an ordinary host from a relay.
// A restart on an ordinary host drops its own tunnels; a restart on the only
// relay drops traffic it was forwarding for machines nobody making the change
// was thinking about.
func TestAddressChangeImpactIsRoleAware(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	net := newNetworkFull(t, s, store.Network{CIDRs: []netip.Prefix{netip.MustParsePrefix("10.44.0.0/24")}})

	relay := store.Membership{
		NetworkID: net.ID, Name: "relay", State: store.MembershipActive,
		IsRelay: true, IsLighthouse: true, StaticAddrs: []string{"198.51.100.1:4242"},
	}
	plain := store.Membership{NetworkID: net.ID, Name: "plain", State: store.MembershipActive}
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := insertHost(ctx, tx, &relay); err != nil {
			return err
		}
		return insertHost(ctx, tx, &plain)
	}); err != nil {
		t.Fatal(err)
	}

	var got *store.AddressImpact
	if err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		got, err = tx.AddressChangeImpact(ctx, relay.ID, time.Time{})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if !got.IsRelay || !got.IsLighthouse {
		t.Fatalf("impact lost the host's roles: %+v", got)
	}
	if !got.OnlyRelay() {
		t.Errorf("the only relay in the network was not reported as the only one: %+v", got)
	}
	if !got.OnlyLighthouse() {
		t.Errorf("the only lighthouse was not reported as the only one: %+v", got)
	}
	if got.RelayClients < 1 {
		t.Errorf("no hosts counted as relying on relays, so the loudest line has no number: %+v", got)
	}
	// No certificate, so nothing is running: the gate must not fire.
	if got.Disruptive() {
		t.Errorf("a host with no certificate was reported as disruptive: %+v", got)
	}
}
