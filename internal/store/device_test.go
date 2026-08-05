package store_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
)

func randomDeviceKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 65)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	k[0] = 0x04 // uncompressed point marker, as a real P-256 key would carry
	return k
}

// TestSeeDeviceIsIdempotent.
//
// SeeDevice runs on every contact, not only the first, because a device's key
// is permanent and "have I seen this before" is the only question. If the
// common path were the error path — an INSERT that conflicts — every steady
// state connection would be handling a duplicate-key error.
func TestSeeDeviceIsIdempotent(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	key := randomDeviceKey(t)

	var first, second store.Device
	err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		first = store.Device{PublicKey: key, Hostname: "laptop-1"}
		return tx.SeeDevice(ctx, &first)
	})
	if err != nil {
		t.Fatalf("first see: %v", err)
	}
	if first.ID.String() == "" || first.KeyFingerprint == "" {
		t.Fatal("SeeDevice did not populate the row it returned")
	}
	if first.KeyBacking != store.DeviceKeyFile {
		t.Errorf("key backing = %q, want the %q default", first.KeyBacking, store.DeviceKeyFile)
	}

	err = st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		second = store.Device{PublicKey: key, Hostname: "laptop-1"}
		return tx.SeeDevice(ctx, &second)
	})
	if err != nil {
		t.Fatalf("second see: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("the same key produced two devices: %s then %s", first.ID, second.ID)
	}
	if !second.LastSeenAt.After(first.LastSeenAt) && !second.LastSeenAt.Equal(first.LastSeenAt) {
		t.Errorf("last_seen_at went backwards: %s then %s", first.LastSeenAt, second.LastSeenAt)
	}
	if !second.FirstSeenAt.Equal(first.FirstSeenAt) {
		t.Errorf("first_seen_at changed on re-contact: %s then %s", first.FirstSeenAt, second.FirstSeenAt)
	}
}

// TestSeeDeviceDoesNotUnblock.
//
// Re-appearing is exactly what a blocked device does. If contact cleared the
// block, a block would last precisely until the machine tried again — which is
// to say, not at all.
func TestSeeDeviceDoesNotUnblock(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	key := randomDeviceKey(t)

	var d store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d = store.Device{PublicKey: key}
		return tx.SeeDevice(ctx, &d)
	}); err != nil {
		t.Fatalf("see: %v", err)
	}

	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.BlockDevice(ctx, d.ID, "laptop reported stolen")
	}); err != nil {
		t.Fatalf("block: %v", err)
	}

	var again store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		again = store.Device{PublicKey: key, Hostname: "still-here"}
		return tx.SeeDevice(ctx, &again)
	}); err != nil {
		t.Fatalf("see after block: %v", err)
	}
	if !again.Blocked() {
		t.Fatal("contact cleared the block; a blocked device unblocks itself by reconnecting")
	}
	if again.BlockedReason != "laptop reported stolen" {
		t.Errorf("blocked reason = %q, want it preserved", again.BlockedReason)
	}

	// And unblocking is an explicit act that does work.
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.UnblockDevice(ctx, d.ID)
	}); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	var after *store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		after, err = tx.GetDevice(ctx, d.ID)
		return err
	}); err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Blocked() {
		t.Error("device is still blocked after UnblockDevice")
	}
}

// TestSeeDeviceRejectsAMismatchedFingerprint.
//
// A caller that computed its own fingerprint and got a different answer is
// using a different encoding of the key. Storing the row anyway would leave a
// fingerprint that does not describe its own public key — and the fingerprint
// is what every lookup goes through.
func TestSeeDeviceRejectsAMismatchedFingerprint(t *testing.T) {
	st := setup(t)
	ctx := context.Background()

	err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d := store.Device{
			PublicKey:      randomDeviceKey(t),
			KeyFingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
		}
		return tx.SeeDevice(ctx, &d)
	})
	if err == nil {
		t.Fatal("SeeDevice accepted a fingerprint that does not match the key")
	}

	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d := store.Device{}
		return tx.SeeDevice(ctx, &d)
	}); err == nil {
		t.Fatal("SeeDevice accepted an empty public key")
	}
}

func TestGetDeviceByFingerprint(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	key := randomDeviceKey(t)

	var d store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d = store.Device{PublicKey: key, KeyBacking: store.DeviceKeyToken}
		return tx.SeeDevice(ctx, &d)
	}); err != nil {
		t.Fatalf("see: %v", err)
	}

	var got *store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		got, err = tx.GetDeviceByFingerprint(ctx, store.DeviceFingerprint(key))
		return err
	}); err != nil {
		t.Fatalf("get by fingerprint: %v", err)
	}
	if got.ID != d.ID {
		t.Errorf("resolved %s, want %s", got.ID, d.ID)
	}
	if got.KeyBacking != store.DeviceKeyToken {
		t.Errorf("key backing = %q, want %q", got.KeyBacking, store.DeviceKeyToken)
	}

	// An unknown fingerprint is not found, not an error the caller has to
	// unwrap — the join path asks this question about every new machine.
	err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.GetDeviceByFingerprint(ctx, "deadbeef")
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown fingerprint gave %v, want store.ErrNotFound", err)
	}
}

func TestDeviceFingerprintIsStable(t *testing.T) {
	key := randomDeviceKey(t)
	if store.DeviceFingerprint(key) != store.DeviceFingerprint(key) {
		t.Fatal("store.DeviceFingerprint is not deterministic")
	}
	other := randomDeviceKey(t)
	if store.DeviceFingerprint(key) == store.DeviceFingerprint(other) {
		t.Fatal("two keys produced the same fingerprint")
	}
	if len(store.DeviceFingerprint(key)) != 64 {
		t.Errorf("fingerprint is %d chars, want 64 hex", len(store.DeviceFingerprint(key)))
	}
}

// TestJoinNetworkIsIdempotent.
//
// An agent that retries a join after a timeout it could not distinguish from a
// failure must not create a second membership. Without this the pending queue
// fills with duplicates of one machine and an operator has to guess which to
// authorize — which is the same as having no queue.
func TestJoinNetworkIsIdempotent(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	net := newNetwork(t, st, "10.90.0.0/16")
	key := randomDeviceKey(t)

	var first, second *store.Membership
	err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d := store.Device{PublicKey: key, Hostname: "laptop"}
		var err error
		first, err = tx.JoinNetwork(ctx, &d, net.ID, "laptop")
		return err
	})
	if err != nil {
		t.Fatalf("first join: %v", err)
	}
	if first.State != store.MembershipPending {
		t.Errorf("state = %q, want %q", first.State, store.MembershipPending)
	}
	if first.DeviceID == nil {
		t.Fatal("join produced a membership with no device")
	}
	if len(first.Addrs) != 0 {
		t.Errorf("a pending membership holds an address: %v", first.Addrs)
	}

	err = st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d := store.Device{PublicKey: key, Hostname: "laptop"}
		var err error
		second, err = tx.JoinNetwork(ctx, &d, net.ID, "laptop")
		return err
	})
	if err != nil {
		t.Fatalf("second join: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("re-joining created a second membership: %s then %s", first.ID, second.ID)
	}
}

// TestJoinNetworkRefusesABlockedDevice.
//
// Blocking is the revocation mechanism for a device identity. A block a machine
// can step around by joining again is not one.
func TestJoinNetworkRefusesABlockedDevice(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	net := newNetwork(t, st, "10.91.0.0/16")
	key := randomDeviceKey(t)

	var dev store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		dev = store.Device{PublicKey: key}
		return tx.SeeDevice(ctx, &dev)
	}); err != nil {
		t.Fatalf("see: %v", err)
	}
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.BlockDevice(ctx, dev.ID, "stolen")
	}); err != nil {
		t.Fatalf("block: %v", err)
	}

	err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d := store.Device{PublicKey: key}
		_, err := tx.JoinNetwork(ctx, &d, net.ID, "laptop")
		return err
	})
	if !errors.Is(err, store.ErrDeviceBlocked) {
		t.Fatalf("join by a blocked device gave %v, want ErrDeviceBlocked", err)
	}
}

// TestJoinNetworkIsAtomic.
//
// The device and its membership are one fact. A device recorded without its
// membership is a machine that asked for nothing, and the operator sees a
// device with no pending row to authorize.
func TestJoinNetworkIsAtomic(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	net := newNetwork(t, st, "10.92.0.0/16")
	key := randomDeviceKey(t)

	// Take the name first, from a different machine, so the membership insert
	// is what fails.
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d := store.Device{PublicKey: randomDeviceKey(t)}
		_, err := tx.JoinNetwork(ctx, &d, net.ID, "taken")
		return err
	}); err != nil {
		t.Fatalf("seed join: %v", err)
	}

	err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d := store.Device{PublicKey: key}
		_, err := tx.JoinNetwork(ctx, &d, net.ID, "taken")
		return err
	})
	if err == nil {
		t.Fatal("two machines joined under the same name")
	}

	// The device must not have been left behind by the rolled-back transaction.
	err = st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.GetDeviceByFingerprint(ctx, store.DeviceFingerprint(key))
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a failed join left the device behind: %v", err)
	}
}

func TestPendingMemberships(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	net := newNetwork(t, st, "10.93.0.0/16")

	for _, name := range []string{"a", "b"} {
		if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			d := store.Device{PublicKey: randomDeviceKey(t)}
			_, err := tx.JoinNetwork(ctx, &d, net.ID, name)
			return err
		}); err != nil {
			t.Fatalf("join %s: %v", name, err)
		}
	}

	var pending []store.Membership
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		pending, err = tx.PendingMemberships(ctx, net.ID)
		return err
	}); err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("got %d pending memberships, want 2", len(pending))
	}
	// Oldest first: this is a queue, and the thing waiting longest is most
	// likely a person standing next to a laptop.
	if !pending[0].CreatedAt.Before(pending[1].CreatedAt) &&
		!pending[0].CreatedAt.Equal(pending[1].CreatedAt) {
		t.Error("pending memberships are not oldest first")
	}
}

// TestAuthorizeMembershipAllocatesAnAddress.
//
// A pending membership holds nothing. Authorization is what grants a place in
// the network, and an address is what "a place" means — without one the row can
// never be issued a certificate at all (enroll.certNetworks refuses it).
func TestAuthorizeMembershipAllocatesAnAddress(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	net := newNetwork(t, st, "10.94.0.0/16")

	var m *store.Membership
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d := store.Device{PublicKey: randomDeviceKey(t)}
		var err error
		m, err = tx.JoinNetwork(ctx, &d, net.ID, "laptop")
		return err
	}); err != nil {
		t.Fatalf("join: %v", err)
	}

	var got *store.Membership
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		got, err = tx.AuthorizeMembership(ctx, net, m.ID, nil, netip.Prefix{})
		return err
	}); err != nil {
		t.Fatalf("authorize: %v", err)
	}

	if len(got.Addrs) != 1 {
		t.Fatalf("got %d addresses, want 1", len(got.Addrs))
	}
	// `created`, not `active`: authorization grants a place in the network, not
	// a credential. The machine still has to prove it holds the device key.
	if got.State != store.MembershipCreated {
		t.Errorf("state = %q, want %q", got.State, store.MembershipCreated)
	}
	if got.DeviceID == nil || *got.DeviceID != *m.DeviceID {
		t.Error("authorization lost the device link")
	}
}

// TestAuthorizeMembershipIsNotRepeatable.
//
// Two operators clicking authorize at the same moment must not both proceed —
// the second would allocate a second address, and one of the two allocations
// would be silently thrown away.
func TestAuthorizeMembershipIsNotRepeatable(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	net := newNetwork(t, st, "10.95.0.0/16")

	var m *store.Membership
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d := store.Device{PublicKey: randomDeviceKey(t)}
		var err error
		m, err = tx.JoinNetwork(ctx, &d, net.ID, "laptop")
		return err
	}); err != nil {
		t.Fatalf("join: %v", err)
	}

	authorize := func() error {
		return st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			_, err := tx.AuthorizeMembership(ctx, net, m.ID, nil, netip.Prefix{})
			return err
		})
	}
	if err := authorize(); err != nil {
		t.Fatalf("first authorize: %v", err)
	}
	if err := authorize(); !errors.Is(err, store.ErrNotPending) {
		t.Fatalf("second authorize gave %v, want ErrNotPending", err)
	}

	var after *store.Membership
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		after, err = tx.GetHost(ctx, m.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(after.Addrs) != 1 {
		t.Errorf("a repeated authorization produced %d addresses, want 1", len(after.Addrs))
	}
}

// TestAuthorizeMembershipRefusesAnotherNetwork.
//
// The membership id alone must not be enough. Without the network in the WHERE
// clause, an operator authorized for one network could admit a machine into
// another by passing its id.
func TestAuthorizeMembershipRefusesAnotherNetwork(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	a := newNetwork(t, st, "10.96.0.0/16")
	b := newNetwork(t, st, "10.97.0.0/16")

	var m *store.Membership
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d := store.Device{PublicKey: randomDeviceKey(t)}
		var err error
		m, err = tx.JoinNetwork(ctx, &d, a.ID, "laptop")
		return err
	}); err != nil {
		t.Fatalf("join: %v", err)
	}

	err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.AuthorizeMembership(ctx, b, m.ID, nil, netip.Prefix{})
		return err
	})
	if err == nil {
		t.Fatal("a membership was authorized into a network it did not join")
	}
}

func TestRecordDeviceFactsCoalesces(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	key := randomDeviceKey(t)

	var dev store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		dev = store.Device{PublicKey: key}
		return tx.SeeDevice(ctx, &dev)
	}); err != nil {
		t.Fatal(err)
	}

	record := func(f store.DeviceFacts) {
		t.Helper()
		if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			return tx.RecordDeviceFacts(ctx, dev.ID, f)
		}); err != nil {
			t.Fatalf("record facts: %v", err)
		}
	}
	read := func() store.Device {
		t.Helper()
		var got *store.Device
		if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			var err error
			got, err = tx.GetDevice(ctx, dev.ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return *got
	}

	record(store.DeviceFacts{OS: "linux", OSVersion: "Fedora 42", Kernel: "6.14.0"})
	if got := read(); got.Facts.OSVersion != "Fedora 42" {
		t.Fatalf("OSVersion = %q", got.Facts.OSVersion)
	}

	// A later report whose OS-version probe failed sends an empty string. That
	// must not blank a known-good value: for descriptive metadata an empty
	// field is "no news", and clearing it would make the record get worse over
	// time rather than better.
	record(store.DeviceFacts{OS: "linux", Kernel: "6.15.0"})
	got := read()
	if got.Facts.OSVersion != "Fedora 42" {
		t.Errorf("a partial report cleared OSVersion: %q", got.Facts.OSVersion)
	}
	if got.Facts.Kernel != "6.15.0" {
		t.Errorf("Kernel = %q, want the newer value", got.Facts.Kernel)
	}
	if got.Facts.ObservedAt == nil {
		t.Error("facts were recorded without an observation time")
	}
}

// TestRecordDevicePostureDoesNotCoalesce.
//
// The asymmetry with facts is the whole point. A posture signal that stops being
// readable must become UNKNOWN, not keep reporting the last value that happened
// to be true — carrying a stale "encrypted" forward past the point where
// anything can confirm it is how a compliance report becomes fiction.
func TestRecordDevicePostureDoesNotCoalesce(t *testing.T) {
	st := setup(t)
	ctx := context.Background()

	var dev store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		dev = store.Device{PublicKey: randomDeviceKey(t)}
		return tx.SeeDevice(ctx, &dev)
	}); err != nil {
		t.Fatal(err)
	}

	yes, no := true, false
	record := func(p store.DevicePosture) {
		t.Helper()
		if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			return tx.RecordDevicePosture(ctx, dev.ID, p)
		}); err != nil {
			t.Fatalf("record posture: %v", err)
		}
	}
	read := func() store.DevicePosture {
		t.Helper()
		var got *store.Device
		if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			var err error
			got, err = tx.GetDevice(ctx, dev.ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return got.Posture
	}

	record(store.DevicePosture{DiskEncrypted: &yes, SecureBoot: &yes})
	if p := read(); p.DiskEncrypted == nil || !*p.DiskEncrypted {
		t.Fatalf("DiskEncrypted = %v, want true", p.DiskEncrypted)
	}

	// A later reading whose disk probe could not tell must leave unknown, not
	// the previous true.
	record(store.DevicePosture{SecureBoot: &yes})
	p := read()
	if p.DiskEncrypted != nil {
		t.Errorf("a stale true survived a reading that could not confirm it: %v", *p.DiskEncrypted)
	}
	if p.SecureBoot == nil || !*p.SecureBoot {
		t.Error("SecureBoot was lost")
	}

	// An explicit false is a determination and must be stored as one.
	record(store.DevicePosture{DiskEncrypted: &no})
	if p := read(); p.DiskEncrypted == nil || *p.DiskEncrypted {
		t.Errorf("an explicit false was not stored: %v", p.DiskEncrypted)
	}
}

// TestRecordDevicePostureIgnoresAnEmptyReading.
//
// A probe harness that fails wholesale must look like silence, not like a
// successful check that determined nothing — the second would stamp a fresh
// observed-at over a row of nulls and read as "we checked recently".
func TestRecordDevicePostureIgnoresAnEmptyReading(t *testing.T) {
	st := setup(t)
	ctx := context.Background()

	var dev store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		dev = store.Device{PublicKey: randomDeviceKey(t)}
		return tx.SeeDevice(ctx, &dev)
	}); err != nil {
		t.Fatal(err)
	}
	yes := true
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RecordDevicePosture(ctx, dev.ID, store.DevicePosture{DiskEncrypted: &yes})
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RecordDevicePosture(ctx, dev.ID, store.DevicePosture{})
	}); err != nil {
		t.Fatal(err)
	}

	var got *store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		got, err = tx.GetDevice(ctx, dev.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got.Posture.DiskEncrypted == nil {
		t.Error("an empty reading wiped a real one")
	}
}

// TestDeviceForHost resolves the machine behind a membership, which is what the
// agent report path needs: a report identifies itself by overlay address, and
// posture belongs to the machine rather than to one of its memberships.
func TestDeviceForHost(t *testing.T) {
	st := setup(t)
	ctx := context.Background()
	net := newNetwork(t, st, "10.98.0.0/16")

	var m *store.Membership
	var joined store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		joined = store.Device{PublicKey: randomDeviceKey(t)}
		var err error
		m, err = tx.JoinNetwork(ctx, &joined, net.ID, "laptop")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var got *store.Device
	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		got, err = tx.DeviceForHost(ctx, m.ID)
		return err
	}); err != nil {
		t.Fatalf("device for host: %v", err)
	}
	if got.ID != joined.ID {
		t.Errorf("resolved %s, want %s", got.ID, joined.ID)
	}

	// A membership created the old way has no device, and that must read as
	// not-found rather than as a nil the caller has to remember to check.
	// A device-less membership can no longer be created at all — device_id is
	// NOT NULL as of migration 0015 — so the old "what happens with no device"
	// branch has nothing to test. That is the outcome, not a gap: DeviceForHost
	// returns ErrNotFound only for a membership that does not exist.
	err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.DeviceForHost(ctx, uuid.New())
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an unknown membership gave %v, want ErrNotFound", err)
	}
}
