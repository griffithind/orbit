package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/griffithind/orbit/internal/device"
)

// Devices: machines, identified by a key they generated themselves.
//
// The one thing to hold onto while reading this file: a device row is a RECORD
// of an identity, not a grant of one. Nothing here issues anything. The control
// plane learns a device's public key when the device first speaks, and from
// then on the row exists so the key can be recognised, described to an
// operator, and blocked.
//
// See docs/design-device-identity.md.

// DeviceKeyBacking says where a device holds its private key.
//
// Reported by the machine and therefore a CLAIM, not a fact, until attestation
// can prove it. Recorded anyway: an operator looking at a fleet should be able to see how
// many machines hold a copyable key before there is anything to enforce.
const (
	DeviceKeyFile  = "file"
	DeviceKeyToken = "token"
)

// ErrDeviceBlocked is returned when a blocked device tries to do anything.
//
// A distinct error because the caller must not retry and must not fall through
// to another path: a blocked device that gets a helpful "try enrolling instead"
// has not been blocked.
var ErrDeviceBlocked = errors.New("device is blocked")

// Device is a machine, across every network it has joined on this control plane.
type Device struct {
	ID uuid.UUID

	// KeyFingerprint is SHA-256 of PublicKey, hex. The natural key, and what an
	// operator sees and pastes back.
	KeyFingerprint string

	// PublicKey is the raw device public key as the host presented it. Kept
	// because a fingerprint proves a match but cannot verify a signature, and
	// issuing a device certificate needs the key itself.
	PublicKey []byte

	// KeyBacking is DeviceKeyFile or DeviceKeyToken. See the constants.
	KeyBacking string

	// Hostname is host-supplied, never trusted, and present so a human deciding
	// whether to authorize a pending join can tell which row is the laptop on
	// their desk.
	Hostname string

	// BlockedAt is set when this device is refused everywhere on this control
	// plane. Nil means allowed.
	BlockedAt     *time.Time
	BlockedReason string

	FirstSeenAt time.Time
	LastSeenAt  time.Time

	// Facts and Posture are what this machine IS, recorded once per machine
	// rather than once per membership. See migration 0013.
	Facts   DeviceFacts
	Posture DevicePosture
}

// DeviceFacts is descriptive metadata a machine reports about itself.
//
// Never an authorization input on its own: an agent can claim any kernel
// version it likes. They exist so an operator can see a fleet — "how many
// machines are still on the old agent" — and so a posture rule has something to
// name.
type DeviceFacts struct {
	OS            string
	OSVersion     string
	Kernel        string
	Arch          string
	AgentVersion  string
	NebulaVersion string

	// ObservedAt is nil when nothing has ever been reported.
	ObservedAt *time.Time
}

// Empty reports whether these facts carry nothing worth recording.
//
// Used to skip the write rather than store a row of empty strings that would
// stamp ObservedAt and make "we have never heard from this machine"
// indistinguishable from "this machine told us nothing".
func (f DeviceFacts) Empty() bool {
	return f.OS == "" && f.OSVersion == "" && f.Kernel == "" &&
		f.Arch == "" && f.AgentVersion == "" && f.NebulaVersion == ""
}

// DevicePosture is what a machine's security configuration looks like.
//
// EVERY FIELD IS A *bool, AND NIL MEANS UNKNOWN — not false. The distinction is
// the point: a machine whose disk encryption could not be read is not a machine
// with an unencrypted disk, and a policy that conflated them would cut off a
// working fleet the day a probe broke. A policy that wants to refuse unknowns
// has to say so.
type DevicePosture struct {
	DiskEncrypted   *bool
	SecureBoot      *bool
	FirewallEnabled *bool
	TPMPresent      *bool

	ObservedAt *time.Time
}

// Empty reports whether this reading determined nothing at all.
func (p DevicePosture) Empty() bool {
	return p.DiskEncrypted == nil && p.SecureBoot == nil &&
		p.FirewallEnabled == nil && p.TPMPresent == nil
}

// Blocked reports whether this device is currently refused.
func (d *Device) Blocked() bool { return d.BlockedAt != nil }

// DeviceFingerprint computes the fingerprint for a device public key.
//
// One definition so the agent, the control plane, and anything that logs a
// device cannot disagree about what a fingerprint is. It lives in
// internal/device because that package is linked into the agent and this one is
// not — see device.Fingerprint.
func DeviceFingerprint(publicKey []byte) string {
	return device.Fingerprint(publicKey)
}

// deviceCols is alias-qualified for SELECTs; deviceColsBare is the same list
// for a RETURNING clause, which has no alias in scope. Two constants rather
// than one because using the qualified form in RETURNING is a runtime SQL
// error, not a compile error — it builds fine and fails on the join path.
const deviceCols = `d.id, d.key_fingerprint, d.public_key, d.key_backing,
	COALESCE(d.hostname, ''), d.blocked_at, COALESCE(d.blocked_reason, ''),
	d.first_seen_at, d.last_seen_at,
	COALESCE(d.os, ''), COALESCE(d.os_version, ''), COALESCE(d.kernel, ''),
	COALESCE(d.arch, ''), COALESCE(d.agent_version, ''), COALESCE(d.nebula_version, ''),
	d.facts_observed_at,
	d.disk_encrypted, d.secure_boot, d.firewall_enabled, d.tpm_present,
	d.posture_observed_at`

const deviceColsBare = `id, key_fingerprint, public_key, key_backing,
	COALESCE(hostname, ''), blocked_at, COALESCE(blocked_reason, ''),
	first_seen_at, last_seen_at,
	COALESCE(os, ''), COALESCE(os_version, ''), COALESCE(kernel, ''),
	COALESCE(arch, ''), COALESCE(agent_version, ''), COALESCE(nebula_version, ''),
	facts_observed_at,
	disk_encrypted, secure_boot, firewall_enabled, tpm_present,
	posture_observed_at`

func scanDevice(row pgx.Row) (*Device, error) {
	var d Device
	if err := row.Scan(&d.ID, &d.KeyFingerprint, &d.PublicKey, &d.KeyBacking,
		&d.Hostname, &d.BlockedAt, &d.BlockedReason,
		&d.FirstSeenAt, &d.LastSeenAt,
		&d.Facts.OS, &d.Facts.OSVersion, &d.Facts.Kernel,
		&d.Facts.Arch, &d.Facts.AgentVersion, &d.Facts.NebulaVersion,
		&d.Facts.ObservedAt,
		&d.Posture.DiskEncrypted, &d.Posture.SecureBoot,
		&d.Posture.FirewallEnabled, &d.Posture.TPMPresent,
		&d.Posture.ObservedAt); err != nil {
		return nil, err
	}
	return &d, nil
}

// SeeDevice records a device's key, or refreshes what is known about it.
//
// Idempotent by design and called on every contact, not only the first: a
// device's key is permanent, so "have I seen this before" is the only question,
// and answering it with an INSERT that fails on a duplicate would make the
// common path the error path.
//
// It deliberately does NOT clear blocked_at. Re-appearing is what a blocked
// device does; treating contact as grounds to unblock would make the block last
// exactly until the machine tried again.
//
// PublicKey and the fingerprint derived from it are not updatable. A row is a
// key; a different key is a different device.
func (t *Tx) SeeDevice(ctx context.Context, d *Device) error {
	if len(d.PublicKey) == 0 {
		return fmt.Errorf("see device: public key is empty")
	}
	fp := DeviceFingerprint(d.PublicKey)
	if d.KeyFingerprint != "" && d.KeyFingerprint != fp {
		// A caller that computed its own fingerprint and got a different answer
		// is a caller using a different encoding of the key. Failing here beats
		// storing a row whose fingerprint does not describe its own key.
		return fmt.Errorf("see device: fingerprint %s does not match the public key (%s)",
			d.KeyFingerprint, fp)
	}
	backing := d.KeyBacking
	if backing == "" {
		backing = DeviceKeyFile
	}

	row := t.tx.QueryRow(ctx, `
		INSERT INTO orbit.device (key_fingerprint, public_key, key_backing, hostname)
		VALUES ($1, $2, $3, NULLIF($4, ''))
		ON CONFLICT (key_fingerprint) DO UPDATE
		   SET last_seen_at = now(),
		       -- Both are advisory and both can legitimately change: a laptop
		       -- gets renamed, and a host that moves its key into a TPM keeps
		       -- the same key only if it was exportable, so in practice this
		       -- goes file -> token exactly once and never back.
		       key_backing = EXCLUDED.key_backing,
		       hostname = COALESCE(EXCLUDED.hostname, orbit.device.hostname)
		RETURNING `+deviceColsBare, fp, d.PublicKey, backing, d.Hostname)

	seen, err := scanDevice(row)
	if err != nil {
		return mapErr(err, "see device")
	}
	*d = *seen
	return nil
}

// RecordDeviceFacts stores what a machine reports about itself.
//
// COALESCE per column, not a wholesale overwrite. An agent that reports facts
// while one probe is failing sends an empty string for that field, and blanking
// a known-good value because this reading could not confirm it would make the
// record get worse over time rather than better. An empty field means "no news",
// which for descriptive metadata is the right reading.
//
// ObservedAt still advances, because it answers "when did we last hear" and not
// "when was every field last confirmed".
func (t *Tx) RecordDeviceFacts(ctx context.Context, deviceID uuid.UUID, f DeviceFacts) error {
	if f.Empty() {
		return nil
	}
	_, err := t.tx.Exec(ctx, `
		UPDATE orbit.device
		   SET os             = COALESCE(NULLIF($2, ''), os),
		       os_version     = COALESCE(NULLIF($3, ''), os_version),
		       kernel         = COALESCE(NULLIF($4, ''), kernel),
		       arch           = COALESCE(NULLIF($5, ''), arch),
		       agent_version  = COALESCE(NULLIF($6, ''), agent_version),
		       nebula_version = COALESCE(NULLIF($7, ''), nebula_version),
		       facts_observed_at = now(),
		       last_seen_at   = now()
		 WHERE id = $1`,
		deviceID, f.OS, f.OSVersion, f.Kernel, f.Arch, f.AgentVersion, f.NebulaVersion)
	return mapErr(err, "record device facts")
}

// RecordDevicePosture stores a posture reading.
//
// UNLIKE FACTS, THIS DOES NOT COALESCE, and the asymmetry is deliberate. A
// posture signal that stops being readable must become NULL — unknown — rather
// than keep reporting the last value that happened to be true. Carrying a
// six-month-old "encrypted" forward past the point where nothing can confirm it
// is how a compliance report becomes fiction, and it is the exact failure mode
// is the documented failure mode of Microsoft Entra's device-compliance signal,
// which is stale by construction: an ~8-hour check-in, policy propagation up to
// a day, and compliance is not a CAE critical event.
//
// So a reading replaces the whole set. What the agent could not determine this
// time reads as unknown, which is true.
//
// An entirely empty reading is refused rather than written: it would stamp a
// fresh posture_observed_at over a set of NULLs, which says "we checked, and
// know nothing" — indistinguishable from a healthy check of a machine that has
// no posture. A probe harness that fails wholesale should look like silence.
func (t *Tx) RecordDevicePosture(ctx context.Context, deviceID uuid.UUID, p DevicePosture) error {
	if p.Empty() {
		return nil
	}
	_, err := t.tx.Exec(ctx, `
		UPDATE orbit.device
		   SET disk_encrypted   = $2,
		       secure_boot      = $3,
		       firewall_enabled = $4,
		       tpm_present      = $5,
		       posture_observed_at = now(),
		       last_seen_at     = now()
		 WHERE id = $1`,
		deviceID, p.DiskEncrypted, p.SecureBoot, p.FirewallEnabled, p.TPMPresent)
	return mapErr(err, "record device posture")
}

// DeviceForHost resolves the machine behind a membership.
//
// The lookup the agent report path needs: a report identifies itself by overlay
// source address, which resolves to a membership, and posture belongs to the
// machine that membership is on. Returns ErrNotFound when the membership was
// created the old way and has no device — see docs/model.md §6, step 4.
func (t *Tx) DeviceForHost(ctx context.Context, membershipID uuid.UUID) (*Device, error) {
	d, err := scanDevice(t.tx.QueryRow(ctx,
		`SELECT `+deviceCols+`
		   FROM orbit.device d
		   JOIN orbit.membership h ON h.device_id = d.id
		  WHERE h.id = $1`, membershipID))
	if err != nil {
		return nil, mapErr(err, "device for host")
	}
	return d, nil
}

// GetDeviceByFingerprint resolves a device by its key fingerprint.
//
// The lookup every authenticated connection makes: a client certificate names a
// device, and this is what turns that name into a row plus a block decision.
func (t *Tx) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (*Device, error) {
	d, err := scanDevice(t.tx.QueryRow(ctx,
		`SELECT `+deviceCols+` FROM orbit.device d WHERE d.key_fingerprint = $1`, fingerprint))
	if err != nil {
		return nil, mapErr(err, "get device")
	}
	return d, nil
}

// GetDevice resolves a device by id.
func (t *Tx) GetDevice(ctx context.Context, id uuid.UUID) (*Device, error) {
	d, err := scanDevice(t.tx.QueryRow(ctx,
		`SELECT `+deviceCols+` FROM orbit.device d WHERE d.id = $1`, id))
	if err != nil {
		return nil, mapErr(err, "get device")
	}
	return d, nil
}

// ListDevices returns every device known to this control plane, newest contact
// first.
func (t *Tx) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := t.tx.Query(ctx,
		`SELECT `+deviceCols+` FROM orbit.device d ORDER BY d.last_seen_at DESC`)
	if err != nil {
		return nil, mapErr(err, "list devices")
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, mapErr(err, "list devices")
		}
		out = append(out, *d)
	}
	return out, mapErr(rows.Err(), "list devices")
}

// BlockDevice refuses a device everywhere on this control plane.
//
// This is the revocation mechanism for a device identity, and it is why the
// device certificate can safely be long-lived. There is one enforcement point —
// this database — so the block takes effect on the next connection with no
// propagation and no cache to invalidate.
//
// It does NOT touch the device's hosts. Blocking a device and suspending a
// membership are different decisions: a stolen laptop should lose everything,
// while a host being rebuilt should lose one network. Callers that want both
// do both, visibly.
func (t *Tx) BlockDevice(ctx context.Context, id uuid.UUID, reason string) error {
	tag, err := t.tx.Exec(ctx, `
		UPDATE orbit.device
		   SET blocked_at = COALESCE(blocked_at, now()),
		       blocked_reason = NULLIF($2, '')
		 WHERE id = $1`, id, reason)
	if err != nil {
		return mapErr(err, "block device")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UnblockDevice allows a device again.
func (t *Tx) UnblockDevice(ctx context.Context, id uuid.UUID) error {
	tag, err := t.tx.Exec(ctx, `
		UPDATE orbit.device
		   SET blocked_at = NULL, blocked_reason = NULL
		 WHERE id = $1`, id)
	if err != nil {
		return mapErr(err, "unblock device")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeviceHosts lists this device's memberships, across every network.
//
// "Where is this laptop" — the question an operator asks before blocking a
// machine, and the one nothing could answer before devices existed, because a
// host row knew only its own network.
func (t *Tx) DeviceHosts(ctx context.Context, deviceID uuid.UUID) ([]Membership, error) {
	rows, err := t.tx.Query(ctx,
		`SELECT `+membershipCols+` `+membershipFrom+` WHERE h.device_id = $1 ORDER BY h.created_at`, deviceID)
	if err != nil {
		return nil, mapErr(err, "device hosts")
	}
	defer rows.Close()

	var out []Membership
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, mapErr(err, "device hosts")
		}
		out = append(out, *h)
	}
	return out, mapErr(rows.Err(), "device hosts")
}

// JoinNetwork records a device and creates its pending membership, atomically.
//
// This is the front door under the device model: a machine presents the key it
// generated at first start, names the network it wants, and gets a row that
// holds nothing until somebody authorizes it. No address, no certificate, no
// reach — see MembershipPending.
//
// Atomic because the two halves are one fact. A device recorded without its
// membership is a machine that asked for nothing; a membership without its
// device is the thing docs/model.md §5 exists to forbid. Either both land or
// neither does.
//
// IDEMPOTENT ON RE-JOIN. A device that joins the same network twice gets its
// existing membership back rather than a second one. This is not a nicety: an
// agent that retries a join after a timeout it could not distinguish from a
// failure would otherwise fill the pending queue with duplicates of one
// machine, and an operator would have to guess which to authorize.
//
// It deliberately refuses a BLOCKED device. Blocking is the revocation
// mechanism for a device identity, and a block that a machine can step around
// by joining again is not one.
func (t *Tx) JoinNetwork(ctx context.Context, d *Device, networkID uuid.UUID, name string) (*Membership, error) {
	if name == "" {
		return nil, fmt.Errorf("join: membership name is required")
	}
	if err := t.SeeDevice(ctx, d); err != nil {
		return nil, err
	}
	if d.Blocked() {
		return nil, fmt.Errorf("%w: %s", ErrDeviceBlocked, d.KeyFingerprint)
	}

	// Already a member? Hand back what exists. Scoped by device AND network:
	// the same machine legitimately holds one membership per network, and a
	// different machine may legitimately hold this network's membership under
	// the same name only if the first one is gone (the UNIQUE below decides).
	existing, err := scanHost(t.tx.QueryRow(ctx,
		`SELECT `+membershipCols+` `+membershipFrom+`
		  WHERE h.device_id = $1 AND h.network_id = $2 AND h.state <> 'deleted'`,
		d.ID, networkID))
	switch {
	case err == nil:
		return existing, nil
	case errors.Is(mapErr(err, "join"), ErrNotFound):
		// Expected: this is the first join.
	default:
		return nil, mapErr(err, "join")
	}

	h := &Membership{
		NetworkID: networkID,
		Name:      name,
		State:     MembershipPending,
		DeviceID:  &d.ID,
	}
	if err := t.CreateHost(ctx, h); err != nil {
		// orbit.membership is UNIQUE (network_id, name), so a name another machine
		// already holds arrives here. Worth saying plainly: the operator picks
		// join names, and "that name is taken" is actionable where a constraint
		// violation is not.
		return nil, fmt.Errorf("join network as %q: %w", name, err)
	}
	return h, nil
}

// PendingMemberships lists joins waiting for a human, oldest first.
//
// Oldest first because this is a queue and the thing that has been waiting
// longest is the thing most likely to be a person standing next to a laptop.
func (t *Tx) PendingMemberships(ctx context.Context, networkID uuid.UUID) ([]Membership, error) {
	rows, err := t.tx.Query(ctx,
		`SELECT `+membershipCols+` `+membershipFrom+`
		  WHERE h.network_id = $1 AND h.state = 'pending'
		  ORDER BY h.created_at`, networkID)
	if err != nil {
		return nil, mapErr(err, "pending memberships")
	}
	defer rows.Close()

	var out []Membership
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, mapErr(err, "pending memberships")
		}
		out = append(out, *h)
	}
	return out, mapErr(rows.Err(), "pending memberships")
}

// ErrNotPending is returned when authorizing something that is not awaiting it.
//
// A distinct error because the two ways to hit it want opposite responses. An
// operator authorizing an already-active membership has done no harm and should
// be told so; a second authorization arriving concurrently must not allocate a
// second address, and this is what stops it.
var ErrNotPending = errors.New("membership is not pending authorization")

// AuthorizeMembership turns a pending membership into a real one: it allocates
// an overlay address and moves the row out of the queue.
//
// prefix selects which of the network's prefixes to allocate from; the zero
// value takes the first.
//
// The state goes to MembershipCreated rather than MembershipActive, which looks like a
// detour and is not. `created` means "has an address, has never held a
// certificate", and that is exactly true here — authorization grants a place in
// the network, not a credential. The machine still has to come back and prove it
// holds the device key before anything is signed for it. Skipping to `active`
// would make a membership nobody has ever authenticated indistinguishable from
// one with a live tunnel.
//
// UPDATE ... WHERE state = 'pending' rather than a read-then-write, so two
// operators clicking authorize at the same moment cannot both proceed: the
// second updates zero rows and gets ErrNotPending, instead of both allocating an
// address and one of them being silently thrown away.
func (t *Tx) AuthorizeMembership(ctx context.Context, net *Network, id uuid.UUID, roleID *uuid.UUID, prefix netip.Prefix) (*Membership, error) {
	var got uuid.UUID
	err := t.tx.QueryRow(ctx, `
		UPDATE orbit.membership
		   SET state = $2,
		       role_id = COALESCE($3, role_id)
		 WHERE id = $1 AND state = 'pending' AND network_id = $4
		RETURNING id`, id, MembershipCreated, roleID, net.ID).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either it does not exist, belongs to another network, or is not
		// pending. Distinguish the last one, because it is the only one an
		// operator can act on.
		if h, gerr := t.GetHost(ctx, id); gerr == nil && h.State != MembershipPending {
			return nil, fmt.Errorf("%w: it is %s", ErrNotPending, h.State)
		}
		return nil, fmt.Errorf("authorize membership: %w", ErrNotFound)
	}
	if err != nil {
		return nil, mapErr(err, "authorize membership")
	}

	if _, err := t.AllocateHostAddress(ctx, net, id, prefix); err != nil {
		return nil, err
	}
	return t.GetHost(ctx, id)
}

// AttachHostToDevice records which machine a membership belongs to.
//
// Separate from host creation because hosts predate devices: every host that
// exists today was created by an admin and enrolled with a code, with no device
// identity anywhere. Backfilling would mean inventing a device key, and an
// invented key is a claim that a machine holds something it has never seen.
func (t *Tx) AttachHostToDevice(ctx context.Context, membershipID, deviceID uuid.UUID) error {
	tag, err := t.tx.Exec(ctx,
		`UPDATE orbit.membership SET device_id = $2 WHERE id = $1`, membershipID, deviceID)
	if err != nil {
		return mapErr(err, "attach host to device")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
