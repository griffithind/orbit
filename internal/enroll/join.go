package enroll

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// Joining: a device asks to become a member of a network.
//
// The distinction from enrollment, which is the thing to hold onto while
// reading this file: enrollment presents a SECRET and gets a certificate back
// in the same round trip. A join presents an IDENTITY and gets a row that holds
// nothing — no address, no certificate, no reach — until a human authorizes it.
//
// Both gates are legitimate and they fail differently. A secret that has to
// travel to the machine is a secret that can be copied off a provisioning
// repository; a queue somebody must watch does not scale to unattended
// provisioning. See docs/design-device-identity.md §3.

var (
	// ErrJoinSignature covers every way the proof of possession fails: a
	// malformed key, a malformed signature, one that does not verify. ONE error
	// for all of them, for the reason ErrInvalidCredential is one error: telling
	// a caller which part it got wrong is a probing oracle.
	//
	// Clock skew is the exception and gets its own error, because it is the one
	// case with a remedy the operator can act on.
	ErrJoinSignature = errors.New("join signature is not valid")

	// ErrJoinName rejects a membership name before it reaches the database.
	ErrJoinName = errors.New("invalid membership name")

	// ErrNameTaken is a join for a name another membership in the network
	// already holds. Distinct from a generic conflict because it is the one
	// join failure an operator fixes by choosing a different name.
	ErrNameTaken = errors.New("a membership with that name already exists in this network")
)

// maxNameLen matches what the database accepts, checked here so the failure is
// a 400 with a reason rather than a constraint violation surfacing as a 500.
const maxNameLen = 253

// Join records a device and creates its pending membership.
//
// The signature is verified BEFORE anything is written. Without that, anyone who
// has seen a device's public key — it is public, and it appears in the CLI, in
// logs and in the admin UI — could lodge join requests on that device's behalf.
// They could never use the result, because every credential issued for the
// membership is bound to the private half they do not hold, but they could fill
// an operator's queue and take the names those rows claim.
func (s *Service) Join(ctx context.Context, req wire.JoinRequest, from netip.Addr) (*wire.JoinResponse, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > maxNameLen {
		return nil, fmt.Errorf("%w: 1-%d characters", ErrJoinName, maxNameLen)
	}

	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: public key is not base64", ErrJoinSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64", ErrJoinSignature)
	}
	// Parse the key before verifying so a P-224 key is refused as a device
	// identity rather than accepted at a strength nothing else here assumes.
	if _, err := device.ParsePublicKey(pub); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrJoinSignature, err)
	}

	signedAt := time.Unix(req.SignedAt, 0)
	if err := device.VerifyJoin(pub, req.Network, name, signedAt, s.clock(), sig); err != nil {
		if errors.Is(err, device.ErrStaleJoin) {
			// Surfaced verbatim: "your clock is 3h12m off" is actionable and
			// reveals nothing an unauthenticated caller could not measure by
			// reading the Date header.
			return nil, err
		}
		s.log.Warn("join rejected: signature", "from", from, "network", req.Network, "error", err)
		return nil, ErrJoinSignature
	}

	// A reservation code, if one was presented. Validated for shape here so a
	// malformed one is refused before any database work.
	if req.Credential != "" {
		if err := Validate(req.Credential); err != nil {
			return nil, ErrInvalidCredential
		}
	}

	var resp wire.JoinResponse
	err = s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		net, err := resolveNetworkRef(ctx, tx, req.Network)
		if err != nil {
			return err
		}

		d := store.Device{
			PublicKey: pub,
			Hostname:  req.Hostname,
		}

		var m *store.Membership
		if req.Credential != "" {
			m, err = s.redeemReservation(ctx, tx, net, &d, req.Credential, from)
		} else {
			m, err = tx.JoinNetwork(ctx, &d, net.ID, name)
		}
		if err != nil {
			if errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("%w: %s", ErrNameTaken, name)
			}
			return err
		}
		// The name the CLIENT signed, kept before `name` is rebound to whatever
		// the membership ended up called. A reservation overrides the requested
		// name, so the two differ exactly when a code was presented — and the
		// proof below has to be over the bytes the client signed, not over the
		// answer it is about to be given.
		signedName := name
		name = m.Name

		// Audited as the device, not as "system". A join is an action taken by
		// a machine that has just proved it holds a key, and the fingerprint is
		// the only name it has — recording it under an anonymous actor would
		// make the queue's provenance unreadable exactly when someone is trying
		// to work out where a row came from.
		if err := tx.AppendAudit(ctx, store.AuditEntry{
			ActorType:    store.ActorAgent,
			ActorID:      d.KeyFingerprint,
			ActorDisplay: req.Hostname,
			Action:       store.ActionDeviceJoin,
			TargetType:   "host",
			TargetID:     m.ID.String(),
			SourceIP:     sourceIP(from),
		}); err != nil {
			return err
		}

		resp = wire.JoinResponse{
			MembershipID: m.ID.String(),
			DeviceID:     d.ID.String(),
			State:        m.State,
			Name:         m.Name,
			NetworkID:    net.NetworkID,
			NetworkKey:   base64.StdEncoding.EncodeToString(net.IdentityPublicKey),
		}

		// The proof that this control plane is the one the network ID names.
		//
		// Signed over the CLIENT'S join statement — the same bytes the client
		// signed to get here — so the client can reconstruct the challenge
		// without another round trip, and so the proof cannot be lifted from
		// one machine's join and shown to another.
		proof, err := s.signNetworkProof(ctx, net,
			device.JoinStatement(req.Network, signedName, d.KeyFingerprint, signedAt))
		if err != nil {
			return err
		}
		resp.NetworkProof = base64.StdEncoding.EncodeToString(proof)
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.log.Info("device joined",
		"membership", resp.MembershipID, "device", resp.DeviceID,
		"network", req.Network, "name", name, "state", resp.State)
	return &resp, nil
}

// PendingJoins lists memberships in a network awaiting authorization.
func (s *Service) PendingJoins(ctx context.Context, networkID uuid.UUID) ([]store.Membership, error) {
	var out []store.Membership
	err := s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		out, err = tx.PendingMemberships(ctx, networkID)
		return err
	})
	return out, err
}

// resolveNetworkRef reads a network reference as a network ID, a uuid, or a slug.
//
// Three forms, and they cannot be confused: a network ID is exactly 16
// characters of Crockford base32, a uuid's canonical form is 36, and a slug is
// neither — so each parse either succeeds on something that is definitely that
// form or fails on something that might be another.
//
// The display name is deliberately NOT accepted. It is mutable, and resolving by
// a mutable string is how a rename silently retargets a script.
//
// Order matters: the network ID is tried FIRST, because it is the only form a
// joining machine can verify afterwards. A ref that is a valid network ID should
// never be resolved as a slug that happens to look like one.
func resolveNetworkRef(ctx context.Context, tx *store.Tx, ref string) (*store.Network, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("network reference is required: %w", store.ErrNotFound)
	}
	if _, err := ca.ParseNetworkID(ref); err == nil {
		return tx.GetNetworkByNetworkID(ctx, ref)
	}
	if id, err := uuid.Parse(ref); err == nil {
		return tx.GetNetwork(ctx, id)
	}
	return tx.GetNetworkBySlug(ctx, ref)
}

// signNetworkProof signs a challenge with this network's identity key.
//
// The key is loaded from the network's signer ref and CACHED, because a join is
// the one hot path that needs it and reading plus decrypting a passphrase-
// protected file per request would put an Argon2 derivation on it.
//
// A failure here fails the join rather than being logged and skipped. A join
// that silently returned no proof would be a join the client cannot verify, and
// the client cannot tell "this control plane could not load its key" from "this
// control plane does not have it" — which is exactly the case the proof exists
// to distinguish.
func (s *Service) signNetworkProof(ctx context.Context, net *store.Network, challenge []byte) ([]byte, error) {
	priv, err := s.networkIdentity(ctx, net)
	if err != nil {
		return nil, err
	}
	return ca.SignNetworkProof(priv, challenge)
}

// loadNetworkIdentity resolves a signer ref through the vault.
//
// Nil is a wiring mistake, not a mode. Every network's identity key is in the
// vault, so a service built without a resolver cannot sign a join proof — and
// saying so names the missing wiring instead of failing as a key that will not
// load.
func (s *Service) loadNetworkIdentity(ctx context.Context, ref string) (ed25519.PrivateKey, error) {
	if s.cfg.NetworkIdentity == nil {
		return nil, errors.New("this service was built without a network identity resolver, " +
			"so it cannot prove which network it is; wire enroll.Config.NetworkIdentity")
	}
	return s.cfg.NetworkIdentity(ctx, ref)
}

func (s *Service) networkIdentity(ctx context.Context, net *store.Network) (ed25519.PrivateKey, error) {
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	if priv, ok := s.identityKeys[net.ID]; ok {
		return priv, nil
	}

	priv, err := s.loadNetworkIdentity(ctx, net.IdentitySignerRef)
	if err != nil {
		return nil, fmt.Errorf("network %s identity key: %w", net.Slug, err)
	}

	// Assert that the key on disk is the one this network's ID commits to. The
	// failure it catches is a runbook transposing two files that sit side by
	// side in /var/lib/orbit, and catching it here — once, at first use — beats
	// every joining machine reporting a mismatch it cannot act on.
	if err := ca.VerifyNetworkID(net.NetworkID, priv.Public().(ed25519.PublicKey)); err != nil {
		return nil, fmt.Errorf("network %s identity key at %s is not the key its id commits to: %w",
			net.Slug, net.IdentitySignerRef, err)
	}

	if s.identityKeys == nil {
		s.identityKeys = map[uuid.UUID]ed25519.PrivateKey{}
	}
	s.identityKeys[net.ID] = priv
	return priv, nil
}

// sourceIP is the nil-or-address dance every audit call site does. netip.Addr's
// zero value is a valid struct and an invalid address, and storing one produces
// a row whose source looks like it was recorded rather than absent.
func sourceIP(from netip.Addr) *netip.Addr {
	if !from.IsValid() {
		return nil
	}
	return &from
}

// Authorize turns a pending membership into a real one.
//
// This is the human half of the join. The machine has already proved it holds a
// key; this is somebody deciding that the machine holding it should be on the
// network. It allocates the overlay address and nothing else — no certificate is
// issued here, because the device has to come back and prove possession again
// before anything is signed for it. See Claim.
func (s *Service) Authorize(ctx context.Context, membershipID uuid.UUID, roleID *uuid.UUID, actor store.Identity) (*store.Membership, *store.Network, error) {
	var out *store.Membership
	var net *store.Network
	err := s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		m, err := tx.GetHost(ctx, membershipID)
		if err != nil {
			return err
		}
		net, err = tx.GetNetwork(ctx, m.NetworkID)
		if err != nil {
			return err
		}
		// Re-check the device here rather than trusting the join. A device
		// blocked while its join sat in the queue is exactly the case this
		// exists for, and it is the likeliest one: the machine was reported
		// stolen between asking and being looked at.
		if m.DeviceID != nil {
			d, err := tx.GetDevice(ctx, *m.DeviceID)
			if err != nil {
				return err
			}
			if d.Blocked() {
				return fmt.Errorf("%w: %s", store.ErrDeviceBlocked, d.KeyFingerprint)
			}
		}

		out, err = tx.AuthorizeMembership(ctx, net, membershipID, roleID, netip.Prefix{})
		if err != nil {
			return err
		}

		meta := fmt.Appendf(nil, `{"name":%q,"addrs":%q}`, out.Name, addrsString(out.Addrs))
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: actor.Kind, ActorID: actor.Subject, ActorDisplay: actor.Display,
			Action:     store.ActionMembershipAuthorized,
			TargetType: "host", TargetID: membershipID.String(),
			Meta: meta,
		})
	})
	if err != nil {
		return nil, nil, err
	}
	s.log.Info("membership authorized",
		"membership", out.ID, "name", out.Name, "addrs", addrsString(out.Addrs), "by", actor.Display)
	return out, net, nil
}

func addrsString(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ",")
}

// ErrNotAuthorized is a claim against a membership nobody has said yes to yet.
//
// The single most common thing that will happen on this endpoint — an agent
// polls after joining and before an operator has looked — so it is a named
// error rather than a generic failure, and the handler turns it into a status
// an agent can loop on without treating it as broken.
var ErrNotAuthorized = errors.New("membership has not been authorized yet")

// Claim issues the membership certificate to the device that joined.
//
// The endpoint that replaces the enrollment code on this path. What makes it
// safe without a shared secret is that the signature is checked against the
// public key ALREADY STORED for the membership's device — the request cannot
// supply the key it is verified against, so holding the private half is the only
// way through.
func (s *Service) Claim(ctx context.Context, req wire.ClaimRequest, from netip.Addr) (*wire.EnrollResponse, error) {
	id, err := uuid.Parse(strings.TrimSpace(req.MembershipID))
	if err != nil {
		return nil, fmt.Errorf("%w: membership id is not a uuid", ErrJoinSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64", ErrJoinSignature)
	}

	var resp *wire.EnrollResponse
	err = s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		m, err := tx.GetHost(ctx, id)
		if err != nil {
			return err
		}
		if m.DeviceID == nil {
			// A membership created the old way, through POST /v1/memberships. It has
			// no device to verify against, so it cannot be claimed — it enrolls
			// with a code, which is the path it was created for. Step 3 removes
			// the ability to make one.
			return fmt.Errorf("%w: this membership was not created by a join", ErrJoinSignature)
		}
		d, err := tx.GetDevice(ctx, *m.DeviceID)
		if err != nil {
			return err
		}
		if d.Blocked() {
			return fmt.Errorf("%w: %s", store.ErrDeviceBlocked, d.KeyFingerprint)
		}

		if err := device.VerifyClaim(d.PublicKey, req.MembershipID, req.PublicKey,
			time.Unix(req.SignedAt, 0), s.clock(), sig); err != nil {
			if errors.Is(err, device.ErrStaleJoin) {
				return err
			}
			s.log.Warn("claim rejected: signature",
				"from", from, "membership", id, "device", d.KeyFingerprint, "error", err)
			return ErrJoinSignature
		}

		// State is checked AFTER the signature, so an unauthenticated caller
		// cannot use this endpoint to learn which memberships an operator has
		// approved.
		switch m.State {
		case store.MembershipPending:
			return ErrNotAuthorized
		case store.MembershipSuspended, store.MembershipDeleted:
			return ErrHostBlocked
		}

		out, err := s.issueAndRender(ctx, tx, m, req.PublicKey, req.Curve)
		if err != nil {
			return err
		}
		if err := tx.SetHostState(ctx, m.ID, store.MembershipEnrolled); err != nil {
			return err
		}
		if err := tx.RecordAgentReport(ctx, m.ID, store.AgentReport{
			NebulaVersion: req.NebulaVersion,
			AgentVersion:  req.AgentVersion,
		}); err != nil {
			return err
		}
		if err := tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: store.ActorAgent, ActorID: d.KeyFingerprint, ActorDisplay: m.Name,
			Action:     store.ActionMembershipClaimed,
			TargetType: "host", TargetID: m.ID.String(),
			SourceIP: sourceIP(from),
		}); err != nil {
			return err
		}

		out.AgentEndpoints = s.agentEndpoints(ctx, tx, m.NetworkID)
		resp = out
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ErrReservationForAnotherNetwork is a code minted for one network presented
// against another.
//
// A distinct error because it is an operator mistake with an obvious fix —
// copying the wrong code into a provisioning script — and because letting it
// fall through to "invalid credential" would send them hunting for an expiry
// that has not happened.
var ErrReservationForAnotherNetwork = errors.New("reservation is for a different network")

// redeemReservation consumes a code and creates the membership it describes.
//
// INSIDE THE CALLER'S TRANSACTION, unlike Enroll's redemption which runs on the
// pool before any other work. The difference is what each is protecting.
//
// Enroll redeems first and outside, deliberately: everything after it is a
// certificate issuance, and an attacker replaying a spent code must not be able
// to cost one. A join issues nothing — it writes two rows — so there is no work
// worth protecting, and the failure that actually happens is a name collision.
// Rolling the redemption back with it means the operator's code still works
// after they fix the collision, instead of being burned by an attempt that
// created nothing.
func (s *Service) redeemReservation(ctx context.Context, tx *store.Tx, net *store.Network,
	d *store.Device, code string, from netip.Addr) (*store.Membership, error) {

	redeemed, err := tx.RedeemCredential(ctx, Hash(code), from)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// One message for unknown, spent and expired, as Enroll does:
			// telling a caller which one it was hands an attacker a way to
			// probe for live codes.
			s.log.Warn("join rejected: unknown, spent, or expired reservation", "from", from)
			return nil, ErrInvalidCredential
		}
		return nil, err
	}
	if redeemed.NetworkID != net.ID {
		return nil, ErrReservationForAnotherNetwork
	}
	if redeemed.Reserved == nil {
		// A code bound to an existing membership. That is the re-enrollment
		// path and goes through /enroll/v1/enroll; accepting it here would
		// create a second membership for a machine that already has one.
		return nil, fmt.Errorf("%w: this code belongs to an existing host, not a reservation",
			ErrInvalidCredential)
	}

	m, err := tx.CreateReservedMembership(ctx, net, d, *redeemed.Reserved)
	if err != nil {
		return nil, err
	}

	// A membership coming into existence is audited, as it was when POST
	// /v1/memberships did it. The actor changes and the action does not: it is the
	// DEVICE that caused the row now, by presenting a code, so the fingerprint
	// is the actor and the operator who reserved the place is recorded
	// separately on the credential (ActionEnrollCodeCreated). Two entries,
	// because two people did two things at two times.
	if err := tx.AppendAudit(ctx, store.AuditEntry{
		ActorType: store.ActorAgent, ActorID: d.KeyFingerprint, ActorDisplay: d.Hostname,
		Action:     store.ActionMembershipCreated,
		TargetType: "host", TargetID: m.ID.String(),
		Meta:     fmt.Appendf(nil, `{"via":"reservation","credential":%q}`, redeemed.CredentialID),
		SourceIP: sourceIP(from),
	}); err != nil {
		return nil, err
	}
	return m, nil
}

// ErrReservedNameTaken is a reservation for a name that is already spoken for,
// either by a live membership or by another unspent reservation.
var ErrReservedNameTaken = errors.New("that name is already taken in this network")

// ErrLighthouseNeedsAddr is a lighthouse reservation with nowhere to be reached.
//
// Refused at RESERVATION time, which is the only moment an operator is present.
// A lighthouse with no public address does not fail — it succeeds into a network
// where every other machine has been told to dial an empty list, and the symptom
// is "nothing can find anything", days later, on a machine nobody is watching.
var ErrLighthouseNeedsAddr = errors.New(
	"a lighthouse needs a public address: pass -public-addr, or set it on the machine " +
		"first with `orbit device set-addrs` if it has already joined another network")

// Reserve holds a place in a network for a machine that has not arrived.
//
// This is what replaced `orbit host create` followed by `orbit host code`. The
// operator's intent — the name, optionally the address, optionally the role — is
// recorded on the CREDENTIAL rather than on a host row, so nothing exists until
// a machine presents the code, and what does come into existence names that
// machine from the start.
//
// The returned plaintext is the only copy. It is relayed once and never stored;
// only its keyed hash is persisted.
func (s *Service) Reserve(ctx context.Context, networkRef string, r store.Reservation,
	ttl time.Duration, actor store.Identity) (*wire.EnrollmentCodeResponse, error) {

	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || len(r.Name) > maxNameLen {
		return nil, fmt.Errorf("%w: 1-%d characters", ErrJoinName, maxNameLen)
	}
	if ttl <= 0 {
		ttl = DefaultCodeTTL
	}
	addrs, err := store.ValidatePublicAddrs(r.PublicAddrs)
	if err != nil {
		return nil, err
	}
	r.PublicAddrs = addrs

	// A lighthouse must be reachable somewhere. Checked here because this is the
	// last moment an operator is present: by redemption time the machine is
	// booting from a template and there is nobody to tell.
	//
	// Only the addresses this reservation carries are visible. A machine that
	// already holds them on its device record satisfies the requirement too, but
	// that device does not exist yet — so the error names both fixes rather than
	// asserting the one it can see.
	if r.IsLighthouse && len(r.PublicAddrs) == 0 {
		return nil, ErrLighthouseNeedsAddr
	}

	plaintext, stored, err := NewCredential()
	if err != nil {
		return nil, err
	}
	expiresAt := s.clock().Add(ttl)

	err = s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		net, err := resolveNetworkRef(ctx, tx, networkRef)
		if err != nil {
			return err
		}

		// Checked here as well as by the unique index, because the index covers
		// reservations against reservations and cannot see orbit.membership. A name a
		// live membership already holds would otherwise mint a code that is
		// guaranteed to fail at redemption — on a machine, unattended, with
		// nobody watching.
		//
		// Not a substitute for the redemption-time check: a host can be created
		// under this name after the reservation is made, so both are needed and
		// this one is the courtesy.
		if _, err := tx.GetHostByName(ctx, net.ID, r.Name); err == nil {
			return fmt.Errorf("%w: %s", ErrReservedNameTaken, r.Name)
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		cred := store.EnrollmentCredential{
			NetworkID: net.ID,
			Reserved:  &r,
			Method:    store.MethodCode,
			ExpiresAt: expiresAt,
			CreatedBy: actor.Subject,
		}
		if err := tx.CreateEnrollmentCredential(ctx, &cred, stored); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("%w: %s", ErrReservedNameTaken, r.Name)
			}
			return err
		}
		// Targeted at the network, not at a host: there is no host yet, and
		// that is precisely the fact worth recording. The reserved name goes in
		// the meta so the entry stays legible once the code is spent.
		e := actor.Audit(store.ActionEnrollCodeCreated, "network", net.ID.String())
		e.Meta = fmt.Appendf(nil, `{"reserved_name":%q}`, r.Name)
		return tx.AppendAudit(ctx, e)
	})
	if err != nil {
		return nil, err
	}

	return &wire.EnrollmentCodeResponse{
		Code:      plaintext,
		ExpiresAt: expiresAt,
		EnrollURL: s.cfg.EnrollURL,
	}, nil
}
