package enroll

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// Recovery for a host whose certificate expired while it was offline.
//
// Such a host is stuck: the agent API rides the overlay, and it can no longer
// build a tunnel, so it cannot renew through the path it normally would. Without
// this endpoint the only remedy is an operator re-enrolling it by hand, which is
// the papercut that decides whether people keep using a thing.
//
// The host proves it is who it claims by demonstrating possession of the private
// key from its last certificate. It cannot do that with a signature: nebula host
// keys on Curve25519 are X25519, key agreement only. So the proof is an ECDH
// challenge — the server derives an ephemeral keypair, the host computes the
// shared secret with its own key, and both sides arrive at the same MAC.

var (
	ErrRecoveryUnavailable = errors.New("host is not eligible for recovery")
	ErrBadProof            = errors.New("recovery proof did not verify")
	ErrChallengeExpired    = errors.New("recovery challenge has expired")
)

// DefaultRecoveryGrace is how long past expiry a host may still recover.
//
// Generous on purpose: a laptop shut for a long holiday is the case this
// exists for. Bounded because a certificate that expired a year ago is more
// likely a decommissioned machine than a returning one, and every day of grace
// is a day an attacker who stole an old key file can still use it.
const DefaultRecoveryGrace = 30 * 24 * time.Hour

// challengeTTL bounds how long a challenge may sit before it is redeemed.
const challengeTTL = 5 * time.Minute

// Challenge issues a recovery challenge for a host.
//
// Deliberately stateless. The ephemeral private key is derived from the server
// pepper and the nonce, so it can be recomputed at verification time and never
// has to be stored or transmitted. That removes a table, a TTL sweep, and the
// possibility of a challenge store filling up under an attacker's control.
//
// Issuing a challenge reveals only that a host id exists, which the caller
// already had to know. It grants nothing: without the host's private key the
// challenge cannot be answered.
func (s *Service) Challenge(ctx context.Context, hostID uuid.UUID) (*wire.RecoveryChallengeResponse, error) {
	var (
		curve cert.Curve
		nonce []byte
	)

	err := s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		if err := s.recoveryEligible(ctx, tx, host); err != nil {
			return err
		}
		net, err := tx.GetNetwork(ctx, host.NetworkID)
		if err != nil {
			return err
		}
		curve, err = parseCurve(net.Curve)
		return err
	})
	if err != nil {
		return nil, err
	}

	// nonce = timestamp || random. The timestamp bounds freshness without any
	// server-side record; the random half keeps two challenges in the same
	// second distinct.
	nonce = make([]byte, 8+16)
	binary.BigEndian.PutUint64(nonce[:8], uint64(s.clock().Unix()))
	if _, err := rand.Read(nonce[8:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	_, pub, err := s.ephemeralFor(curve, nonce)
	if err != nil {
		return nil, err
	}

	return &wire.RecoveryChallengeResponse{
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		ServerPublicKey: base64.StdEncoding.EncodeToString(pub),
		Curve:           curve.String(),
		ExpiresAt:       s.clock().Add(challengeTTL),
	}, nil
}

// ephemeralFor derives the server's challenge keypair from the pepper and nonce.
//
// The nonce is public and the pepper is not, so an attacker choosing their own
// nonce still cannot learn the corresponding private key — and without it they
// cannot compute the shared secret from the host public key alone.
func (s *Service) ephemeralFor(curve cert.Curve, nonce []byte) (priv, pub []byte, err error) {
	// A counter lets us re-derive if a curve rejects the scalar. Impossible on
	// X25519, vanishingly unlikely on P-256, and a silent failure here would be
	// a challenge nobody could debug.
	for counter := byte(0); counter < 8; counter++ {
		info := append([]byte("orbit-recovery-ephemeral-v1"), counter)
		material, err := hkdf.Key(sha256.New, s.hasher.pepper, nonce, string(info), 32)
		if err != nil {
			return nil, nil, fmt.Errorf("derive ephemeral: %w", err)
		}
		priv, pub, err = ca.DeriveHostKey(curve, material)
		if err == nil {
			return priv, pub, nil
		}
	}
	return nil, nil, errors.New("could not derive a usable ephemeral key")
}

// proofFor computes the expected MAC.
//
// It binds the new public key, so a captured proof cannot be replayed to obtain
// a certificate for a key the attacker controls: the MAC would not match. That
// is what makes the stateless, single-use-free design safe.
func proofFor(sharedSecret, nonce []byte, hostID uuid.UUID, newPublicKey []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, sharedSecret, nonce, "orbit-recovery-v1", 32)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(hostID[:])
	mac.Write(newPublicKey)
	return mac.Sum(nil), nil
}

// Recover verifies a proof and issues a fresh certificate.
func (s *Service) Recover(ctx context.Context, req wire.RecoverRequest, from netip.Addr) (*wire.EnrollResponse, error) {
	hostID, err := uuid.Parse(req.HostID)
	if err != nil {
		return nil, ErrRecoveryUnavailable
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil || len(nonce) != 24 {
		return nil, ErrChallengeExpired
	}
	presented, err := base64.StdEncoding.DecodeString(req.Proof)
	if err != nil || len(presented) == 0 {
		return nil, ErrBadProof
	}
	newPub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(newPub) == 0 {
		return nil, ErrInvalidPublicKey
	}

	// Freshness. Checked before any database work so a flood of stale
	// challenges costs nothing.
	issued := time.Unix(int64(binary.BigEndian.Uint64(nonce[:8])), 0)
	age := s.clock().Sub(issued)
	if age < -time.Minute || age > challengeTTL {
		return nil, ErrChallengeExpired
	}

	var resp *wire.EnrollResponse
	err = s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		if err := s.recoveryEligible(ctx, tx, host); err != nil {
			return err
		}

		net, err := tx.GetNetwork(ctx, host.NetworkID)
		if err != nil {
			return err
		}
		curve, err := parseCurve(net.Curve)
		if err != nil {
			return err
		}

		// The key to prove possession of comes from the certificate we issued,
		// not from anything the caller sent. A client-supplied certificate
		// would let an attacker nominate a key they hold.
		last, err := tx.LatestCertificate(ctx, host.ID)
		if err != nil {
			return fmt.Errorf("%w: no certificate on record", ErrRecoveryUnavailable)
		}
		lastCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(last.PEM))
		if err != nil {
			return fmt.Errorf("parse recorded certificate: %w", err)
		}

		ephPriv, _, err := s.ephemeralFor(curve, nonce)
		if err != nil {
			return err
		}
		shared, err := ca.SharedSecret(curve, ephPriv, lastCert.PublicKey())
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBadProof, err)
		}
		expected, err := proofFor(shared, nonce, host.ID, newPub)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(expected, presented) != 1 {
			return ErrBadProof
		}

		out, err := s.issueAndRender(ctx, tx, host, req.PublicKey, net.Curve)
		if err != nil {
			return err
		}
		if err := tx.SetHostState(ctx, host.ID, store.HostEnrolled); err != nil {
			return err
		}

		var ip *netip.Addr
		if from.IsValid() {
			ip = &from
		}
		// Audited loudly. Routine recovery means renewal is broken somewhere,
		// and a recovery an operator did not expect is worth investigating.
		if err := tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: store.ActorAgent, ActorID: host.ID.String(), ActorDisplay: host.Name,
			Action: store.ActionRecovered, TargetType: "host", TargetID: host.ID.String(),
			Meta:     []byte(fmt.Sprintf(`{"previous_not_after":%q}`, last.NotAfter.Format(time.RFC3339))),
			SourceIP: ip,
		}); err != nil {
			return err
		}

		out.AgentEndpoints = s.agentEndpoints(ctx, tx, host.NetworkID)
		resp = out
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.log.Warn("host recovered after certificate expiry; renewal is not working for it",
		"host", hostID, "from", from)
	return resp, nil
}

// recoveryEligible applies the policy gates.
func (s *Service) recoveryEligible(ctx context.Context, tx *store.Tx, host *store.Host) error {
	// A blocked host must never recover. Recovery is a path to a new
	// certificate, and blocking exists precisely to stop that.
	if host.State == store.HostSuspended {
		return ErrHostBlocked
	}
	if host.State == store.HostDeleted || host.State == store.HostCreated {
		return fmt.Errorf("%w: host is %s", ErrRecoveryUnavailable, host.State)
	}

	last, err := tx.LatestCertificate(ctx, host.ID)
	if err != nil {
		return fmt.Errorf("%w: no certificate on record", ErrRecoveryUnavailable)
	}

	grace := s.cfg.RecoveryGrace
	if grace <= 0 {
		grace = DefaultRecoveryGrace
	}
	if s.clock().After(last.NotAfter.Add(grace)) {
		// Past the window this is more likely a decommissioned machine than a
		// returning one, and the old key file has had a long time to leak.
		return fmt.Errorf("%w: certificate expired more than %s ago; re-enroll instead",
			ErrRecoveryUnavailable, grace)
	}
	return nil
}
