package ca

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Signed configurations: the material an agent installs carries its own proof
// that the control plane produced it.
//
// WHAT THIS FIXES.
//
// The agent asks for material only when its epoch differs from the control
// plane's, and reports back the epoch it RECEIVED. Nothing reads what is on
// disk. An operator who edits nebula.yml therefore gets a machine running an
// unrendered config while the control plane's convergence view — which gates CA
// rotation and backs the revocation SLO — says it converged. The edit is
// invisible while it is live and vanishes without trace when some later epoch
// overwrites it.
//
// WHAT IT DOES NOT FIX. Root on the machine. Someone who can edit the config can
// also stop the agent, replace nebula, or drop the tun device, and no signature
// changes that. What this buys is that a divergence is DETECTED and REPORTED
// rather than silent — and, more importantly, that the material no longer needs
// a trusted transport to be trustworthy. See docs/config-integrity.md.

// ConfigStatementV1 is the domain separator. Present so a signature over a
// configuration can never be mistaken for a signature over a join statement:
// both are made by the same key, and a scheme where one message type can be
// reinterpreted as another is one substitution away from being broken.
const ConfigStatementV1 = "orbit-config-v1"

// ErrConfigSignature means material did not verify under the network's key.
var ErrConfigSignature = errors.New("this configuration was not signed by this network")

// ConfigEnvelope is what gets signed. Not the config bytes alone.
//
// Signing only the bytes leaves three attacks intact, and each field here closes
// exactly one:
//
//	MembershipID   installing machine A's config on machine B
//	ConfigEpoch    replaying an old generation to restore a firewall hole
//	CABundleSHA256 pairing a valid config with a different trust bundle
//
// NetworkID is included even though the verifying key already determines it: a
// verifier that has pinned one network's key can then check the envelope names
// the network it thinks it is on, and get a legible error instead of a
// signature failure when a machine is pointed at the wrong control plane.
type ConfigEnvelope struct {
	NetworkID      string `json:"network_id"`
	MembershipID   string `json:"membership_id"`
	ConfigEpoch    int64  `json:"config_epoch"`
	BlocklistEpoch int64  `json:"blocklist_epoch"`

	// ConfigSHA256 and CABundleSHA256 are lowercase hex.
	ConfigSHA256   string `json:"config_sha256"`
	CABundleSHA256 string `json:"ca_bundle_sha256"`
}

// Bytes is the canonical encoding that is actually signed.
//
// LENGTH-PREFIXED, and that is the point of the function rather than an
// implementation detail. A delimiter-joined encoding lets two different field
// sets produce identical bytes — a membership id ending in a newline and an
// empty next field are indistinguishable from the fields shifted by one — so a
// signature over one set verifies over another. device.JoinStatement is
// length-prefixed for the same reason, after a test caught exactly that.
func (e ConfigEnvelope) Bytes() []byte {
	var b strings.Builder
	for _, f := range []string{
		ConfigStatementV1,
		e.NetworkID,
		e.MembershipID,
		strconv.FormatInt(e.ConfigEpoch, 10),
		strconv.FormatInt(e.BlocklistEpoch, 10),
		e.ConfigSHA256,
		e.CABundleSHA256,
	} {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return []byte(b.String())
}

// SHA256Hex is the digest form the envelope carries.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// NewConfigEnvelope builds an envelope over one generation's material.
func NewConfigEnvelope(networkID, membershipID string, configEpoch, blocklistEpoch int64,
	config, caBundle string) ConfigEnvelope {
	return ConfigEnvelope{
		NetworkID:      networkID,
		MembershipID:   membershipID,
		ConfigEpoch:    configEpoch,
		BlocklistEpoch: blocklistEpoch,
		ConfigSHA256:   SHA256Hex([]byte(config)),
		CABundleSHA256: SHA256Hex([]byte(caBundle)),
	}
}

// SignConfig signs an envelope with the network identity key.
//
// The same key that proves network identity at join, deliberately. The agent has
// already verified it there — VerifyNetworkProof, before it acts on anything the
// control plane said — so the trust anchor is established at the one moment a
// machine is most careful, and no second key has to be distributed. It is not
// the CA key, so a compromise of one is not a compromise of both, and it never
// rotates, so a verifier never has to handle a key change. A machine that cannot
// verify its configuration is a machine that cannot start.
func SignConfig(priv ed25519.PrivateKey, e ConfigEnvelope) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("network identity key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(priv))
	}
	return ed25519.Sign(priv, e.Bytes()), nil
}

// VerifyConfig checks material against an envelope and a signature.
//
// The config and bundle are re-hashed here rather than trusted from the
// envelope. Checking the signature over an envelope whose digests nobody
// recomputed would verify that the control plane once signed SOMETHING, not
// that it signed THIS — which is the whole question.
func VerifyConfig(identityPublicKey []byte, e ConfigEnvelope, sig []byte, config, caBundle string) error {
	if len(identityPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: the pinned network key is %d bytes, want %d",
			ErrConfigSignature, len(identityPublicKey), ed25519.PublicKeySize)
	}
	if got := SHA256Hex([]byte(config)); got != e.ConfigSHA256 {
		return fmt.Errorf("%w: the configuration does not match the digest it was signed with "+
			"(have %s, signed %s)", ErrConfigSignature, got, e.ConfigSHA256)
	}
	if got := SHA256Hex([]byte(caBundle)); got != e.CABundleSHA256 {
		return fmt.Errorf("%w: the trust bundle does not match the digest it was signed with "+
			"(have %s, signed %s)", ErrConfigSignature, got, e.CABundleSHA256)
	}
	if !ed25519.Verify(ed25519.PublicKey(identityPublicKey), e.Bytes(), sig) {
		return ErrConfigSignature
	}
	return nil
}
