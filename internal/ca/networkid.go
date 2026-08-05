package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/slackhq/nebula/cert"
)

// Network IDs.
//
// A network's ID is derived from its NETWORK IDENTITY KEY, which makes it
// something stronger than a label: it is a COMMITMENT TO A TRUST ANCHOR. A
// machine joining `p8k3zj9x2mq4wr7t` can check that whatever control plane
// answers actually holds the key that ID names, so pointing a machine at a
// hostile URL stops working. A UUID plus a URL cannot defend against that,
// because nothing in either one says which key to expect.
//
// NOT THE CA KEY, and this is the correction that matters.
//
// The obvious choice is the CA's public key — it is already the mesh's root of
// trust, and it needs no second key. It is wrong. Orbit rotates CAs: create,
// activate, retire. A rotation gives the network a new CA with a new key, so an
// ID derived from the active CA CHANGES ON EVERY ROTATION — every machine's
// stored ID becomes wrong at once and verification fails fleet-wide. An
// identifier that changes is not an identifier.
//
// So the ID commits to a key generated once at bootstrap, never rotated, and
// never used to sign a certificate. Its only jobs are to name the network and to
// prove, during a join, that the control plane answering is the one the ID
// names. docs/design-device-identity.md §4 records the rotation chain that was
// considered and rejected.
//
// ZeroTier's trick — encoding the controller's address in the ID's top bits, so
// `join <id>` needs nothing else — does not transfer: an Orbit control plane is
// a URL, not a routable identity, so the URL stays a separate argument. What
// transfers is the part worth more than brevity.
//
// This sits BESIDE Network.slug rather than replacing it. Different jobs: the
// slug is the memorable name and the directory on every machine, the ID is the
// verifiable one. A slug can be renamed; an ID cannot, because the key it names
// cannot change.

// networkIDBytes is how much of the hash the ID carries.
//
// 80 bits. The attack this resists is second-preimage — someone standing up a
// control plane whose identity key happens to hash to your network's ID, so a
// machine pointed at their URL accepts them — and 2^80 puts that out of reach.
//
// ZeroTier gets away with 40 bits only because a memory-hard function makes
// grinding expensive. There is no proof of work here (see
// docs/design-device-identity.md §6), so the length has to do that work alone.
const networkIDBytes = 10

// crockford is Crockford's base32 alphabet: no I, L, O or U, because those are
// the glyphs people confuse when reading a string aloud or copying it by hand.
// Someone will type these.
var crockford = base32.
	NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").
	WithPadding(base32.NoPadding)

// NetworkIDLen is the number of characters in a network ID.
const NetworkIDLen = 16 // ceil(80 / 5)

// ErrNetworkIDMismatch means an ID does not name the key that was offered.
//
// The one error in this file worth handling rather than logging: it is what a
// machine sees when the control plane it reached is not the one its ID commits
// to.
var ErrNetworkIDMismatch = errors.New("network id does not match this control plane")

// GenerateNetworkIdentity creates a network's identity keypair.
//
// Ed25519, and deliberately NOT the network's nebula curve. The two are
// unrelated: a certificate's curve must match its signer's, so the CA's curve is
// forced by nebula, while this key never touches a certificate. It signs exactly
// one thing — a proof that this control plane holds it — so a P-256 network and
// a Curve25519 network get the same kind of identity key.
//
// Generated once, at bootstrap, and never rotated. There is no rotation path on
// purpose: rotating it would change the network's ID, which is the one thing an
// ID must never do.
func GenerateNetworkIdentity() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate network identity key: %w", err)
	}
	return pub, priv, nil
}

// NetworkIDFor derives the network ID committed to by an identity public key.
//
// The length check is the encoding check: an Ed25519 public key has exactly one
// representation, so unlike a nebula CA key there is no way to hash "the same
// key in a different encoding" and get a different ID.
func NetworkIDFor(identityPublicKey []byte) (string, error) {
	if len(identityPublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("network identity key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(identityPublicKey))
	}
	sum := sha256.Sum256(identityPublicKey)
	return crockford.EncodeToString(sum[:networkIDBytes]), nil
}

// NormalizeNetworkID canonicalises a user-typed ID.
//
// Crockford base32 is case-insensitive by design and treats a few glyphs as
// interchangeable, so "P8K3-ZJ9X-2MQ4-WR7T" and "p8k3zj9x2mq4wr7t" are the same
// identifier. Accepting both is not leniency for its own sake — these get read
// off a screen and typed into a terminal, sometimes over a phone.
func NormalizeNetworkID(id string) string {
	var b strings.Builder
	b.Grow(len(id))
	for _, r := range strings.ToLower(id) {
		switch r {
		case '-', ' ', '_':
			// Grouping separators people add to make it readable.
			continue
		case 'i', 'l':
			// Crockford: both decode as 1.
			b.WriteRune('1')
		case 'o':
			// Crockford: decodes as 0.
			b.WriteRune('0')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ParseNetworkID validates the shape of an ID without knowing any key.
//
// Shape only. An ID that parses is well-formed, not correct — correctness is
// VerifyNetworkID, which needs the key. Kept separate so a CLI can reject a typo
// before making a network call, and so a reference that may be "a uuid, a slug,
// or a network ID" can tell which it is being handed.
func ParseNetworkID(id string) (string, error) {
	norm := NormalizeNetworkID(id)
	if len(norm) != NetworkIDLen {
		return "", fmt.Errorf("network id must be %d characters, got %d (%q)", NetworkIDLen, len(norm), id)
	}
	if _, err := crockford.DecodeString(norm); err != nil {
		return "", fmt.Errorf("network id %q is not valid base32: %w", id, err)
	}
	return norm, nil
}

// VerifyNetworkID reports whether an identity public key is the one an ID
// commits to.
//
// HALF of what makes the ID worth deriving; the other half is
// VerifyNetworkProof. This establishes that the key offered is the expected key,
// and on its own proves nothing — anyone who read the ID off a wiki can serve
// the right public key. A joining machine checks both.
//
// Constant time, because the comparison is between a value an attacker supplies
// and one they are trying to match. The timing leak is small and the mitigation
// is one function call.
func VerifyNetworkID(id string, identityPublicKey []byte) error {
	want, err := ParseNetworkID(id)
	if err != nil {
		return err
	}
	got, err := NetworkIDFor(identityPublicKey)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return fmt.Errorf("%w: expected %s, this control plane is %s", ErrNetworkIDMismatch, want, got)
	}
	return nil
}

// SignNetworkProof signs a challenge with the network identity key.
//
// The challenge is the joining machine's own canonical join statement, which
// already carries that machine's key fingerprint and a timestamp. Signing that
// rather than a constant is what makes the proof unreplayable: a recording of
// one machine's join cannot convince a different machine, or the same machine
// later.
func SignNetworkProof(priv ed25519.PrivateKey, challenge []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("network identity key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(priv))
	}
	return ed25519.Sign(priv, challenge), nil
}

// VerifyNetworkProof checks that a control plane holds the key its ID names.
//
// The check the whole scheme exists for, and the one a client must not skip.
// VerifyNetworkID alone says "you served the right public key", which an
// attacker who read the ID off a wiki can also do. This says "you hold the
// private half", which only the real control plane can.
func VerifyNetworkProof(id string, identityPublicKey, challenge, proof []byte) error {
	if err := VerifyNetworkID(id, identityPublicKey); err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(identityPublicKey), challenge, proof) {
		return fmt.Errorf("%w: it served the right public key but cannot prove it holds the private half",
			ErrNetworkIDMismatch)
	}
	return nil
}

//------------------------------------------------------------------------------
// Custody
//------------------------------------------------------------------------------
//
// The private half gets the CA key's treatment: its own file, mode 0600 enforced
// at load, and the same passphrase. Someone holding it cannot mint a certificate
// — that needs the CA key — but they can convince every machine that joins
// afterwards that their control plane is this network, which is close enough to
// warrant the same care.
//
// It is deliberately NOT in the database. Migration 0017 carries a tripwire that
// fails if a column which could hold it is ever added.

// MarshalNetworkIdentityPEM encodes the identity private key for storage.
//
// Nebula's own Ed25519 signing-key PEM, deliberately, even though this key never
// touches nebula. The payoff is that EncryptKeyFile, the passphrase handling and
// `orbitd ca encrypt` all work on it unchanged — one encryption path for both
// keys instead of a second one that would inevitably differ.
//
// An earlier version used a distinct PEM banner so that swapping this file for
// the CA key would be caught at parse. That protection was not worth a private
// crypto path, and it was redundant: loading the wrong key produces a network ID
// that does not match, and every join then fails with ErrNetworkIDMismatch,
// which names both IDs. A wrong key is caught either way, and the ID check
// catches strictly more — including a key that parses perfectly and is simply
// the wrong network's.
func MarshalNetworkIdentityPEM(priv ed25519.PrivateKey) []byte {
	return cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, priv)
}

// LoadNetworkIdentity reads the identity private key from a signer ref.
//
// Only `file://` today, and the ref is the same opaque-locator shape
// orbit.ca.signer_ref uses so that a KMS-backed one is an added case here rather
// than a change everywhere. The mode check refuses rather than warns, for the
// reason the CA key's does: a key the whole machine can read is a mistake nobody
// notices.
func LoadNetworkIdentity(ref string, passphrase []byte) (ed25519.PrivateKey, error) {
	path, ok := strings.CutPrefix(ref, "file://")
	if !ok {
		return nil, fmt.Errorf("%w: network identity ref %q is not file://",
			ErrSignerUnavailable, ref)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: stat %s: %w", ErrSignerUnavailable, path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s is mode %04o, want 0600 (chmod 600 %s)",
			ErrKeyPermissions, path, mode, path)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrSignerUnavailable, path, err)
	}

	if IsEncryptedKey(b) {
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("%w: set ORBIT_CA_KEY_PASSPHRASE or ORBIT_CA_KEY_PASSPHRASE_FILE",
				ErrPassphraseRequired)
		}
		_, raw, _, err := cert.DecryptAndUnmarshalSigningPrivateKey(passphrase, b)
		if err != nil {
			return nil, fmt.Errorf("decrypt network identity key %s: %w", path, err)
		}
		return checkIdentityKey(raw, path)
	}
	key, err := ParseNetworkIdentityPEM(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// ParseNetworkIdentityPEM decodes an identity key from unencrypted PEM.
//
// Split out from LoadNetworkIdentity so the vault can reuse it. A key that came
// out of the database has already been decrypted and has no file, no mode and no
// passphrase — but it is byte-identical PEM, and one parser rather than two is
// what stops a vault-stored key and a file-stored key from ever differing.
func ParseNetworkIdentityPEM(b []byte) (ed25519.PrivateKey, error) {
	raw, _, _, err := cert.UnmarshalSigningPrivateKeyFromPEM(b)
	if err != nil {
		return nil, fmt.Errorf("parse network identity key: %w", err)
	}
	return checkIdentityKey(raw, "the stored key")
}

// checkIdentityKey rejects anything that is not an Ed25519 private key.
//
// The two key files sit side by side and are easy to transpose in a runbook. A
// P-256 CA key is the wrong length and is caught here; a Curve25519 one has the
// same shape and is caught later, by the network ID not matching — which is the
// better error anyway, because it names both IDs.
func checkIdentityKey(raw []byte, what string) (ed25519.PrivateKey, error) {
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s holds %d bytes, want an Ed25519 private key of %d — "+
			"is this the CA key?", what, len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}
