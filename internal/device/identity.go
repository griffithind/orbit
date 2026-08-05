// Package device is the machine's own identity: a keypair it generates at first
// start, before it has joined anything and before it has heard of a control
// plane.
//
// Nobody issues it, nothing expires it, and it is the same key across every
// network the machine joins and every control plane it talks to. That is the
// entire point — see docs/design-device-identity.md §2. Everything else a host
// holds is a grant that can lapse; this is the one thing that cannot, which is
// what lets a machine whose data plane is broken report that its data plane is
// broken.
//
// The package is imported by BOTH the agent and the control plane, deliberately.
// The agent signs; the control plane verifies. A signing scheme with two
// implementations is a signing scheme with two chances to disagree, and the
// disagreement shows up as "join fails on some hosts" rather than as a test.
package device

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// P-256, matching the network curve (migration 0021).
//
// Ed25519 would be a defensible choice for a key that only ever signs, and the
// reason not to is consistency rather than cryptography: one curve across the
// device key, the CA, and every certificate means one set of encodings, one
// fingerprint rule, and no place for two halves of the system to disagree about
// what a key looks like.
var curve = elliptic.P256()

// ErrNoKey is returned by Load when no device key exists at the path.
//
// Distinct from a read error because the two call for opposite responses:
// missing means generate one, unreadable means stop and tell somebody. A single
// error would make first start indistinguishable from a corrupted keystore.
var ErrNoKey = errors.New("no device key")

// Identity is a device's keypair. The private half never leaves the machine and
// has no wire representation anywhere in this codebase.
type Identity struct {
	key *ecdsa.PrivateKey

	// spki is the marshalled public key, computed once. It is what gets sent,
	// stored, and fingerprinted, and recomputing it per use would be three
	// chances for one of them to marshal differently.
	spki []byte
}

// Generate creates a new device identity.
func Generate() (*Identity, error) {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	return fromKey(k)
}

func fromKey(k *ecdsa.PrivateKey) (*Identity, error) {
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal device public key: %w", err)
	}
	return &Identity{key: k, spki: spki}, nil
}

// PublicKey returns the DER SubjectPublicKeyInfo.
//
// SPKI rather than a raw point because this key's second job is to be the
// subject of an X.509 device certificate (internal/ca.DeviceCertParams takes
// exactly this), and because SPKI is self-describing: it carries the algorithm
// and the curve, so a future key type does not need a parallel field on the
// wire saying which one it is.
func (i *Identity) PublicKey() []byte { return i.spki }

// Fingerprint is the device's stable name: hex SHA-256 of the SPKI.
func (i *Identity) Fingerprint() string { return Fingerprint(i.spki) }

// Fingerprint computes a device's fingerprint from its marshalled public key.
//
// The canonical definition, and store.DeviceFingerprint calls this rather than
// repeating it, so the value the agent prints and the value the database indexes
// cannot drift apart.
//
// The dependency runs that way round on purpose. This package is linked into the
// agent, which runs on every managed machine and does not otherwise import the
// store — pointing it at internal/store would pull pgx and the whole database
// layer into a binary that never opens a database.
func Fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// Sign signs msg with the device key.
//
// ASN.1 ECDSA over SHA-256, which is what crypto/ecdsa and every PKCS#11 token
// agree on, so the token-backed implementation can slot in behind this without
// changing what a verifier accepts.
func (i *Identity) Sign(msg []byte) ([]byte, error) {
	sum := sha256.Sum256(msg)
	return i.key.Sign(rand.Reader, sum[:], crypto.SHA256)
}

// Verify checks a device signature against a marshalled public key.
//
// The control plane's half. It takes the SPKI bytes rather than a parsed key
// because that is what comes out of the database and off the wire, and parsing
// at the boundary is what keeps a malformed key from becoming a nil dereference
// three frames in.
func Verify(spki, msg, sig []byte) error {
	pub, err := ParsePublicKey(spki)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return errors.New("device signature does not verify")
	}
	return nil
}

// ParsePublicKey decodes and validates a device public key.
//
// It rejects anything that is not P-256 rather than accepting whatever parses.
// A P-224 key parses cleanly and would be recorded as a device identity at a
// strength nothing else in this system assumes.
func ParsePublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	if len(spki) == 0 {
		return nil, errors.New("device public key is empty")
	}
	any, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("parse device public key: %w", err)
	}
	pub, ok := any.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("device public key is %T, want ECDSA P-256", any)
	}
	if pub.Curve != curve {
		return nil, fmt.Errorf("device public key is on %s, want P-256", pub.Curve.Params().Name)
	}
	return pub, nil
}

// Load reads the device key at path, returning ErrNoKey if there is none.
func Load(path string) (*Identity, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, fmt.Errorf("read device key: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("device key at %s is not PEM", path)
	}
	k, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse device key: %w", err)
	}
	if k.Curve != curve {
		return nil, fmt.Errorf("device key is on %s, want P-256", k.Curve.Params().Name)
	}
	return fromKey(k)
}

// LoadOrCreate returns the device key at path, generating and writing one if
// there is none.
//
// TWO PROCESSES MAY RUN THIS AT ONCE, and that is the whole difficulty. A
// systemd unit and an operator running the same command by hand is exactly what
// happens during installation. Getting it wrong leaves the machine holding an
// identity no control plane recognises, and the failure surfaces much later as
// an unexplained join.
//
// Two properties are needed, and the obvious O_EXCL-and-write does not give
// both:
//
//   - EXACTLY ONE key wins. O_EXCL alone provides this.
//   - Nobody ever reads a PARTIAL key. O_EXCL alone does NOT: it creates the
//     file empty and returns, so a racing reader can open it between the create
//     and the write and get zero bytes. TestLoadOrCreateUnderRace found this.
//
// So: write the key to a temporary file in the same directory, complete it, and
// then os.Link it into place. Link is atomic and refuses to overwrite, so the
// file at path is never observable in a half-written state and the first linker
// wins. Losing the race means re-reading the file, which is the right answer —
// the device key is whatever is on disk, and there is only ever one.
func LoadOrCreate(path string) (*Identity, error) {
	id, err := Load(path)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, ErrNoKey) {
		return nil, err
	}

	id, err = Generate()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(id.key)
	if err != nil {
		return nil, fmt.Errorf("marshal device key: %w", err)
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the directory for the device key at %s "+
			"(pass -device-key to put it somewhere writable): %w", dir, err)
	}

	// Same directory, so the link below cannot cross a filesystem boundary.
	tmp, err := os.CreateTemp(dir, ".device.key.*")
	if err != nil {
		// Named with the DESTINATION, not the temporary file the write goes
		// through. A permission error quoting `.device.key.1869827180` sends an
		// operator looking for a file that has never existed.
		return nil, fmt.Errorf("create the device key at %s "+
			"(pass -device-key to put it somewhere writable): %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once linked; the cleanup path when not

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("secure device key: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write device key: %w", err)
	}
	// Synced before linking, not after. A key that is visible at its final name
	// but not yet on disk is one a power loss can erase after the control plane
	// has already been told about it, which is the one inconsistency that
	// cannot be repaired by re-running anything.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write device key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("write device key: %w", err)
	}

	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Load(path)
		}
		return nil, fmt.Errorf("install device key: %w", err)
	}
	return id, nil
}
