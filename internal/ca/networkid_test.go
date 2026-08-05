package ca

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slackhq/nebula/cert"
)

// genIdentity is the network identity keypair every case here starts from.
//
// Not a CA key, and the tests were rewritten when that changed: an ID derived
// from the active CA would change on every rotation, which is the one thing an
// identifier must not do. See networkid.go.
// The ed25519 types, not []byte: ed25519.PrivateKey.Equal type-asserts its
// argument, so comparing against a plain []byte returns false however identical
// the bytes are. They still satisfy the []byte parameters everywhere else.
func genIdentity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := GenerateNetworkIdentity()
	if err != nil {
		t.Fatalf("generate network identity: %v", err)
	}
	return pub, priv
}

func TestNetworkIDForIsStableAndDistinct(t *testing.T) {
	pubA, _ := genIdentity(t)
	pubB, _ := genIdentity(t)

	idA, err := NetworkIDFor(pubA)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	again, err := NetworkIDFor(pubA)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if idA != again {
		t.Fatalf("derivation is not deterministic: %q then %q", idA, again)
	}

	idB, err := NetworkIDFor(pubB)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if idA == idB {
		t.Fatal("two different identity keys produced the same network id")
	}

	if len(idA) != NetworkIDLen {
		t.Errorf("id %q is %d chars, want %d", idA, len(idA), NetworkIDLen)
	}
	// The alphabet excludes the glyphs people confuse. If one appears, the
	// encoding was changed and every ID already written down is now ambiguous.
	for _, bad := range []string{"i", "l", "o", "u"} {
		if strings.Contains(idA, bad) {
			t.Errorf("id %q contains %q, which Crockford base32 excludes", idA, bad)
		}
	}
	if idA != strings.ToLower(idA) {
		t.Errorf("id %q is not lowercase", idA)
	}
}

// TestNormalizeNetworkID covers what someone actually types.
//
// These get read off a screen and typed into a terminal, sometimes dictated
// over a phone. Crockford's substitutions exist for exactly that, and rejecting
// a correctly-heard-but-differently-written ID would be a self-inflicted
// support burden.
func TestNormalizeNetworkID(t *testing.T) {
	const want = "p8k3zj9x2mq4wr71"
	for _, typed := range []string{
		"p8k3zj9x2mq4wr71",
		"P8K3ZJ9X2MQ4WR71",
		"p8k3-zj9x-2mq4-wr71",
		"p8k3 zj9x 2mq4 wr71",
		"P8K3ZJ9X2MQ4WR7I", // I -> 1
		"P8K3ZJ9X2MQ4WR7l", // l -> 1
	} {
		if got := NormalizeNetworkID(typed); got != want {
			t.Errorf("NormalizeNetworkID(%q) = %q, want %q", typed, got, want)
		}
	}
	// O -> 0 is the other substitution, checked separately so the expected
	// value stays honest.
	if got := NormalizeNetworkID("O8k3zj9x2mq4wr71"); got != "08k3zj9x2mq4wr71" {
		t.Errorf("O was not normalised to 0: %q", got)
	}
}

func TestParseNetworkIDRejectsMalformed(t *testing.T) {
	for _, id := range []string{
		"",
		"too-short",
		"p8k3zj9x2mq4wr71extra",
	} {
		if _, err := ParseNetworkID(id); err == nil {
			t.Errorf("ParseNetworkID(%q) accepted a malformed id", id)
		}
	}
}

// TestVerifyNetworkID is the check the whole derivation exists for.
//
// A host holds an ID, dials a URL, is handed a CA, and asks whether that CA is
// the one its ID commits to. Without this the host trusts whatever the URL
// served and the ID is decoration — which is precisely the attack a UUID plus a
// URL cannot defend against.
func TestVerifyNetworkID(t *testing.T) {
	pub, _ := genIdentity(t)
	id, err := NetworkIDFor(pub)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	if err := VerifyNetworkID(id, pub); err != nil {
		t.Fatalf("the key that produced this id did not verify against it: %v", err)
	}
	// Written the way an operator would.
	if err := VerifyNetworkID(strings.ToUpper(id), pub); err != nil {
		t.Errorf("uppercase id did not verify: %v", err)
	}

	// A different key must be rejected. This is the hostile-control-plane case.
	other, _ := genIdentity(t)
	err = VerifyNetworkID(id, other)
	if err == nil {
		t.Fatal("an unrelated identity key verified against this network id")
	}
	if !errors.Is(err, ErrNetworkIDMismatch) {
		t.Errorf("error = %v, want ErrNetworkIDMismatch so callers can act on it", err)
	}
	// The message must show both, or an operator cannot tell which end is wrong.
	if !strings.Contains(err.Error(), id) {
		t.Errorf("error %q does not name the expected id", err)
	}
}

// TestNetworkIDDependsOnEveryBitOfTheKey.
//
// The whole security claim is second-preimage resistance over 80 bits, which
// only holds if the derivation actually depends on the key.
func TestNetworkIDDependsOnEveryBitOfTheKey(t *testing.T) {
	pub, _ := genIdentity(t)
	raw, err := NetworkIDFor(pub)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	// One byte different is a different network.
	altered := make([]byte, len(pub))
	copy(altered, pub)
	altered[0] ^= 0x01
	other, err := NetworkIDFor(altered)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if raw == other {
		t.Fatal("a one-bit change to the identity key produced the same network id")
	}
}

// TestVerifyNetworkProof is the check the scheme exists for.
//
// VerifyNetworkID alone establishes that the control plane served the expected
// public key — which anyone who read the ID off a wiki can also do. Only the
// proof distinguishes the real control plane from one that merely knows its
// name.
func TestVerifyNetworkProof(t *testing.T) {
	pub, priv := genIdentity(t)
	id, err := NetworkIDFor(pub)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	challenge := []byte("the joining machine's canonical statement")
	proof, err := SignNetworkProof(priv, challenge)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyNetworkProof(id, pub, challenge, proof); err != nil {
		t.Fatalf("a genuine proof did not verify: %v", err)
	}

	// THE ATTACK THIS DEFENDS AGAINST: a control plane that knows the network
	// ID, and therefore can serve the right public key, but does not hold the
	// private half. Without the proof this case is indistinguishable from the
	// real thing.
	_, impostorPriv := genIdentity(t)
	forged, err := SignNetworkProof(impostorPriv, challenge)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyNetworkProof(id, pub, challenge, forged)
	if err == nil {
		t.Fatal("a control plane that does not hold the identity key passed verification")
	}
	if !errors.Is(err, ErrNetworkIDMismatch) {
		t.Errorf("error = %v, want ErrNetworkIDMismatch", err)
	}

	// A proof for one challenge must not verify against another. This is what
	// makes a recorded join useless to replay: the challenge is the joining
	// machine's own statement, carrying its fingerprint and a timestamp.
	if err := VerifyNetworkProof(id, pub, []byte("a different machine's statement"), proof); err == nil {
		t.Error("a proof verified against a challenge it was not made over")
	}

	// And serving a different key than the ID names fails before the signature
	// is even considered.
	otherPub, otherPriv := genIdentity(t)
	otherProof, err := SignNetworkProof(otherPriv, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNetworkProof(id, otherPub, challenge, otherProof); err == nil {
		t.Error("a control plane with an internally consistent but unrelated key passed")
	}
}

func TestSignNetworkProofRejectsAMalformedKey(t *testing.T) {
	if _, err := SignNetworkProof(make([]byte, 7), []byte("x")); err == nil {
		t.Error("a short key was accepted as a network identity key")
	}
}

// TestNetworkIdentityRoundTripsThroughAFile, both plaintext and encrypted.
//
// The identity key uses nebula's Ed25519 signing-key PEM so that one encryption
// path serves both keys. That is only worth it if a key encrypted by
// EncryptKeyFile actually loads again — which is the thing a bootstrap does once
// and a control plane does on every start.
func TestNetworkIdentityRoundTripsThroughAFile(t *testing.T) {
	_, priv := genIdentity(t)

	for _, tc := range []struct {
		name       string
		passphrase []byte
	}{
		{"plaintext", nil},
		{"encrypted", []byte("correct horse battery staple")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "network-identity.key")
			if err := os.WriteFile(path, MarshalNetworkIdentityPEM(priv), 0o600); err != nil {
				t.Fatal(err)
			}
			if len(tc.passphrase) > 0 {
				if err := EncryptKeyFile(path, tc.passphrase); err != nil {
					t.Fatalf("encrypt: %v", err)
				}
			}

			got, err := LoadNetworkIdentity("file://"+path, tc.passphrase)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if !got.Equal(priv) {
				t.Fatal("the key that came back is not the key that went in")
			}
		})
	}
}

// TestLoadNetworkIdentityRefusesAWorldReadableKey.
//
// Refuse, not warn. Someone holding this key can convince every machine that
// joins afterwards that their control plane is this network, and a key the whole
// machine can read is a mistake nobody notices.
func TestLoadNetworkIdentityRefusesAWorldReadableKey(t *testing.T) {
	_, priv := genIdentity(t)
	path := filepath.Join(t.TempDir(), "network-identity.key")
	if err := os.WriteFile(path, MarshalNetworkIdentityPEM(priv), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadNetworkIdentity("file://"+path, nil)
	if !errors.Is(err, ErrKeyPermissions) {
		t.Fatalf("error = %v, want ErrKeyPermissions", err)
	}
}

// TestLoadNetworkIdentityRejectsTheCAKey.
//
// The two files sit side by side in /var/lib/orbit and are easy to transpose in
// a runbook. A P-256 CA key is the wrong length and is caught here; a Curve25519
// one has the same shape and is caught later, by the network ID not matching —
// which is the better error anyway, because it names both IDs.
func TestLoadNetworkIdentityRejectsTheCAKey(t *testing.T) {
	_, caPriv, err := GenerateCAKey(cert.Curve_P256)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.key")
	if err := os.WriteFile(path, cert.MarshalSigningPrivateKeyToPEM(cert.Curve_P256, caPriv), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNetworkIdentity("file://"+path, nil); err == nil {
		t.Fatal("a P-256 CA key was accepted as a network identity key")
	}
}

func TestLoadNetworkIdentityRejectsANonFileRef(t *testing.T) {
	if _, err := LoadNetworkIdentity("awskms://key/abc", nil); !errors.Is(err, ErrSignerUnavailable) {
		t.Errorf("error = %v, want ErrSignerUnavailable", err)
	}
}
