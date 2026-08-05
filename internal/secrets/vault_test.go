package secrets

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestMain turns the KDF down for everything in this package.
//
// Nothing here is testing Argon2 — the cases are about binding, verification and
// salting, all of which behave identically at any cost — and a derivation per
// case adds up. TestProductionKEKParametersAreUsable covers the real numbers.
func TestMain(m *testing.M) {
	argonMemory, argonTime, argonThreads = 8*1024, 1, 1
	os.Exit(m.Run())
}

var testKEK = func() *KEK {
	salt, err := NewSalt()
	if err != nil {
		panic(err)
	}
	k, err := DeriveKEK([]byte("correct horse battery staple"), salt)
	if err != nil {
		panic(err)
	}
	return k
}()

func TestSealOpenRoundTrip(t *testing.T) {
	plaintext := []byte("a private key, notionally")
	nonce, ct, err := testKEK.Seal("id-1", KindCASigning, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if strings.Contains(string(ct), string(plaintext)) {
		t.Fatal("the plaintext is visible in the ciphertext")
	}

	got, err := testKEK.Open("id-1", KindCASigning, nonce, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip returned %q", got)
	}
}

// TestSealBindsIdAndKind is the check that makes database WRITE access less
// useful than it looks.
//
// Both stored kinds are Ed25519 keys, so a row moved from the identity slot into
// a CA's slot would parse perfectly and let the control plane sign certificates
// with a key whose custody rules are weaker. Authenticating the id and kind as
// additional data turns that substitution into a decryption failure.
func TestSealBindsIdAndKind(t *testing.T) {
	nonce, ct, err := testKEK.Seal("id-1", KindNetworkIdentity, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := testKEK.Open("id-1", KindCASigning, nonce, ct); err == nil {
		t.Error("a network identity key opened as a CA signing key")
	}
	if _, err := testKEK.Open("id-2", KindNetworkIdentity, nonce, ct); err == nil {
		t.Error("a secret opened under a different row id")
	}
	// And tampering with the ciphertext fails, which is what makes it an AEAD
	// rather than a cipher.
	altered := make([]byte, len(ct))
	copy(altered, ct)
	altered[0] ^= 0x01
	if _, err := testKEK.Open("id-1", KindNetworkIdentity, nonce, altered); err == nil {
		t.Error("an altered ciphertext opened")
	}
}

// TestWrongPassphraseIsCaughtByTheVerifier.
//
// The point is WHERE it is caught. A replica with a mistyped passphrase that
// started cleanly would fail on its first signing operation — while somebody was
// adding a machine, days after the mistake, with nothing connecting the two.
func TestWrongPassphraseIsCaughtByTheVerifier(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	right, err := DeriveKEK([]byte("the real passphrase"), salt)
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := right.SealVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if err := right.CheckVerifier(nonce, ct); err != nil {
		t.Fatalf("the passphrase that sealed the verifier did not check: %v", err)
	}

	wrong, err := DeriveKEK([]byte("a typo"), salt)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.CheckVerifier(nonce, ct); !errors.Is(err, ErrWrongKEK) {
		t.Fatalf("error = %v, want ErrWrongKEK", err)
	}
}

// TestSaltMakesDeploymentsDistinct.
//
// The salt is not secret and is stored beside the ciphertext. Its whole job is
// that one passphrase reused across two Orbit deployments yields two unrelated
// keys — so a KEK recovered from one cannot open the other's secrets.
func TestSaltMakesDeploymentsDistinct(t *testing.T) {
	pass := []byte("shared across two deployments, as passphrases are")
	saltA, _ := NewSalt()
	saltB, _ := NewSalt()

	a, err := DeriveKEK(pass, saltA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKEK(pass, saltB)
	if err != nil {
		t.Fatal(err)
	}

	nonce, ct, err := a.Seal("id", KindCASigning, []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open("id", KindCASigning, nonce, ct); err == nil {
		t.Fatal("the same passphrase under a different salt opened the secret")
	}
}

func TestDeriveKEKRejectsNothing(t *testing.T) {
	salt, _ := NewSalt()
	if _, err := DeriveKEK(nil, salt); !errors.Is(err, ErrNoKEK) {
		t.Errorf("error = %v, want ErrNoKEK", err)
	}
	if _, err := DeriveKEK([]byte("x"), []byte("short")); err == nil {
		t.Error("a short salt was accepted")
	}
}

// TestProductionKEKParametersAreUsable.
//
// TestMain turns the KDF down so the rest of the package is fast. That leaves
// the real parameters untested, which is exactly how a deployment discovers at
// boot that its control plane wants memory it does not have.
//
// One derivation at the numbers production uses, asserting that it completes and
// produces a working key.
func TestProductionKEKParametersAreUsable(t *testing.T) {
	mem, tim, thr := argonMemory, argonTime, argonThreads
	argonMemory, argonTime, argonThreads = defaultArgonMemory, defaultArgonTime, defaultArgonThreads
	t.Cleanup(func() { argonMemory, argonTime, argonThreads = mem, tim, thr })

	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	k, err := DeriveKEK([]byte("production parameters"), salt)
	if err != nil {
		t.Fatalf("derive at production parameters: %v", err)
	}
	nonce, ct, err := k.SealVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if err := k.CheckVerifier(nonce, ct); err != nil {
		t.Fatalf("verifier round trip at production parameters: %v", err)
	}
}

// TestConfigureKDFOnlyGoesUp.
//
// A knob that can weaken a KDF is one somebody eventually turns the wrong way
// while chasing a slow boot, and the result is silent. Raising it is visible —
// the boot gets slower — so only that direction is allowed.
func TestConfigureKDFOnlyGoesUp(t *testing.T) {
	orig := argonMemory
	t.Cleanup(func() { argonMemory = orig })

	t.Setenv("ORBIT_KEK_ARGON_MEMORY_MIB", "16")
	if err := ConfigureKDF(); err == nil {
		t.Error("a value below the built-in default was accepted")
	}

	t.Setenv("ORBIT_KEK_ARGON_MEMORY_MIB", "not-a-number")
	if err := ConfigureKDF(); err == nil {
		t.Error("a non-numeric value was accepted")
	}

	t.Setenv("ORBIT_KEK_ARGON_MEMORY_MIB", "256")
	if err := ConfigureKDF(); err != nil {
		t.Fatalf("raising the cost was refused: %v", err)
	}
	if argonMemory != 256*1024 {
		t.Errorf("argonMemory = %d KiB, want %d", argonMemory, 256*1024)
	}
}
