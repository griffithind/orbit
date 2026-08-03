package ca_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/ca"
)

// The file signer is the supported path for a self-hosted deployment, so its
// failure modes need to be loud. A root key that silently loads from a
// world-readable file, or an encrypted key that fails with a parse error
// because nobody supplied a passphrase, are exactly the mistakes that go
// unnoticed until they matter.

func writeCAKey(t *testing.T, dir string, mode os.FileMode) (path string, pub []byte) {
	t.Helper()
	pub, priv, err := ca.GenerateCAKey(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "ca.key")
	if err := os.WriteFile(path, cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, priv), mode); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

func TestFileSignerRefusesReadableKey(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeCAKey(t, dir, 0o644)

	_, err := ca.NewFileSignerFromPath(path, nil)
	if !errors.Is(err, ca.ErrKeyPermissions) {
		t.Fatalf("loading a 0644 CA key = %v, want ErrKeyPermissions", err)
	}

	// And it loads once corrected, so the check is about the mode and nothing
	// else.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ca.NewFileSignerFromPath(path, nil)
	if err != nil {
		t.Fatalf("loading a 0600 CA key: %v", err)
	}
	s.Close()
}

func TestFileSignerEncryptedRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path, pub := writeCAKey(t, dir, 0o600)
	pass := []byte("correct horse battery staple")

	if err := ca.EncryptKeyFile(path, pass); err != nil {
		t.Fatalf("EncryptKeyFile: %v", err)
	}

	raw, _ := os.ReadFile(path)
	if !ca.IsEncryptedKey(raw) {
		t.Fatal("key is not encrypted after EncryptKeyFile")
	}
	// The plaintext key must be gone from disk, not merely superseded.
	if _, _, _, err := cert.UnmarshalSigningPrivateKeyFromPEM(raw); err == nil {
		t.Error("the file still parses as a plaintext signing key")
	}

	// Encrypting again is a no-op rather than double-encrypting.
	if err := ca.EncryptKeyFile(path, pass); err != nil {
		t.Fatalf("second EncryptKeyFile: %v", err)
	}

	s, err := ca.NewFileSignerFromPath(path, pass)
	if err != nil {
		t.Fatalf("load encrypted key: %v", err)
	}
	defer s.Close()

	got, err := s.Public(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pub) {
		t.Error("decrypted key does not match the original")
	}
}

// TestFileSignerMismatchedPassphraseIsClear covers both directions of the
// mistake, because inferring "is this encrypted" from whether a passphrase was
// supplied produces baffling errors either way.
func TestFileSignerMismatchedPassphraseIsClear(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeCAKey(t, dir, 0o600)

	// Plaintext key, passphrase supplied.
	_, err := ca.NewFileSignerFromPath(path, []byte("unnecessary"))
	if err == nil {
		t.Fatal("a passphrase against a plaintext key was accepted")
	}
	if !contains(err.Error(), "not encrypted") {
		t.Errorf("error does not explain the mismatch: %v", err)
	}

	// Encrypted key, no passphrase.
	if err := ca.EncryptKeyFile(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	_, err = ca.NewFileSignerFromPath(path, nil)
	if !errors.Is(err, ca.ErrPassphraseRequired) {
		t.Fatalf("encrypted key with no passphrase = %v, want ErrPassphraseRequired", err)
	}
	if !contains(err.Error(), "ORBIT_CA_KEY_PASSPHRASE") {
		t.Errorf("error does not say how to fix it: %v", err)
	}

	// Wrong passphrase.
	if _, err := ca.NewFileSignerFromPath(path, []byte("wrong")); err == nil {
		t.Error("a wrong passphrase was accepted")
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
