//go:build cgo && pkcs11

package device

import (
	"os"
	"testing"
	"time"
)

// A device identity whose key lives on a real token.
//
// Skipped unless ORBIT_TEST_PKCS11_URI names one, because it needs hardware (or
// a software TPM) that a normal `go test` run does not have. The value is that
// it exercises the one thing unit tests cannot fake: that a signature produced
// ON the token verifies against the public key READ from the token, through
// exactly the SPKI conversion and ASN.1 encoding the rest of Orbit uses.
func TestTokenBackedIdentitySignsAndVerifies(t *testing.T) {
	uri := os.Getenv("ORBIT_TEST_PKCS11_URI")
	if uri == "" {
		t.Skip("set ORBIT_TEST_PKCS11_URI to a pkcs11: URI to run this")
	}

	id, err := Open(uri)
	if err != nil {
		t.Fatalf("open the token-backed identity: %v", err)
	}
	if id.Backing() != BackingToken {
		t.Errorf("backing = %q, want %q", id.Backing(), BackingToken)
	}
	if len(id.PublicKey()) == 0 {
		t.Fatal("no public key was read from the token")
	}
	if id.Fingerprint() == "" {
		t.Fatal("no fingerprint")
	}

	// The real assertion: a join statement signed on the token verifies under
	// the SPKI this package derived from the token's raw EC point. If the
	// conversion or the digest handling were wrong, this is where it shows.
	msg := JoinStatement("test-network", "host-01", id.Fingerprint(), time.Unix(1770000000, 0))
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatalf("sign on the token: %v", err)
	}
	if err := Verify(id.PublicKey(), msg, sig); err != nil {
		t.Fatalf("a signature made on the token did not verify: %v", err)
	}

	// And it must not verify over different bytes, or the check above proves
	// nothing about what was signed.
	if err := Verify(id.PublicKey(), append(msg, '!'), sig); err == nil {
		t.Fatal("the signature verified over altered bytes")
	}
}
