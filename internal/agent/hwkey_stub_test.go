//go:build !cgo || !pkcs11

package agent

import (
	"errors"
	"strings"
	"testing"
)

// TestKeypairFromTokenWithoutPKCS11Support.
//
// Tagged to match the stub it tests, so `go test` and `go test -tags pkcs11`
// are both green: under the real build this assertion is false by design, and a
// test that only passes in one configuration is worse than no test.
//
// What it pins: a binary lacking PKCS#11 support must refuse at the seam rather
// than defer to nebula's pkclient stub, whose every method returns "not
// implemented" from inside the Noise handshake. Deferring would produce a host
// that enrolls cleanly, writes a plausible config, starts nebula without
// complaint, and then never forms a tunnel — a failure that surfaces as
// silence, on the machine furthest from the operator.
func TestKeypairFromTokenWithoutPKCS11Support(t *testing.T) {
	_, err := KeypairFromToken("pkcs11:token=orbit;object=host")
	if !errors.Is(err, ErrPKCS11Unsupported) {
		t.Fatalf("KeypairFromToken error = %v, want ErrPKCS11Unsupported", err)
	}
	// The message has to say what to do about it. "not implemented" sends an
	// operator looking at their token; naming the build tag sends them to the
	// binary, which is where the problem is.
	for _, want := range []string{"cgo", "pkcs11"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
