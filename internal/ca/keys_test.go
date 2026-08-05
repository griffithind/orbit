package ca

import (
	"strings"
	"testing"

	"github.com/slackhq/nebula/cert"
)

// TestParseCurve.
//
// The empty case is the one that matters. `orbitd bootstrap -curve` picks a
// network's curve, and a network's curve is permanent — nebula refuses a
// certificate whose curve differs from its signer's, and nothing updates
// store.Network.Curve after creation. So an empty or misspelled name must be an
// error here, not a silent CURVE25519, or `-curve ""` quietly builds a network
// which Orbit no longer creates.
//
// internal/enroll wraps this and applies its own empty-means-CURVE25519 default
// for wire compatibility with agents that predate P-256. That default belongs
// there, on the wire, and nowhere else.
func TestParseCurve(t *testing.T) {
	for _, tc := range []struct {
		name string
		want cert.Curve
	}{
		{"CURVE25519", cert.Curve_CURVE25519},
		{"25519", cert.Curve_CURVE25519},
		{"X25519", cert.Curve_CURVE25519},
		{"Curve25519", cert.Curve_CURVE25519},
		{"P256", cert.Curve_P256},
	} {
		got, err := ParseCurve(tc.name)
		if err != nil {
			t.Errorf("ParseCurve(%q): unexpected error: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseCurve(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}

	for _, name := range []string{"", " ", "p256", "curve25519", "P-256", "ed25519", "secp256r1"} {
		if _, err := ParseCurve(name); err == nil {
			t.Errorf("ParseCurve(%q) succeeded; every unrecognized spelling must "+
				"fail, because the caller is choosing a network's permanent curve", name)
		}
	}

	// The error has to name the alternatives. Someone hitting it is choosing a
	// value they cannot change later.
	_, err := ParseCurve("nonsense")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"CURVE25519", "P256"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestGenerateCAKeyRejectsUnknownCurve guards the default arm. A zero-value
// cert.Curve is CURVE25519, so a curve that arrived from an uninitialized
// variable would generate silently; only an out-of-range value reaches the
// default.
func TestGenerateCAKeyRejectsUnknownCurve(t *testing.T) {
	if _, _, err := GenerateCAKey(cert.Curve(99)); err == nil {
		t.Fatal("GenerateCAKey accepted an unknown curve")
	}
	if _, _, err := GenerateHostKey(cert.Curve(99)); err == nil {
		t.Fatal("GenerateHostKey accepted an unknown curve")
	}
}
