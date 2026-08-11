package enroll

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/slackhq/nebula/cert"
)

// TestAP256KeyMustBeAPointOnTheCurve.
//
// The length and the 0x04 prefix say a key is SHAPED like an uncompressed
// point. They say nothing about whether it is one, and this is the code that
// decides what a certificate authority puts its signature on.
//
// Nebula's cert package runs private keys through crypto/ecdh and never the
// public key carried in a certificate, so nothing between here and a peer's
// handshake inspects it. A Go peer rejects an off-curve point when it parses
// one, which makes this a durability problem rather than a live break: without
// the check, a host enrols, receives a signed certificate, has it distributed
// to the whole network, and then cannot complete a single handshake — reporting
// itself as a machine that never comes up for no visible reason.
func TestAP256KeyMustBeAPointOnTheCurve(t *testing.T) {
	real, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := real.PublicKey().Bytes()
	if err := validatePublicKey(cert.Curve_P256, valid); err != nil {
		t.Fatalf("a real P-256 key was refused: %v", err)
	}

	// Right length, right prefix, coordinates that are not on the curve.
	bogus := make([]byte, 65)
	copy(bogus, valid)
	bogus[0] = 0x04
	bogus[64] ^= 0x01 // perturb Y

	if err := validatePublicKey(cert.Curve_P256, bogus); err == nil {
		t.Error("a 65-byte 0x04-prefixed non-point was accepted for signing")
	}

	// The cheaper checks still stand.
	if err := validatePublicKey(cert.Curve_P256, make([]byte, 65)); err == nil {
		t.Error("an all-zero key was accepted")
	}
	if err := validatePublicKey(cert.Curve_P256, valid[:64]); err == nil {
		t.Error("a short key was accepted")
	}
}
