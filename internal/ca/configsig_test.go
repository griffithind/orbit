package ca

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func testIdentity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestConfigSignatureRoundTrips(t *testing.T) {
	pub, priv := testIdentity(t)
	const cfg, bundle = "listen:\n  port: 4242\n", "-----BEGIN NEBULA CERTIFICATE-----\n"

	e := NewConfigEnvelope("01ABCDEF", "m-1", 47, 12, cfg, bundle)
	sig, err := SignConfig(priv, e)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConfig(pub, e, sig, cfg, bundle); err != nil {
		t.Fatalf("freshly signed material did not verify: %v", err)
	}
}

// The digests in the envelope are not taken on trust.
//
// A verifier that checked the signature over an envelope whose digests nobody
// recomputed would confirm the control plane once signed SOMETHING, not that it
// signed THIS — which is the entire question being asked.
func TestConfigSignatureCatchesAnEditedConfig(t *testing.T) {
	pub, priv := testIdentity(t)
	const cfg, bundle = "firewall:\n  inbound: []\n", "bundle"

	e := NewConfigEnvelope("01ABCDEF", "m-1", 47, 12, cfg, bundle)
	sig, err := SignConfig(priv, e)
	if err != nil {
		t.Fatal(err)
	}

	edited := cfg + "\n# an operator was here\n"
	err = VerifyConfig(pub, e, sig, edited, bundle)
	if err == nil {
		t.Fatal("an edited configuration verified")
	}
	if !strings.Contains(err.Error(), "does not match the digest") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}

	if err := VerifyConfig(pub, e, sig, cfg, "a different bundle"); err == nil {
		t.Error("a swapped trust bundle verified")
	}
}

// Every bound field must actually be bound. A field in the envelope that does
// not reach the signed bytes is a field an attacker can change freely, and the
// failure is silent — the signature still verifies.
func TestConfigSignatureBindsEveryField(t *testing.T) {
	pub, priv := testIdentity(t)
	const cfg, bundle = "cfg", "bundle"
	base := NewConfigEnvelope("01ABCDEF", "m-1", 47, 12, cfg, bundle)
	sig, err := SignConfig(priv, base)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*ConfigEnvelope){
		"network id":      func(e *ConfigEnvelope) { e.NetworkID = "01FEDCBA" },
		"membership id":   func(e *ConfigEnvelope) { e.MembershipID = "m-2" },
		"config epoch":    func(e *ConfigEnvelope) { e.ConfigEpoch = 48 },
		"blocklist epoch": func(e *ConfigEnvelope) { e.BlocklistEpoch = 13 },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := base
			mutate(&tampered)
			if err := VerifyConfig(pub, tampered, sig, cfg, bundle); err == nil {
				t.Errorf("%s is not covered by the signature", name)
			}
		})
	}
}

// A different network's key must not verify, which is what stops a machine
// pointed at a hostile control plane from installing its configuration.
func TestConfigSignatureRefusesAnotherNetworksKey(t *testing.T) {
	_, priv := testIdentity(t)
	otherPub, _ := testIdentity(t)
	const cfg, bundle = "cfg", "bundle"

	e := NewConfigEnvelope("01ABCDEF", "m-1", 1, 1, cfg, bundle)
	sig, err := SignConfig(priv, e)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConfig(otherPub, e, sig, cfg, bundle); err == nil {
		t.Fatal("material verified under a different network's key")
	}
}

// The encoding must be unambiguous: no two distinct envelopes may produce the
// same signed bytes.
//
// This is the test that forced length-prefixing on device.JoinStatement. A
// delimiter-joined encoding lets fields shift across the delimiter — here, a
// membership id that swallows the epoch — and a signature over one envelope
// then verifies over a different one.
func TestConfigEnvelopeIsUnambiguous(t *testing.T) {
	a := ConfigEnvelope{NetworkID: "01AB", MembershipID: "m-1", ConfigEpoch: 47}
	b := ConfigEnvelope{NetworkID: "01AB", MembershipID: "m-1:47", ConfigEpoch: 0}
	if string(a.Bytes()) == string(b.Bytes()) {
		t.Fatalf("two different envelopes encode identically:\n%s", a.Bytes())
	}

	// And the empty-vs-absent case, which a delimiter encoding also collapses.
	c := ConfigEnvelope{NetworkID: "01AB", MembershipID: ""}
	d := ConfigEnvelope{NetworkID: "01AB:", MembershipID: ""}
	if string(c.Bytes()) == string(d.Bytes()) {
		t.Fatalf("an embedded delimiter collides with a field boundary:\n%s", c.Bytes())
	}
}

// A signature over a join statement must not verify as a configuration, and the
// reverse. Both are made by the same key, so without a domain separator one
// message type could be presented as the other.
func TestConfigSignatureIsDomainSeparated(t *testing.T) {
	e := ConfigEnvelope{NetworkID: "01AB", MembershipID: "m-1"}
	if !strings.HasPrefix(string(e.Bytes()), "15:"+ConfigStatementV1) {
		t.Fatalf("the domain separator is not the first signed field: %s", e.Bytes())
	}
}
