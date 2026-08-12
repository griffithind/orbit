package agent

import (
	"net/http"
	"testing"
	"time"
)

// TestEscapeHatchOffByDefault is the blast radius: a host with no exit node must use the
// stock transport, so the fallback path behaves exactly as it did before this existed.
func TestEscapeHatchOffByDefault(t *testing.T) {
	c := NewClient("https://cp.example:8443")
	if c.HTTP.Transport != nil {
		t.Fatal("a new client should use the default transport")
	}

	c.SetEscapeHatch("https://cp.example:8443", 0x4242, []string{"198.51.100.7"})
	if c.HTTP.Transport == nil {
		t.Fatal("an exit-node host needs a dialer that bypasses the tunnel")
	}
	if c.escapeHost != "cp.example" {
		t.Errorf("escapeHost = %q, want the enrolled hostname", c.escapeHost)
	}

	// Withdrawal has to put it back. A machine that stops using an exit node and
	// keeps bypassing the tunnel is sending control-plane traffic somewhere the
	// control plane no longer expects it from.
	c.SetEscapeHatch("", 0, nil)
	if c.HTTP.Transport != nil {
		t.Error("withdrawing the exit node should restore the default transport")
	}
}

// TestEscapeHatchIgnoresUnparseableURL: this is a safety net, and one that stops the
// agent from starting is worse than the hazard it guards.
func TestEscapeHatchIgnoresUnparseableURL(t *testing.T) {
	c := &Client{HTTP: &http.Client{Timeout: time.Second}}
	c.SetEscapeHatch("::not a url::", 0x4242, nil)
	if c.HTTP.Transport != nil {
		t.Error("an unusable endpoint should leave the client alone, not half-configured")
	}
}

// TestTheHatchMatchesOnCachedAddressesRatherThanResolving.
//
// The property that makes it work when it matters. Dialer.Control receives an
// address that is ALREADY resolved, and the resolver's own packets carry no
// mark — so on a host whose exit route is the broken thing, a lookup at dial
// time goes into the tunnel and fails, and the old sameHost returned false on
// that error. The hatch was dead in exactly the situation it exists for.
//
// It also means no lookup per dial. The old comparison never matched on its
// first term, so every connection this transport made — including every
// steady-state overlay poll, whose destination is not the escape host at all —
// went through a blocking net.LookupHost inside the connect path.
func TestTheHatchMatchesOnCachedAddressesRatherThanResolving(t *testing.T) {
	c := NewClient("https://cp.example:8443")
	c.SetEscapeHatch("https://cp.example:8443", 0x4242, []string{"198.51.100.7", "203.0.113.9"})

	for _, addr := range []string{"198.51.100.7", "203.0.113.9"} {
		if !c.knownAddr(addr) {
			t.Errorf("%s is a known address of the enrolled endpoint and was not matched", addr)
		}
	}
	// An overlay address is NOT the escape host. Pinning those to a physical
	// interface would send them out somewhere that cannot route them at all.
	if c.knownAddr("10.42.0.9") {
		t.Error("an overlay address matched the escape host")
	}
}

// TestTheHatchWithNoCachedAddressesMatchesNothing. A host that has never
// resolved its endpoint must not start pinning arbitrary connections — an
// empty cache is "I do not know", not "everything".
func TestTheHatchWithNoCachedAddressesMatchesNothing(t *testing.T) {
	c := NewClient("https://cp.example:8443")
	c.SetEscapeHatch("https://cp.example:8443", 0x4242, nil)
	if c.knownAddr("198.51.100.7") {
		t.Error("an empty address cache matched something")
	}
}
