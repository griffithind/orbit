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

	c.SetEscapeHatch("https://cp.example:8443", 0x4242)
	if c.HTTP.Transport == nil {
		t.Fatal("an exit-node host needs a dialer that bypasses the tunnel")
	}
	if c.escapeHost != "cp.example" {
		t.Errorf("escapeHost = %q, want the enrolled hostname", c.escapeHost)
	}

	// Withdrawal has to put it back. A machine that stops using an exit node and
	// keeps bypassing the tunnel is sending control-plane traffic somewhere the
	// control plane no longer expects it from.
	c.SetEscapeHatch("", 0)
	if c.HTTP.Transport != nil {
		t.Error("withdrawing the exit node should restore the default transport")
	}
}

// TestEscapeHatchIgnoresUnparseableURL: this is a safety net, and one that stops the
// agent from starting is worse than the hazard it guards.
func TestEscapeHatchIgnoresUnparseableURL(t *testing.T) {
	c := &Client{HTTP: &http.Client{Timeout: time.Second}}
	c.SetEscapeHatch("::not a url::", 0x4242)
	if c.HTTP.Transport != nil {
		t.Error("an unusable endpoint should leave the client alone, not half-configured")
	}
}
