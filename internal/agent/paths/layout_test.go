package paths

import "testing"

func TestValidateNetwork(t *testing.T) {
	for _, ok := range []string{"prod", "a", "staging-2", "0123456789012345678901234567890a"} {
		if err := ValidateNetwork(ok); err != nil {
			t.Errorf("ValidateNetwork(%q) = %v, want nil", ok, err)
		}
	}
	// "." and ".." escape the root, "/" escapes it further, and uppercase or
	// "@" would confuse a systemd instance name.
	for _, bad := range []string{"", ".", "..", "a/b", "Prod", "pro_d", "net@1",
		"01234567890123456789012345678901x"} {
		if err := ValidateNetwork(bad); err == nil {
			t.Errorf("ValidateNetwork(%q) = nil, want an error", bad)
		}
	}
}

// TestLayoutPaths pins the contract the control-plane renderer and the systemd
// units are both written against.
func TestLayoutPaths(t *testing.T) {
	auth := DefaultLayout("/var/lib/orbit/prod")
	if got := auth.ConfigPath(); got != "/var/lib/orbit/prod/nebula.yml" {
		t.Errorf("config = %q", got)
	}
	if auth.Network != "prod" {
		t.Errorf("network = %q, want prod", auth.Network)
	}
	if got := auth.StatePath(); got != "/var/lib/orbit/prod/agent.json" {
		t.Errorf("state path = %q", got)
	}
	if got := auth.PreviousDir(); got != "/var/lib/orbit/prod/.previous" {
		t.Errorf("previous dir = %q", got)
	}
}
