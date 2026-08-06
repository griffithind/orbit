package agent

import (
	"os/exec"
	"testing"
)

// TestNoFrontendNeedsNothing: on a host where neither firewalld nor ufw owns the verdict,
// the kernel's FORWARD policy decides and Orbit's own table is sufficient. This must not
// error, because that is the common container and minimal-distro case and an error here
// would stop a gateway that is working.
func TestNoFrontendNeedsNothing(t *testing.T) {
	if firewalldRunning() || ufwActive() {
		t.Skip("a firewall frontend is running on this host")
	}
	if err := ensureForwardAllowed(HostState{Forward: true, TunDev: "orbit0"}); err != nil {
		t.Errorf("a host with no firewall frontend should need nothing: %v", err)
	}
}

// TestForwardNeedsATunDevice: every mechanism here names an interface, so a missing one
// is a bug in the caller rather than something to paper over — silently doing nothing
// would leave a gateway dropping traffic with no error anywhere.
func TestForwardNeedsATunDevice(t *testing.T) {
	if err := ensureForwardAllowed(HostState{Forward: true}); err == nil {
		t.Error("an empty tun device should be refused, not ignored")
	}
}

// TestDetectionMatchesTheSystem guards the two probes against the machine they run on.
// Getting these wrong is silent: a false negative on firewalld means Orbit writes its own
// forward chain and firewalld drops the packet anyway.
func TestDetectionMatchesTheSystem(t *testing.T) {
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		if firewalldRunning() {
			t.Error("firewalldRunning is true with no firewall-cmd on PATH")
		}
	}
	if _, err := exec.LookPath("ufw"); err != nil {
		if ufwActive() {
			t.Error("ufwActive is true with no ufw on PATH")
		}
	}
}

// TestRemoveIsSafeWithoutATun: uninstall runs on machines that never forwarded.
func TestRemoveIsSafeWithoutATun(t *testing.T) {
	if err := removeForwardAllowed(""); err != nil {
		t.Errorf("removing forwarding for no interface should be a no-op: %v", err)
	}
}
