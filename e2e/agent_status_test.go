package e2e

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/agent"
)

// `orbit status`, through the real binaries.
//
// The command exists to answer "why is nothing working" on a host that cannot
// reach whatever would tell it. So these run a real agent, over a real socket,
// and assert on what an operator would see — including on a host where nebula
// is NOT running, which under test is every host, because a tun device needs
// root. That is not a limitation being worked around: a data plane that is down
// while the control path keeps working is exactly the state the command has to
// render clearly.

// shortTempDir is a temporary directory short enough to hold a unix socket.
//
// t.TempDir() on macOS sits under /var/folders/<...>/T/<TestName>/001, which
// with a socket name appended runs past the ~104-byte sun_path limit — and the
// failure arrives as "invalid argument" from bind, which names nothing.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "orbit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// lockedBuffer collects a child's output while the test reads it.
//
// The agent writes from its own goroutines for as long as it runs, so an
// unguarded bytes.Buffer here is a data race that -race turns into a failure in
// whichever test happens to read first.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startAgent runs `orbit agent run` until the test ends.
//
// Not -once: that mode performs a single pass and deliberately does not bind
// the socket, so it cannot exercise any of this.
func (h *harness) startAgent(t *testing.T, root string) *lockedBuffer {
	t.Helper()

	cmd := exec.Command(orbitBinary(t), "agent", "run", "-root", root, "-interval", "1s")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}

	var stderr lockedBuffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Wait for the socket rather than sleeping: the agent binds it after it has
	// discovered the networks, so its appearance is the readiness signal.
	sock := agent.SocketPath(root)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if c, err := net.Dial("unix", sock); err == nil {
			_ = c.Close()
			return &stderr
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent never bound %s\n%s", sock, stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestStatusReportsAJoinedNetwork is the ordinary case.
func TestStatusReportsAJoinedNetwork(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	root := shortTempDir(t)
	h.enrollIntoDir(t, ts, "reported", "10.42.91.7", filepath.Join(root, "prod"))
	h.startAgent(t, root)

	// No ORBIT_URL and no ORBIT_TOKEN. Status is node-local: it asks the agent
	// on this machine, not the control plane, and requiring an admin credential
	// to ask a host what it is doing would make it useless in the outage it
	// exists for.
	res := h.cliEnv(t, nil, "status", "-root", root, "-json")
	if res.code != 0 {
		t.Fatalf("status exited %d\n%s", res.code, res.stderr)
	}

	var rep agent.Report
	if err := json.Unmarshal([]byte(res.stdout), &rep); err != nil {
		t.Fatalf("parse status: %v\n%s", err, res.stdout)
	}
	if len(rep.Networks) != 1 {
		t.Fatalf("got %d networks, want 1: %s", len(rep.Networks), res.stdout)
	}

	n := rep.Networks[0]
	if n.Network != "prod" {
		t.Errorf("network = %q, want prod", n.Network)
	}
	if !n.Ready {
		t.Errorf("an enrolled network reported as not ready: %s", n.Error)
	}
	if n.HostID == "" {
		t.Error("no host id; the report cannot be tied to a host in the console")
	}
	if n.ControlURL == "" {
		t.Error("no control plane URL; an operator cannot tell which one this host talks to")
	}
	if n.Certificate == nil {
		t.Fatal("no certificate in the report — the first thing to check on a broken host")
	}
	if n.Certificate.Name != "reported" {
		t.Errorf("certificate name = %q, want reported", n.Certificate.Name)
	}
	if len(n.Certificate.Networks) == 0 || !strings.HasPrefix(n.Certificate.Networks[0], "10.42.91.7") {
		t.Errorf("certificate networks = %v, want the address it enrolled with", n.Certificate.Networks)
	}
}

// TestStatusSeparatesADeadDataPlaneFromABrokenAgent.
//
// nebula does not start here — a tun device needs root — and the agent is
// designed to keep polling anyway. The report has to say both things at once,
// because "the agent is fine and the tunnel is not" and "the agent is broken"
// have completely different remedies and look identical from `ping`.
func TestStatusSeparatesADeadDataPlaneFromABrokenAgent(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	root := shortTempDir(t)
	h.enrollIntoDir(t, ts, "no-tun", "10.42.91.8", filepath.Join(root, "prod"))
	h.startAgent(t, root)

	res := h.cliEnv(t, nil, "status", "-root", root, "-json")
	if res.code != 0 {
		t.Fatalf("status exited %d\n%s", res.code, res.stderr)
	}
	var rep agent.Report
	if err := json.Unmarshal([]byte(res.stdout), &rep); err != nil {
		t.Fatal(err)
	}
	n := rep.Networks[0]

	if !n.Ready {
		t.Fatalf("the network reported as not ready: %s", n.Error)
	}
	if !n.Nebula.Known {
		t.Error("nebula's state reported as unknown; the embedded engine always knows")
	}
	if n.Nebula.Running {
		t.Error("nebula reported as running, but it cannot start without a tun device.\n" +
			"A status that reports a data plane that is not there is worse than none.")
	}
}

// TestStatusShowsANetworkThatNeverCameUp is the case the command exists for.
//
// A directory whose state file cannot be read is retried forever in the
// background. Reporting only the networks that started would omit the single
// most useful fact on the screen — and it is the shape a registry populated on
// success alone would have.
func TestStatusShowsANetworkThatNeverCameUp(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	root := shortTempDir(t)
	h.enrollIntoDir(t, ts, "healthy", "10.42.91.9", filepath.Join(root, "prod"))

	// A second network that cannot be set up: enrolled, then its state file
	// corrupted, which is what a truncated write or a half-finished install
	// leaves behind.
	broken := filepath.Join(root, "staging")
	h.enrollIntoDir(t, ts, "broken", "10.42.91.10", broken)
	if err := os.WriteFile(agent.StatePath(broken), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	h.startAgent(t, root)

	res := h.cliEnv(t, nil, "status", "-root", root, "-json")
	if res.code != 0 {
		t.Fatalf("status exited %d\n%s", res.code, res.stderr)
	}
	var rep agent.Report
	if err := json.Unmarshal([]byte(res.stdout), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Networks) != 2 {
		t.Fatalf("got %d networks, want both the healthy one and the broken one: %s",
			len(rep.Networks), res.stdout)
	}

	var ready, notReady int
	for _, n := range rep.Networks {
		if n.Ready {
			ready++
			continue
		}
		notReady++
		if n.Error == "" {
			t.Errorf("network %q is not ready and the report says nothing about why", n.Network)
		}
	}
	if ready != 1 || notReady != 1 {
		t.Errorf("got %d ready and %d not ready, want one of each", ready, notReady)
	}
}

// TestStatusWithoutAnAgentSaysSo. The command's own failure has to be legible:
// it is asked precisely when things are broken, and a dial error naming a
// socket path is not an answer to "is the agent running".
func TestStatusWithoutAnAgentSaysSo(t *testing.T) {
	h := setup(t)
	root := shortTempDir(t)

	res := h.cliEnv(t, nil, "status", "-root", root)
	if res.code == 0 {
		t.Fatal("status succeeded with no agent running")
	}
	if !strings.Contains(res.stderr, "not running") {
		t.Errorf("the message does not say the agent is not running:\n%s", res.stderr)
	}
	// Exit 7 is "nothing answered", the same class the admin CLI uses for an
	// unreachable control plane, so a script can tell it from a real failure.
	if res.code != 7 {
		t.Errorf("exit %d, want 7 (unreachable)", res.code)
	}
}
