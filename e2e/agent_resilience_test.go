// Agent resilience: what happens when the control plane, one network, or the
// data plane goes away.
//
// Formerly agent_recovery_test.go, which was a misnomer even then — none of
// these tests exercised `orbit agent recover`. That command is gone (a device
// identity never expires, so there is nothing to recover from; see
// TestExpiredCertificateRecoversByRejoining), and these three are about
// something else entirely: an agent that must not die, discard state, or go
// quiet when part of the world stops answering.

package e2e

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/wire"
)

// Recovery, through the real binary.
//
// A host that cannot heal itself is a host somebody has to visit, and every
// interesting failure here is one the agent must survive without help: the
// control plane going away, a directory that is not ready, a sibling network
// that is broken.
//
// These run `orbit agent run -once`, which performs exactly one pass and exits,
// so an assertion is about what one pass does rather than about timing.
//
// Nebula itself does not start under test — a tun device needs root and a
// device node — and that is deliberately not skipped over. It is the same path
// a host with a bad configuration takes, and the agent is supposed to keep
// polling anyway, so these also assert that the data plane failing does not
// stop the control path.

// enrollIntoDir enrolls a host into a directory the CLI owns, using the CLI.
func (h *harness) enrollIntoDir(t *testing.T, ts *httptest.Server, name, addr, dir string) {
	t.Helper()

	var membership wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: name, OverlayAddr: addr, RoleID: h.roleID.String(),
	}, &membership); code != http.StatusCreated {
		t.Fatalf("create membership %s: %d", name, code)
	}

	var code wire.EnrollmentCodeResponse
	if c := h.adminPost(t, ts.URL+"/v1/memberships/"+membership.ID+"/enrollment-code", nil, &code); c != http.StatusCreated {
		t.Fatalf("mint code for %s: %d", name, c)
	}

	res := h.cli(t, ts, "agent", "enroll", "-url", ts.URL, "-code", code.Code, "-dir", dir)
	if res.code != 0 {
		t.Fatalf("enroll %s: exit %d\n%s", name, res.code, res.stderr)
	}
}

// TestAgentSurvivesTheControlPlaneGoingAway is the outage an operator actually
// has: the control plane stops answering, and must not leave hosts in a state
// they cannot get out of when it returns.
func TestAgentSurvivesTheControlPlaneGoingAway(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	root := t.TempDir()
	dir := filepath.Join(root, "prod")
	h.enrollIntoDir(t, ts, "recovers", "10.42.90.7", dir)

	// Healthy.
	if res := h.cli(t, ts, "agent", "run", "-root", root, "-once"); res.code != 0 {
		t.Fatalf("first pass: exit %d\n%s", res.code, res.stderr)
	}

	// The control plane goes away mid-life. The agent must not exit, must not
	// discard what it has, and must say what happened.
	ts.Close()

	res := h.cli(t, ts, "agent", "run", "-root", root, "-once")
	if res.code != 0 {
		t.Errorf("the agent exited %d because the control plane was unreachable.\n"+
			"A host whose agent dies on an outage stops renewing, and stops being "+
			"told about revocations, for as long as nobody notices.\n%s",
			res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "tick failed") {
		t.Errorf("nothing said the poll failed:\n%s", res.stderr)
	}
	// Whatever it had must still be there. An agent that cannot reach the
	// control plane and responds by discarding its configuration would take the
	// host off the mesh for the length of the outage.
	if _, err := os.Stat(paths.DefaultLayout(dir).ConfigPath()); err != nil {
		t.Errorf("the configuration was lost during the outage: %v", err)
	}
	if _, err := agent.ReadState(dir); err != nil {
		t.Errorf("the agent state was lost during the outage: %v", err)
	}
}

// TestOneBrokenNetworkDoesNotStopTheOthers. A host on several networks must not
// lose all of them because one directory is unreadable — the whole reason each
// network owns a directory rather than sharing one.
func TestOneBrokenNetworkDoesNotStopTheOthers(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	root := t.TempDir()
	good := filepath.Join(root, "good")
	h.enrollIntoDir(t, ts, "good-net", "10.42.91.7", good)

	// A directory that looks joined and is not: agent state present, and
	// unparseable. This is what a half-finished install or a truncated write
	// leaves behind.
	broken := filepath.Join(root, "broken")
	if err := os.MkdirAll(broken, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "agent.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := h.cli(t, ts, "agent", "run", "-root", root, "-once")
	if res.code != 0 {
		t.Fatalf("one broken network took the whole agent down: exit %d\n%s", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "network not ready") {
		t.Errorf("the broken network was not reported:\n%s", res.stderr)
	}
	if !strings.Contains(res.stderr, "good") {
		t.Errorf("the healthy network does not appear to have been served:\n%s", res.stderr)
	}
}

// TestAgentKeepsPollingWithoutADataPlane. Nebula not starting is not a reason
// to stop talking to the control plane — it is the reason TO talk to it, since
// the fix is a new generation and reaching it is what the loop does.
func TestAgentKeepsPollingWithoutADataPlane(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	root := t.TempDir()
	dir := filepath.Join(root, "prod")
	h.enrollIntoDir(t, ts, "no-dataplane", "10.42.92.7", dir)

	res := h.cli(t, ts, "agent", "run", "-root", root, "-once")
	if res.code != 0 {
		t.Fatalf("the agent gave up because nebula could not start: exit %d\n%s", res.code, res.stderr)
	}
	// It must SAY so. A host silently without a data plane is the failure that
	// takes longest to notice.
	if !strings.Contains(res.stderr, "nebula") {
		t.Errorf("nothing mentioned nebula's state:\n%s", res.stderr)
	}
}
