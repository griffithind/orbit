package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The admin CLI is tested by running the real binary against the real server.
//
// Not by calling its functions: what this suite has to hold is the process
// contract — the exit code, what lands on stdout, what lands on stderr — and
// none of that exists below os.Exit. An in-process test of a CLI asserts the
// parts nobody scripts against.

var (
	buildOnce sync.Once
	orbitBin  string
	buildErr  error
)

// orbitBinary builds cmd/orbit once for the whole package.
func orbitBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "orbit-cli")
		if err != nil {
			buildErr = err
			return
		}
		orbitBin = filepath.Join(dir, "orbit")
		cmd := exec.Command("go", "build", "-o", orbitBin, "github.com/griffithind/orbit/cmd/orbit")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = err
			orbitBin = string(out)
		}
	})
	if buildErr != nil {
		t.Fatalf("build cmd/orbit: %v\n%s", buildErr, orbitBin)
	}
	return orbitBin
}

// cliResult is one invocation's process contract.
type cliResult struct {
	stdout string
	stderr string
	code   int
}

// run invokes the CLI with ORBIT_URL, ORBIT_TOKEN, and ORBIT_NETWORK set from
// the harness.
//
// stdin is /dev/null, which is what makes the confirmation path deterministic:
// an irreversible action refuses without -y rather than waiting for an answer
// nobody is there to give.
func (h *harness) cli(t *testing.T, ts *httptest.Server, args ...string) cliResult {
	t.Helper()
	return h.cliAs(t, ts, h.token, args...)
}

func (h *harness) cliAs(t *testing.T, ts *httptest.Server, token string, args ...string) cliResult {
	t.Helper()
	return h.cliEnv(t, []string{
		"ORBIT_URL=" + ts.URL,
		"ORBIT_TOKEN=" + token,
		"ORBIT_NETWORK=" + h.netName,
	}, args...)
}

// cliEnv runs the binary with exactly the environment given, plus the two
// variables a process needs to function at all.
//
// Exactly, and nothing inherited: a developer's own ORBIT_* exports and their
// ~/.config/orbit/config.yaml would otherwise reach into every one of these
// assertions, and the ones about configuration precedence would be measuring the
// machine.
func (h *harness) cliEnv(t *testing.T, env []string, args ...string) cliResult {
	t.Helper()

	home := t.TempDir()
	cmd := exec.Command(orbitBinary(t), args...)
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		// A config path that does not exist, so "no profile" is the default
		// rather than whatever is in $HOME. Overridden when a case supplies its
		// own ORBIT_CONFIG, because the later assignment wins.
		"ORBIT_CONFIG=" + filepath.Join(home, "absent.yaml"),
	}, env...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	cmd.Stdin = devnull

	err = cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errorsAs(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run orbit %v: %v", args, err)
	}
	return cliResult{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

// TestCLIExitCodeByErrorClass is the contract scripts/check-break-glass.sh cares
// about, moved into the CLI.
//
// Each class has a different remedy — a rejected token, a missing scope, an
// absent object, a system that is not in the right state, a control plane that
// does not answer — and a caller that only knows "non-zero" retries the wrong
// one. They are asserted together because their value is that they differ.
func TestCLIExitCodeByErrorClass(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	// A host carrying the default role, so `role rm` has something to conflict
	// with.
	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "exit-codes", OverlayAddr: "10.42.71.1",
		RoleID: h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	// A token that authenticates but cannot block, for the 403.
	var narrow wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "cli-narrow-" + uuid.NewString()[:8], Scopes: []string{"memberships:read", "networks:read"},
	}, &narrow); code != http.StatusCreated {
		t.Fatalf("create narrow token: %d", code)
	}

	cases := []struct {
		name  string
		token string
		args  []string
		want  int
		// contains is asserted against stderr, and names the remedy rather than
		// the diagnosis wherever the CLI knows one.
		contains string
		// absent must not appear anywhere: used for the 404, which must never
		// hint that the object might exist but be invisible.
		absent []string
	}{
		{
			name: "ok", token: h.token,
			args: []string{"whoami"}, want: 0,
		},
		{
			name: "usage: unknown subcommand", token: h.token,
			args: []string{"membership", "nosuchverb"}, want: 2,
		},
		{
			name: "usage: unresolvable host name", token: h.token,
			args: []string{"membership", "show", "no-such-host"}, want: 2,
			contains: `no membership named "no-such-host"`,
		},
		{
			name: "401: token rejected", token: "orbat_notarealtoken",
			args: []string{"whoami"}, want: 3,
			// The remedy is orbitd, on the control plane host — not this CLI,
			// which by definition cannot mint a token without one.
			contains: "orbitd token create",
		},
		{
			name: "403: missing scope", token: narrow.Token,
			args: []string{"membership", "block", "exit-codes"}, want: 4,
			contains: `memberships:block`,
		},
		{
			name: "404: absent host", token: h.token,
			args: []string{"membership", "show", uuid.NewString()}, want: 5,
			// The API conflates absent and forbidden deliberately. The CLI must
			// not un-conflate it, however helpful that would feel.
			absent: []string{"permission", "may not see", "not allowed", "forbidden"},
		},
		{
			name: "409: role still carried", token: h.token,
			args: []string{"role", "rm", "default", "-y"}, want: 6,
			contains: "exit-codes",
		},
		{
			name: "7: nothing answers", token: h.token,
			// Port 1 refuses immediately on every platform this runs on.
			args: []string{"whoami", "-url", "http://127.0.0.1:1"}, want: 7,
			contains: "not an authentication failure",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.cliAs(t, ts, tc.token, tc.args...)
			if got.code != tc.want {
				t.Errorf("orbit %s = exit %d, want %d\nstdout: %s\nstderr: %s",
					strings.Join(tc.args, " "), got.code, tc.want, got.stdout, got.stderr)
			}
			if tc.contains != "" && !strings.Contains(got.stderr, tc.contains) {
				t.Errorf("stderr does not mention %q:\n%s", tc.contains, got.stderr)
			}
			for _, a := range tc.absent {
				if strings.Contains(strings.ToLower(got.stdout+got.stderr), a) {
					t.Errorf("output mentions %q, which un-conflates absent from forbidden:\n%s%s",
						a, got.stdout, got.stderr)
				}
			}
		})
	}
}

// TestCLIJSONIsTheAPIResponseVerbatim is the property that lets the CLI replace
// the curl in the docs without invalidating any of the pipelines around it.
//
// Byte-for-byte, not "equivalent JSON". A re-encode would reorder fields, respell
// numbers, and — the part that actually breaks people — drop every field this
// build of the CLI does not know about, so an operator's jq filter would work
// against curl and silently return null against orbit.
func TestCLIJSONIsTheAPIResponseVerbatim(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "verbatim", OverlayAddr: "10.42.72.1",
		RoleID: h.roleID.String(), Tags: []string{"a", "b"},
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	cases := []struct {
		name string
		args []string
		path string
	}{
		{"membership ls", []string{"membership", "ls", "-json"}, "/v1/memberships?network_id=" + h.netID.String()},
		{"membership show", []string{"membership", "show", "verbatim", "-json"}, "/v1/memberships/" + host.ID},
		{"whoami", []string{"whoami", "-json"}, "/v1/whoami"},
		{"network ls", []string{"network", "ls", "-json"}, "/v1/networks"},
		{"role ls", []string{"role", "ls", "-json"}, "/v1/roles?network_id=" + h.netID.String()},
		{"ca ls", []string{"ca", "ls", "-json"}, "/v1/cas?network_id=" + h.netID.String()},
		{"converge", []string{"converge", "-json"}, "/v1/networks/" + h.netID.String() + "/convergence"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.cli(t, ts, tc.args...)
			if got.code != 0 {
				t.Fatalf("exit %d: %s", got.code, got.stderr)
			}
			want := rawGet(t, h.token, ts.URL+tc.path)
			if got.stdout != want {
				t.Errorf("-json is not the API response verbatim\n cli: %q\ncurl: %q", got.stdout, want)
			}
		})
	}
}

// rawGet is curl: the exact bytes the endpoint produced, with no decode step in
// between to normalise anything.
func rawGet(t *testing.T, token, url string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestCLISecretsGoAloneOnStdout is what makes these commands pipeable into a
// password manager.
//
// The property `orbitd token create` established: the secret and nothing else on
// stdout, every word of prose on stderr. Without it the only way to get a
// credential out is to select it from a scrollback buffer, which is how it ends
// up in a shell history.
func TestCLISecretsGoAloneOnStdout(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "secret-pipe", OverlayAddr: "10.42.73.1",
		RoleID: h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	t.Run("host code", func(t *testing.T) {
		got := h.cli(t, ts, "membership", "code", "secret-pipe")
		if got.code != 0 {
			t.Fatalf("exit %d: %s", got.code, got.stderr)
		}
		code := strings.TrimSuffix(got.stdout, "\n")
		if strings.ContainsAny(code, " \n\t") || code == "" {
			t.Fatalf("stdout is not a bare enrollment code: %q", got.stdout)
		}
		if !strings.HasPrefix(code, "orb_") {
			t.Errorf("stdout %q does not look like an enrollment code", code)
		}
		// The prose has to exist — it is where the expiry and the next command
		// are — it just must not be on stdout.
		if !strings.Contains(got.stderr, "orbit agent enroll") {
			t.Errorf("stderr lost the guidance:\n%s", got.stderr)
		}
		// And the code must not be echoed into the prose, or redirecting stdout
		// would still leave it on the terminal.
		if strings.Contains(got.stderr, code) {
			t.Errorf("the code was repeated on stderr, defeating the split")
		}

		// The strongest form of the assertion: it actually enrolls.
		if !enrollWorks(t, ts, code) {
			t.Errorf("the code on stdout did not enroll")
		}
	})

	t.Run("token create", func(t *testing.T) {
		got := h.cli(t, ts, "token", "create",
			"-name", "cli-pipe-"+uuid.NewString()[:8], "-scopes", "memberships:read")
		if got.code != 0 {
			t.Fatalf("exit %d: %s", got.code, got.stderr)
		}
		tok := strings.TrimSuffix(got.stdout, "\n")
		if strings.ContainsAny(tok, " \n\t") || tok == "" {
			t.Fatalf("stdout is not a bare token: %q", got.stdout)
		}
		if strings.Contains(got.stderr, tok) {
			t.Errorf("the token was repeated on stderr, defeating the split")
		}
		// It has to be the real credential, not a formatted echo of one.
		if code := h.reqAs(t, tok, http.MethodGet,
			ts.URL+"/v1/memberships?network_id="+h.netID.String(), nil, nil); code != http.StatusOK {
			t.Errorf("token from stdout = %d, want 200", code)
		}
	})
}

func enrollWorks(t *testing.T, ts *httptest.Server, code string) bool {
	t.Helper()
	kp, err := agent.GenerateKeypair(cert.Curve_P256)
	if err != nil {
		t.Fatal(err)
	}
	var out wire.EnrollResponse
	body, err := jsonMarshal(wire.EnrollRequest{
		Credential: code, PublicKey: kp.PublicB64, Curve: cert.Curve_P256.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/enroll/v1/enroll", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Logf("enroll: %d %s", resp.StatusCode, raw)
		return false
	}
	return jsonUnmarshal(raw, &out) == nil && out.Certificate != ""
}

// TestCLIDoesNotLinkTheDataPlane guards the reason `orbit` is a separate binary.
//
// orbit RUNS nebula — the agent embeds it — so the data plane is expected here
// and this test is about the two things that must still not cross.
//
// gvisor is the userspace network stack, and only the control plane needs it:
// orbitd joins the overlay without a tun device, a managed host IS the tun
// device. If gvisor appears in orbit, something has wired the agent to the
// userspace path and every host is now carrying a second TCP/IP implementation
// it never uses.
//
// The postgres driver and internal/store are the other side. orbit talks to the
// control plane over HTTP and holds no database credential; a host that links
// the driver is one import away from someone deciding it could just read the
// database directly.
//
// The failure this catches is innocent: a command that wants a constant from
// internal/store, or a helper from internal/mesh, pulling the whole graph in
// behind it.
func TestCLIDoesNotLinkTheDataPlane(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/griffithind/orbit/cmd/orbit").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}

	forbidden := []string{
		"gvisor.dev/gvisor",
		"github.com/jackc/pgx",
		"github.com/griffithind/orbit/internal/store",
		"github.com/griffithind/orbit/internal/mesh",
	}
	for _, line := range strings.Split(string(out), "\n") {
		for _, f := range forbidden {
			if line == f || strings.HasPrefix(line, f+"/") {
				t.Errorf("cmd/orbit links %s, which belongs to the control plane. "+
					"A managed host runs nebula on a real tun device and talks to "+
					"orbitd over HTTP; it needs neither a userspace network stack "+
					"nor a database driver", line)
			}
		}
	}
}

//------------------------------------------------------------------------------
// Browser sessions, from the terminal
//------------------------------------------------------------------------------

// newUISession opens a browser session directly against the store, which is
// what a sign-in on the console does. The CLI has no way to create one — it
// authenticates with a bearer token and opens nothing — and that asymmetry is
// the point of the command: the sessions it lists were made by somebody else,
// somewhere else.
func (h *harness) newUISession(t *testing.T, tokenID uuid.UUID, readOnly bool, agent string) string {
	t.Helper()
	from := netip.MustParseAddr("198.51.100.23")
	var cookie string
	err := h.store.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		cookie, _, err = tx.CreateUISession(ctx, tokenID, readOnly, &from, agent)
		return err
	})
	if err != nil {
		t.Fatalf("CreateUISession: %v", err)
	}
	return cookie
}

// TestCLISessionListAndRevoke is the terminal half of the session controls.
//
// It exists because the operator whose laptop is missing reaches for a shell,
// not for a browser — and because the browser they need to close may be the
// only one they had. A capability that lives solely in the console is one that
// is unavailable in precisely the situation it was built for.
func TestCLISessionListAndRevoke(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "cli-sessions-" + uuid.NewString()[:8], Scopes: []string{"memberships:read"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}
	tokenID := uuid.MustParse(tok.ID)

	h.newUISession(t, tokenID, false, "Mozilla/5.0 (Macintosh) orbit-e2e-laptop")
	h.newUISession(t, tokenID, true, "Mozilla/5.0 (iPhone) orbit-e2e-phone")

	res := h.cli(t, ts, "session", "ls")
	if res.code != 0 {
		t.Fatalf("session ls = %d\n%s", res.code, res.stderr)
	}
	for _, want := range []string{tok.Name, "orbit-e2e-laptop", "orbit-e2e-phone", "read-only", "full"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("session ls does not mention %q:\n%s", want, res.stdout)
		}
	}

	// -json is the API response verbatim, which is what makes the id available
	// to a script without parsing a table.
	res = h.cli(t, ts, "session", "ls", "-json")
	if res.code != 0 {
		t.Fatalf("session ls -json = %d\n%s", res.code, res.stderr)
	}
	var listed []wire.SessionResponse
	if err := json.Unmarshal([]byte(res.stdout), &listed); err != nil {
		t.Fatalf("decode session ls -json: %v\n%s", err, res.stdout)
	}
	var phone string
	for _, sess := range listed {
		if sess.TokenID == tok.ID && sess.ReadOnly {
			phone = sess.ID
			if sess.CreatedIP != "198.51.100.23" {
				t.Errorf("created_ip = %q", sess.CreatedIP)
			}
			if sess.ExpiresAt.IsZero() || sess.LastSeenAt.IsZero() {
				t.Error("a listed session carries a zero timestamp")
			}
		}
	}
	if phone == "" {
		t.Fatalf("the read-only session is not in the listing:\n%s", res.stdout)
	}

	res = h.cli(t, ts, "session", "revoke", phone)
	if res.code != 0 {
		t.Fatalf("session revoke = %d\n%s", res.code, res.stderr)
	}
	// The id on stdout, every word of prose on stderr — the split the whole CLI
	// keeps, so `orbit session revoke $id > /dev/null` stays quiet and a script
	// reading stdout gets a value and not a paragraph.
	if !strings.Contains(res.stdout, phone) {
		t.Errorf("stdout does not name the session that was ended:\n%s", res.stdout)
	}
	if strings.Contains(res.stdout, "token revoke") {
		t.Error("advice landed on stdout, where a script reads values")
	}
	// The advice matters more than it looks: closing a browser is the SMALLER
	// act, and an operator who came here because a credential leaked has not
	// finished.
	if !strings.Contains(res.stderr, "orbit token revoke") {
		t.Errorf("nothing said that the token is still live:\n%s", res.stderr)
	}

	// Gone, and gone in a way the next command can see.
	res = h.cli(t, ts, "session", "ls")
	if strings.Contains(res.stdout, "orbit-e2e-phone") {
		t.Errorf("the revoked session is still listed:\n%s", res.stdout)
	}
	if !strings.Contains(res.stdout, "orbit-e2e-laptop") {
		t.Errorf("revoking one session removed another:\n%s", res.stdout)
	}

	// Twice is a 404, not a silent success. An operator working an incident is
	// entitled to know whether they were the one who ended it.
	if res := h.cli(t, ts, "session", "revoke", phone); res.code != 5 {
		t.Errorf("second revoke = %d, want 5 (not found)\n%s", res.code, res.stderr)
	}
	if res := h.cli(t, ts, "session", "revoke", "not-a-uuid"); res.code != 2 {
		t.Errorf("revoke of a non-uuid = %d, want 2 (usage)\n%s", res.code, res.stderr)
	}
}

// TestCLISessionRevokeNeedsTokensWrite. Listing is tokens:read and ending one is
// tokens:write, the same pair that guards the token itself — because revoking
// the token already ends every session it opened, so a caller who can do that
// can do this, and one who cannot must not be able to reach it the short way.
func TestCLISessionRevokeNeedsTokensWrite(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var owner wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "cli-session-owner-" + uuid.NewString()[:8], Scopes: []string{"memberships:read"},
	}, &owner); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}
	h.newUISession(t, uuid.MustParse(owner.ID), false, "orbit-e2e-scope-check")

	var reader wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "cli-session-reader-" + uuid.NewString()[:8], Scopes: []string{"tokens:read"},
	}, &reader); code != http.StatusCreated {
		t.Fatalf("create reader token: %d", code)
	}

	res := h.cliAs(t, ts, reader.Token, "session", "ls", "-json")
	if res.code != 0 {
		t.Fatalf("tokens:read cannot list sessions: %d\n%s", res.code, res.stderr)
	}
	var listed []wire.SessionResponse
	if err := json.Unmarshal([]byte(res.stdout), &listed); err != nil {
		t.Fatalf("decode: %v\n%s", err, res.stdout)
	}
	var target string
	for _, sess := range listed {
		if sess.TokenID == owner.ID {
			target = sess.ID
		}
	}
	if target == "" {
		t.Fatal("the session under test is not listed")
	}

	if res := h.cliAs(t, ts, reader.Token, "session", "revoke", target); res.code != 4 {
		t.Fatalf("tokens:read ended a session: exit %d\n%s", res.code, res.stderr)
	}

	// And it really is still live, not merely reported as refused.
	res = h.cli(t, ts, "session", "ls")
	if !strings.Contains(res.stdout, "orbit-e2e-scope-check") {
		t.Errorf("the session was ended by a caller holding only tokens:read:\n%s", res.stdout)
	}
}
