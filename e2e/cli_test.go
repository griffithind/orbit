package e2e

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
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
	var host wire.HostResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts", wire.CreateHostRequest{
		NetworkID: h.netID.String(), Name: "exit-codes", OverlayAddr: "10.42.71.1",
		RoleID: h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	// A token that authenticates but cannot block, for the 403.
	var narrow wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "cli-narrow-" + uuid.NewString()[:8], Scopes: []string{"hosts:read", "networks:read"},
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
			args: []string{"host", "nosuchverb"}, want: 2,
		},
		{
			name: "usage: unresolvable host name", token: h.token,
			args: []string{"host", "show", "no-such-host"}, want: 2,
			contains: `no host named "no-such-host"`,
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
			args: []string{"host", "block", "exit-codes"}, want: 4,
			contains: `hosts:block`,
		},
		{
			name: "404: absent host", token: h.token,
			args: []string{"host", "show", uuid.NewString()}, want: 5,
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

	var host wire.HostResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts", wire.CreateHostRequest{
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
		{"host ls", []string{"host", "ls", "-json"}, "/v1/hosts?network_id=" + h.netID.String()},
		{"host show", []string{"host", "show", "verbatim", "-json"}, "/v1/hosts/" + host.ID},
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

	var host wire.HostResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts", wire.CreateHostRequest{
		NetworkID: h.netID.String(), Name: "secret-pipe", OverlayAddr: "10.42.73.1",
		RoleID: h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	t.Run("host code", func(t *testing.T) {
		got := h.cli(t, ts, "host", "code", "secret-pipe")
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
		if !strings.Contains(got.stderr, "orbit-agent enroll") {
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
			"-name", "cli-pipe-"+uuid.NewString()[:8], "-scopes", "hosts:read")
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
			ts.URL+"/v1/hosts?network_id="+h.netID.String(), nil, nil); code != http.StatusOK {
			t.Errorf("token from stdout = %d, want 200", code)
		}
	})
}

func enrollWorks(t *testing.T, ts *httptest.Server, code string) bool {
	t.Helper()
	kp, err := agent.GenerateKeypair(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	var out wire.EnrollResponse
	body, err := jsonMarshal(wire.EnrollRequest{
		Credential: code, PublicKey: kp.PublicB64, Curve: "CURVE25519",
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
// orbitd links internal/mesh, and through it nebula and gvisor — a userspace
// TCP/IP stack — and it links the postgres driver. The admin CLI installs on a
// laptop and a CI runner, where none of that belongs, and the separation is only
// real for as long as nothing imports its way back across.
//
// The failure this catches is an innocent one: a command that wants a constant
// from internal/store, or a helper from internal/agent, and pulls the whole
// dependency graph in behind it.
func TestCLIDoesNotLinkTheDataPlane(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/griffithind/orbit/cmd/orbit").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}

	forbidden := []string{
		"github.com/slackhq/nebula",
		"gvisor.dev/gvisor",
		"github.com/jackc/pgx",
		"golang.zx2c4.com/wireguard",
		"github.com/griffithind/orbit/internal/store",
		"github.com/griffithind/orbit/internal/mesh",
	}
	for _, line := range strings.Split(string(out), "\n") {
		for _, f := range forbidden {
			if line == f || strings.HasPrefix(line, f+"/") {
				t.Errorf("cmd/orbit links %s; the admin CLI must not carry the data plane "+
					"or the database driver onto an operator's laptop", line)
			}
		}
	}
}
