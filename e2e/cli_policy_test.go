package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// `orbit policy`, run as the real binary against the real server.
//
// The same reasoning as cli_test.go: what has to hold here is the PROCESS
// contract — the exit code, what lands on stdout, what lands on stderr — and none
// of that exists below os.Exit. For this command the exit code carries more than
// usual, because `orbit policy check` is meant to be a CI gate on a policy file
// in review, and a gate that exits 0 on a bad document is worse than no gate.

// policyFile writes a document to a temp file and returns the path.
func policyFile(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCLIPolicyCheckExitCodes is the CI contract.
//
// A valid document exits 0, an invalid one exits 2, and the message names the
// fault rather than saying "invalid". Exit 2 specifically — the usage class —
// because the problem is the argument this invocation was given, and it is the
// same code the server's 400 maps to, so a script cannot tell a local refusal
// from a remote one and does not have to.
func TestCLIPolicyCheckExitCodes(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	good := h.cli(t, ts, "policy", "check", policyFile(t, policyDocV1))
	if good.code != 0 {
		t.Fatalf("check of a valid document exited %d\nstdout: %s\nstderr: %s",
			good.code, good.stdout, good.stderr)
	}
	if !strings.Contains(good.stdout, "valid") {
		t.Errorf("check of a valid document said nothing about it: %s", good.stdout)
	}

	for _, tc := range []struct {
		name string
		doc  string
		want string
	}{
		{"unknown field", `{"version":1,"allows":[]}`, "allows"},
		{"unknown proto", `{"version":1,"allow":[{"src":["*"],"dst":["*"],"proto":"sctp","ports":["1"]}]}`, "sctp"},
		{"bare selector", `{"version":1,"allow":[{"src":["web"],"dst":["*"],"proto":"tcp","ports":["1"]}]}`, "web"},
		{"not json", `{`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := h.cli(t, ts, "policy", "check", policyFile(t, tc.doc))
			if res.code != 2 {
				t.Errorf("check of an invalid document exited %d, want 2\nstdout: %s\nstderr: %s",
					res.code, res.stdout, res.stderr)
			}
			// Nothing on stdout. A CI job that pipes stdout into a report must not
			// receive a partial success for a document that was refused.
			if strings.TrimSpace(res.stdout) != "" {
				t.Errorf("a refused document wrote to stdout: %q", res.stdout)
			}
			if tc.want != "" && !strings.Contains(res.stderr, tc.want) {
				t.Errorf("the refusal does not name %q: %s", tc.want, res.stderr)
			}
		})
	}
}

// TestCLIPolicyApplyRefusesBeforeSending.
//
// The distinction that matters: "your document is wrong" and "your document is
// wrong and is now the firewall for four hundred hosts". A lint failure must stop
// the request, not be discovered by it.
func TestCLIPolicyApplyRefusesBeforeSending(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	before := h.networkEpochs(t, ts.URL).ConfigEpoch

	bad := h.cli(t, ts, "policy", "apply",
		policyFile(t, `{"version":1,"allow":[{"src":["*"],"dst":["*"],"proto":"icmp","ports":["22"]}]}`))
	if bad.code != 2 {
		t.Fatalf("apply of an invalid document exited %d, want 2\nstderr: %s", bad.code, bad.stderr)
	}
	if !strings.Contains(bad.stderr, "icmp") {
		t.Errorf("the refusal does not name the fault: %s", bad.stderr)
	}

	// Nothing reached the server: no document, and no epoch movement.
	if code, _ := h.adminRaw(t, http.MethodGet, h.policyURL(ts.URL), nil); code != http.StatusNotFound {
		t.Errorf("a document refused by the CLI was stored anyway: GET returned %d", code)
	}
	if after := h.networkEpochs(t, ts.URL).ConfigEpoch; after != before {
		t.Errorf("config epoch %d -> %d for a document that was never applied", before, after)
	}
}

// TestCLIPolicyApplyAndShow walks the operator path: apply a document, read it
// back, re-apply it unchanged.
func TestCLIPolicyApplyAndShow(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	applied := h.cli(t, ts, "policy", "apply", policyFile(t, policyDocV1))
	if applied.code != 0 {
		t.Fatalf("apply exited %d\nstdout: %s\nstderr: %s", applied.code, applied.stdout, applied.stderr)
	}
	if !strings.Contains(applied.stdout, "version 1") {
		t.Errorf("apply does not report the version it wrote: %s", applied.stdout)
	}
	// The network is still in role mode, so the document is stored and enforcing
	// nothing. An operator who reads "applied" and walks away has drawn the wrong
	// conclusion, so this has to be unmissable — and on stderr, so it never
	// contaminates -json.
	if !strings.Contains(applied.stderr, "NOT IN FORCE") {
		t.Errorf("apply to a network in role mode did not say the document is not enforced:\n%s",
			applied.stderr)
	}

	shown := h.cli(t, ts, "policy", "show")
	if shown.code != 0 {
		t.Fatalf("show exited %d\nstderr: %s", shown.code, shown.stderr)
	}
	for _, want := range []string{"version", "in force", "document"} {
		if !strings.Contains(shown.stdout, want) {
			t.Errorf("show omits %q:\n%s", want, shown.stdout)
		}
	}
	if !strings.Contains(shown.stdout, "tag:db") {
		t.Errorf("show does not print the document itself:\n%s", shown.stdout)
	}

	// -json emits the API response verbatim, which is the property that keeps
	// `orbit … -json | jq` and `curl … | jq` interchangeable.
	asJSON := h.cli(t, ts, "policy", "show", "-json")
	if asJSON.code != 0 {
		t.Fatalf("show -json exited %d\nstderr: %s", asJSON.code, asJSON.stderr)
	}
	var decoded wire.PolicyResponse
	if err := json.Unmarshal([]byte(asJSON.stdout), &decoded); err != nil {
		t.Fatalf("show -json did not emit a decodable response: %v\n%s", err, asJSON.stdout)
	}
	if decoded.Version != 1 {
		t.Errorf("show -json reports version %d", decoded.Version)
	}

	// Re-applying the same document is a no-op, and the CLI says so rather than
	// reporting a success that implies a change. This is the case a reconcile
	// loop hits every run.
	before := h.networkEpochs(t, ts.URL).ConfigEpoch
	again := h.cli(t, ts, "policy", "apply", policyFile(t, policyDocV1Reordered))
	if again.code != 0 {
		t.Fatalf("re-apply exited %d\nstderr: %s", again.code, again.stderr)
	}
	if !strings.Contains(again.stdout, "unchanged") {
		t.Errorf("re-applying an identical document did not report it as unchanged: %s", again.stdout)
	}
	if after := h.networkEpochs(t, ts.URL).ConfigEpoch; after != before {
		t.Errorf("config epoch %d -> %d on a no-op apply", before, after)
	}
}

// TestCLIPolicyApplyFromStdin. A policy document lives in git and arrives through
// a pipe as often as through a path, so `-` has to work — and it is the form a CI
// job uses when the document is generated rather than committed.
func TestCLIPolicyApplyFromStdin(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	res := h.cliStdin(t, ts, policyDocV1, "policy", "apply", "-")
	if res.code != 0 {
		t.Fatalf("apply from stdin exited %d\nstdout: %s\nstderr: %s",
			res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "version 1") {
		t.Errorf("apply from stdin did not report the version: %s", res.stdout)
	}

	var read wire.PolicyResponse
	if code := h.adminReq(t, http.MethodGet, h.policyURL(ts.URL), nil, &read); code != http.StatusOK {
		t.Fatalf("GET policy after a stdin apply: %d", code)
	}
	if read.Version != 1 {
		t.Errorf("stored version is %d after a stdin apply", read.Version)
	}
}

// TestCLIPolicyCheckForAHost is the question an operator actually has, at the
// terminal: "will web-01 still reach the database".
func TestCLIPolicyCheckForAHost(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	h.createTaggedHost(t, ts.URL, "cli-web", "10.42.95.1", []string{"web"})
	h.createTaggedHost(t, ts.URL, "cli-db", "10.42.95.2", []string{"db"})

	res := h.cli(t, ts, "policy", "check", policyFile(t, policyDocV1), "-membership", "cli-web")
	if res.code != 0 {
		t.Fatalf("check -membership exited %d\nstdout: %s\nstderr: %s", res.code, res.stdout, res.stderr)
	}
	// The compiled rules, naming the peer's ADDRESS. That the rule is an address
	// and not a group is the whole reason this feature exists: it is what makes
	// the edit config-only.
	if !strings.Contains(res.stdout, "10.42.95.2/32") {
		t.Errorf("the compiled output does not name the db host's address:\n%s", res.stdout)
	}
	if !strings.Contains(res.stdout, "5432") {
		t.Errorf("the compiled output does not show the 5432 rule:\n%s", res.stdout)
	}
	// And the selector inputs, which are the half that explains a rule that did
	// not appear.
	if !strings.Contains(res.stdout, "tags") || !strings.Contains(res.stdout, "web") {
		t.Errorf("the compiled output does not report the tags the selectors matched on:\n%s",
			res.stdout)
	}

	// An unknown host is exit 5, not a compiled empty rule set. A typo'd name that
	// answered "this host gets no rules" reads as a policy problem rather than a
	// typo.
	missing := h.cli(t, ts, "policy", "check", policyFile(t, policyDocV1), "-membership", "cli-nope")
	if missing.code != 5 {
		t.Errorf("check against an unknown host exited %d, want 5 (not found)\nstderr: %s",
			missing.code, missing.stderr)
	}
}

// TestCLIPolicyUseIsConfirmed covers the fleet-wide switch: refused without
// consent, and consent cannot come from a pipeline that never asked for it.
func TestCLIPolicyUseIsConfirmed(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	if code, _ := h.putPolicy(t, ts.URL, policyDocV1); code != http.StatusOK {
		t.Fatalf("PUT policy: %d", code)
	}

	// stdin is /dev/null in this harness, so there is nobody to ask. The action
	// is REFUSED rather than performed: proceeding silently would mean any
	// pipeline that invoked this replaced the firewall on a whole network with no
	// confirmation anywhere in it.
	refused := h.cli(t, ts, "policy", "use", "policy")
	if refused.code != 2 {
		t.Fatalf("unconfirmed switch exited %d, want 2\nstdout: %s\nstderr: %s",
			refused.code, refused.stdout, refused.stderr)
	}
	var net wire.NetworkResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/networks/"+h.netID.String(), nil, &net); code != http.StatusOK {
		t.Fatalf("get network: %d", code)
	}
	if net.FirewallSource != store.FirewallSourceRole {
		t.Fatalf("an unconfirmed switch went through anyway: firewall_source is %q",
			net.FirewallSource)
	}

	// With -y it proceeds.
	ok := h.cli(t, ts, "policy", "use", "policy", "-y")
	if ok.code != 0 {
		t.Fatalf("confirmed switch exited %d\nstdout: %s\nstderr: %s",
			ok.code, ok.stdout, ok.stderr)
	}
	if !strings.Contains(ok.stdout, "policy") {
		t.Errorf("the switch does not report the source it moved to: %s", ok.stdout)
	}
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/networks/"+h.netID.String(), nil, &net); code != http.StatusOK {
		t.Fatalf("get network: %d", code)
	}
	if net.FirewallSource != store.FirewallSourcePolicy {
		t.Fatalf("after a confirmed switch firewall_source is %q", net.FirewallSource)
	}

	// Now `policy show` reports it as in force, which is the field an operator
	// checks before believing their change landed.
	shown := h.cli(t, ts, "policy", "show")
	if shown.code != 0 {
		t.Fatalf("show exited %d", shown.code)
	}
	if !strings.Contains(shown.stdout, "in force       yes") {
		t.Errorf("show does not report the document as in force:\n%s", shown.stdout)
	}
	if strings.Contains(shown.stderr, "NOT in force") {
		t.Errorf("show still warns the document is not enforced:\n%s", shown.stderr)
	}

	// Re-running it is a no-op that says so and exits 0, so a reconcile script
	// does not have to check the state first.
	repeat := h.cli(t, ts, "policy", "use", "policy", "-y")
	if repeat.code != 0 {
		t.Errorf("re-running the same switch exited %d\nstderr: %s", repeat.code, repeat.stderr)
	}
	if !strings.Contains(repeat.stdout, "already") {
		t.Errorf("a repeated switch did not report it as already set: %s", repeat.stdout)
	}
}

// TestCLIPolicyShowWithoutADocument. The state of every network that has not
// opted in, so its message must not read as a broken deployment.
func TestCLIPolicyShowWithoutADocument(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	res := h.cli(t, ts, "policy", "show")
	if res.code != 5 {
		t.Errorf("show on a network with no document exited %d, want 5 (not found)\nstderr: %s",
			res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "no policy document") {
		t.Errorf("the message does not say the network simply has no document: %s", res.stderr)
	}
}

// cliStdin runs the CLI with a document on stdin, for the `-` operand.
//
// A separate helper rather than a parameter on cliEnv, because cliEnv attaches
// /dev/null deliberately: that is what makes the confirmation path deterministic
// everywhere else, and a shared stdin parameter would make it easy to lose.
//
// The environment is exact and nothing is inherited, for the reason cliEnv gives:
// a developer's own ORBIT_* exports would otherwise reach into these assertions.
func (h *harness) cliStdin(t *testing.T, ts *httptest.Server, stdin string, args ...string) cliResult {
	t.Helper()

	home := t.TempDir()
	cmd := exec.Command(orbitBinary(t), args...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"ORBIT_CONFIG=" + filepath.Join(home, "absent.yaml"),
		"ORBIT_URL=" + ts.URL,
		"ORBIT_TOKEN=" + h.token,
		"ORBIT_NETWORK=" + h.netName,
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = strings.NewReader(stdin)

	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errorsAs(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run orbit %v: %v", args, err)
	}
	return cliResult{stdout: stdout.String(), stderr: stderr.String(), code: code}
}
