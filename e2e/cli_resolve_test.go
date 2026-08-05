package e2e

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// Name resolution is the whole reason an operator would type this rather than
// curl. It is also where a CLI can quietly do the wrong thing: the API takes
// uuids, names are not uuids, and every mapping between them is a place to guess.

// TestCLIResolvesNamesToIDs covers the mappings that are unique by construction.
//
// Membership and role names carry UNIQUE (network_id, name), so an exact match is the
// only match. Network names are globally unique. What the CLI adds beyond
// convenience is `-role <name>` on the host listing, which the server refuses
// outright — "role_id must be a uuid, not a role name" — because a name there
// would match no host and read as a role nobody carries.
func TestCLIResolvesNamesToIDs(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "resolve-me", OverlayAddr: "10.42.74.1",
		RoleID: h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}
	// A second host on a different role, so filtering by role name has to
	// actually filter rather than merely succeed.
	var other wire.RoleResponse
	if code := h.adminPost(t, ts.URL+"/v1/roles", wire.CreateRoleRequest{
		NetworkID: h.netID.String(), Name: "cli-other", Groups: []string{"default"},
		Firewall: []byte(`{"inbound":[],"outbound":[]}`),
	}, &other); code != http.StatusCreated {
		t.Fatalf("create role: %d", code)
	}
	var offRole wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "other-role", OverlayAddr: "10.42.74.2",
		RoleID: other.ID,
	}, &offRole); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	t.Run("host by name and by uuid agree", func(t *testing.T) {
		byName := h.cli(t, ts, "membership", "show", "resolve-me", "-json")
		byID := h.cli(t, ts, "membership", "show", host.ID, "-json")
		if byName.code != 0 || byID.code != 0 {
			t.Fatalf("exits %d/%d: %s%s", byName.code, byID.code, byName.stderr, byID.stderr)
		}
		if byName.stdout != byID.stdout {
			t.Errorf("name and uuid resolved to different hosts\n%s\n%s", byName.stdout, byID.stdout)
		}
	})

	t.Run("a substring is not a match", func(t *testing.T) {
		// "resolve" is a prefix of a real host, and name_contains will return
		// that host. Accepting it would make `orbit host rm resolve` delete
		// something the operator did not name.
		got := h.cli(t, ts, "membership", "show", "resolve")
		if got.code != 2 {
			t.Errorf("substring resolved: exit %d, want 2\n%s", got.code, got.stderr)
		}
		if !strings.Contains(got.stderr, "resolve-me") {
			t.Errorf("the error does not offer the near miss:\n%s", got.stderr)
		}
	})

	t.Run("role name on the host filter", func(t *testing.T) {
		got := h.cli(t, ts, "membership", "ls", "-role", "cli-other", "-json")
		if got.code != 0 {
			t.Fatalf("exit %d: %s", got.code, got.stderr)
		}
		var page wire.MembershipListResponse
		if err := jsonUnmarshal([]byte(got.stdout), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Memberships) != 1 || page.Memberships[0].Name != "other-role" {
			t.Errorf("-role cli-other returned %v, want just other-role", listedNames(page))
		}
	})

	t.Run("network by name", func(t *testing.T) {
		got := h.cli(t, ts, "membership", "ls", "-network", h.netName, "-json")
		if got.code != 0 {
			t.Fatalf("exit %d: %s", got.code, got.stderr)
		}
		if !strings.Contains(got.stdout, "resolve-me") {
			t.Errorf("network name did not resolve:\n%s", got.stdout)
		}
	})

	t.Run("unknown role name is a usage error, not an empty listing", func(t *testing.T) {
		// The failure being avoided: a name that reaches the server as nothing,
		// returning the whole fleet or none of it, either of which reads as an
		// answer.
		got := h.cli(t, ts, "membership", "ls", "-role", "no-such-role")
		if got.code != 2 {
			t.Errorf("exit %d, want 2\n%s", got.code, got.stderr)
		}
	})
}

// TestCLIDetectsAmbiguousCAName is the resolution case that is not unique by
// construction, and the one that matters most.
//
// orbit.ca carries UNIQUE (network_id, fingerprint) and no constraint on name.
// Two CAs in one network may therefore share a name — which is exactly what a
// rotation produces, since the replacement is usually named after the authority
// it replaces. Resolving a name to "the first one" would activate an arbitrary
// half of a rotation, and the operator would learn which from the fleet.
func TestCLIDetectsAmbiguousCAName(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	second := h.addCA(t, "e2e-ca") // deliberately the same name as the bootstrap CA

	t.Run("the shared name is refused", func(t *testing.T) {
		got := h.cli(t, ts, "ca", "activate", "e2e-ca")
		if got.code != 2 {
			t.Fatalf("ambiguous name = exit %d, want 2\n%s%s", got.code, got.stdout, got.stderr)
		}
		if !strings.Contains(got.stderr, "ambiguous") {
			t.Errorf("the error does not say what went wrong:\n%s", got.stderr)
		}
		// The remedy has to be in the message, and it has to be usable: both
		// fingerprints, printed to be pasted back.
		if !strings.Contains(got.stderr, second.Fingerprint[:16]) {
			t.Errorf("the candidates do not include the new CA's fingerprint:\n%s", got.stderr)
		}
		if !strings.Contains(got.stderr, "fingerprint prefix") {
			t.Errorf("the error does not name the way out:\n%s", got.stderr)
		}
	})

	t.Run("a fingerprint prefix resolves", func(t *testing.T) {
		// Not activated here — the network has an unconverged host, so activation
		// is refused with a 409, which is itself the proof that resolution got
		// past the name and reached the right CA.
		got := h.cli(t, ts, "ca", "activate", second.Fingerprint[:12])
		if got.code == 2 {
			t.Fatalf("a fingerprint prefix did not resolve:\n%s", got.stderr)
		}
		if got.code != 0 && got.code != 6 {
			t.Fatalf("unexpected exit %d\n%s%s", got.code, got.stdout, got.stderr)
		}
		// Whichever way it went, it acted on the CA that was named.
		if !strings.Contains(got.stdout+got.stderr, second.Fingerprint[:12]) {
			t.Errorf("output does not mention the CA that was resolved:\n%s%s", got.stdout, got.stderr)
		}
	})

	t.Run("an unknown prefix is a usage error", func(t *testing.T) {
		got := h.cli(t, ts, "ca", "activate", "ffffffffffffffff")
		if got.code != 2 {
			t.Errorf("exit %d, want 2\n%s", got.code, got.stderr)
		}
	})
}

// addCA inserts a second CA into the harness network, pending, sharing a name
// with the bootstrap one.
//
// Written through the store rather than the API because POST /v1/cas needs a
// signer_ref the server can open, and the point here is the name collision, not
// the signing path.
func (h *harness) addCA(t *testing.T, name string) *store.CA {
	t.Helper()
	ctx := context.Background()

	pub, priv, err := ca.GenerateCAKey(h.curve)
	if err != nil {
		t.Fatal(err)
	}
	signer := ca.NewMemorySigner(h.curve, pub, priv)
	now := time.Now()
	caCert, err := ca.CreateCA(ctx, signer, ca.CAParams{
		Name:      name,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		Groups:    []string{"default"},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _ := caCert.MarshalPEM()
	fingerprint, _ := caCert.Fingerprint()

	row := store.CA{
		NetworkID: h.netID, Name: name, Fingerprint: fingerprint,
		CertPEM:   string(pemBytes),
		Curve:     h.curve.String(),
		NotBefore: caCert.NotBefore(), NotAfter: caCert.NotAfter(),
	}
	err = h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.CreateCA(ctx, &row)
	})
	if err != nil {
		t.Fatalf("create second ca: %v", err)
	}
	return &row
}

// TestCLIRefusesIrreversibleActionsWithoutConsent.
//
// The prompt only exists on a terminal, so off one the action has to be refused
// rather than performed: consent has to come from somewhere, and -y is where.
// Proceeding silently would mean any pipeline that reached this — including one
// written by an operator who expected the prompt they get by hand —
// decommissions a host with no confirmation anywhere in it.
func TestCLIRefusesIrreversibleActionsWithoutConsent(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "consent", OverlayAddr: "10.42.75.1",
		RoleID: h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	got := h.cli(t, ts, "membership", "rm", "consent")
	if got.code != 2 {
		t.Errorf("host rm without -y = exit %d, want 2\n%s", got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "-y") {
		t.Errorf("the refusal does not name the way to proceed:\n%s", got.stderr)
	}
	// And nothing happened.
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/memberships/"+host.ID, nil, nil); code != http.StatusOK {
		t.Errorf("the host was removed despite the refusal: %d", code)
	}

	// Blocking is reversible and is deliberately not gated: a prompt on a
	// reversible action trains people to confirm without reading, which is what
	// makes the prompt on an irreversible one worthless.
	if got := h.cli(t, ts, "membership", "block", "consent"); got.code != 0 {
		t.Errorf("host block should not require consent: exit %d\n%s", got.code, got.stderr)
	}

	// With -y the removal goes through.
	if got := h.cli(t, ts, "membership", "rm", "consent", "-y"); got.code != 0 {
		t.Errorf("host rm -y = exit %d\n%s", got.code, got.stderr)
	}
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/memberships/"+host.ID, nil, nil); code != http.StatusNotFound {
		t.Errorf("host survived rm -y: %d", code)
	}
}

// TestCLIPipedOutputStaysParseable.
//
// stdout is not a terminal here, so there must be no truncation, no ANSI escape,
// and no summary footer: `orbit host ls | awk '{print $1}'` has to keep working,
// and a footer is a line that is not a row.
func TestCLIPipedOutputStaysParseable(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	long := "a-deliberately-long-host-name-that-would-be-truncated-on-any-terminal"
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: long, OverlayAddr: "10.42.76.1",
		RoleID: h.roleID.String(),
	}, nil); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	got := h.cli(t, ts, "membership", "ls")
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, long) {
		t.Errorf("a piped listing truncated a name:\n%s", got.stdout)
	}
	if strings.Contains(got.stdout, "\x1b[") {
		t.Errorf("a piped listing emitted ANSI escapes:\n%q", got.stdout)
	}
	if strings.Contains(got.stdout, "…") {
		t.Errorf("a piped listing emitted an ellipsis:\n%s", got.stdout)
	}
	if strings.Contains(got.stdout, "host(s)") {
		t.Errorf("a piped listing emitted a summary footer, which is a line that is not a row:\n%s", got.stdout)
	}
	// Every line is a row awk can split, header included.
	for _, line := range strings.Split(strings.TrimRight(got.stdout, "\n"), "\n") {
		if line == "" {
			t.Errorf("a blank line reached a piped listing:\n%q", got.stdout)
		}
		if strings.HasSuffix(line, " ") {
			t.Errorf("trailing whitespace on %q", line)
		}
	}
}

// TestCLIRefusesTokenInConfigFile.
//
// A config file ends up in a dotfiles repository, in configuration management,
// and in a support bundle. A path to a token survives all three; a token does
// not. The key is declared purely so this refusal can name it — a silently
// ignored line would leave an operator with a CLI that inexplicably has no
// credential.
func TestCLIRefusesTokenInConfigFile(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	dir := t.TempDir()
	cfg := dir + "/config.yaml"
	body := "default_profile: p\nprofiles:\n  p:\n    url: " + ts.URL + "\n    token: orbat_inline\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got := h.cliEnv(t, []string{"ORBIT_CONFIG=" + cfg}, "whoami")
	if got.code != 2 {
		t.Errorf("exit %d, want 2\n%s", got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "token_file") {
		t.Errorf("the refusal does not name the supported form:\n%s", got.stderr)
	}
}

// TestCLIWarnsOnLooseTokenFilePermissions.
//
// Warn, not refuse — mirroring ca.NewFileSignerFromPath's check but not its
// severity. That one guards a mesh-wide root key; this one guards a credential
// that is scoped, revocable, and often expiring, and refusing would strand an
// operator mid-incident over a file mode.
func TestCLIWarnsOnLooseTokenFilePermissions(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	dir := t.TempDir()
	path := dir + "/token"
	if err := os.WriteFile(path, []byte(h.token+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := h.cliEnv(t, []string{
		"ORBIT_URL=" + ts.URL,
		"ORBIT_TOKEN_FILE=" + path,
		"ORBIT_NETWORK=" + h.netName,
	}, "whoami")
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "0644") || !strings.Contains(got.stderr, "chmod 600") {
		t.Errorf("no permission warning, or one without the remedy:\n%s", got.stderr)
	}

	// Tightened, it says nothing.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	got = h.cliEnv(t, []string{
		"ORBIT_URL=" + ts.URL,
		"ORBIT_TOKEN_FILE=" + path,
		"ORBIT_NETWORK=" + h.netName,
	}, "whoami")
	if strings.Contains(got.stderr, "chmod") {
		t.Errorf("warned about a 0600 file:\n%s", got.stderr)
	}
}
