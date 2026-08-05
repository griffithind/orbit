package nebulacfg_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/nebulacfg"
)

// The point of these tests is that they do not assert on YAML text. They render
// a fragment, write real certificates next to it, and hand the result to
// nebula's own Main() in config-test mode, which loads the PKI and builds the
// firewall exactly as a running node would. A fragment that passes here is one
// nebula will actually accept; a golden-file comparison would only prove we
// still produce the string we produced last week.

// writeMesh issues a CA and a host certificate and writes them where a rendered
// fragment expects to find them, returning paths pointing into dir.
func writeMesh(t *testing.T, dir string, addr string) nebulacfg.Paths {
	t.Helper()
	ctx := context.Background()

	caPub, caPriv, err := ca.GenerateCAKey(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatalf("GenerateCAKey: %v", err)
	}
	signer := ca.NewMemorySigner(cert.Curve_CURVE25519, caPub, caPriv)

	now := time.Now()
	caCert, err := ca.CreateCA(ctx, signer, ca.CAParams{
		Name:      "orbit-test",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		Groups:    []string{"web", "db", "ssh"},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	issuer, err := ca.NewIssuer(ctx, caCert, signer)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	hostPub, hostPriv, err := ca.GenerateHostKey(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatalf("GenerateHostKey: %v", err)
	}
	nb, na, err := issuer.ValidityFor(24*time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("ValidityFor: %v", err)
	}
	hostCert, err := issuer.IssueHost(ctx, ca.HostParams{
		Name:      "test-host",
		Networks:  []netip.Prefix{netip.MustParsePrefix(addr)},
		Groups:    []string{"web"},
		PublicKey: hostPub,
		NotBefore: nb,
		NotAfter:  na,
	})
	if err != nil {
		t.Fatalf("IssueHost: %v", err)
	}

	paths := nebulacfg.Paths{
		CA:   filepath.Join(dir, "orbit-ca.crt"),
		Cert: filepath.Join(dir, "orbit-host.crt"),
		Key:  filepath.Join(dir, "orbit-host.key"),
	}

	caPEM, err := caCert.MarshalPEM()
	if err != nil {
		t.Fatalf("marshal ca: %v", err)
	}
	hostPEM, err := hostCert.MarshalPEM()
	if err != nil {
		t.Fatalf("marshal host cert: %v", err)
	}

	write := func(path string, b []byte, mode os.FileMode) {
		if err := os.WriteFile(path, b, mode); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(paths.CA, caPEM, 0o644)
	write(paths.Cert, hostPEM, 0o644)
	write(paths.Key, cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, hostPriv), 0o600)

	return paths
}

// validate runs the fragment through nebula's config-test path, which loads the
// PKI and constructs the firewall without touching the tun device or opening
// sockets.
func validate(t *testing.T, fragment []byte) {
	t.Helper()

	c := config.NewC(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := c.LoadString(string(fragment)); err != nil {
		t.Fatalf("nebula could not parse the fragment: %v\n\n%s", err, fragment)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := nebula.Main(c, true, "orbit-test", logger, nil); err != nil {
		t.Fatalf("nebula rejected the config: %v\n\n%s", err, fragment)
	}
}

func TestRenderIsAcceptedByNebula(t *testing.T) {
	dir := t.TempDir()
	paths := writeMesh(t, dir, "10.42.0.7/16")

	fragment, err := nebulacfg.Render(nebulacfg.Input{
		Paths: paths,
		Lighthouses: []nebulacfg.Lighthouse{{
			VpnAddr:     netip.MustParseAddr("10.42.0.1"),
			StaticAddrs: []string{"lh.example.com:4242", "198.51.100.1:4242"},
		}},
		Relays:     []netip.Addr{netip.MustParseAddr("10.42.0.2")},
		Blocklist:  []string{"deadbeef", "cafebabe"},
		ListenPort: 4242,
		Firewall: &nebulacfg.Firewall{
			Outbound: []nebulacfg.Rule{{Port: "any", Proto: "any", Host: "any"}},
			Inbound: []nebulacfg.Rule{
				{Port: "any", Proto: "icmp", Host: "any"},
				{Port: "22", Proto: "tcp", Groups: []string{"ssh"}},
				{Port: "8000-9000", Proto: "tcp", Group: "web"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	validate(t, fragment)
}

func TestRenderLighthouse(t *testing.T) {
	dir := t.TempDir()
	paths := writeMesh(t, dir, "10.42.0.1/16")

	fragment, err := nebulacfg.Render(nebulacfg.Input{
		Paths:        paths,
		AmLighthouse: true,
		// A lighthouse is given the full list too; Render must drop it, since
		// nebula refuses a config that asks a lighthouse to query lighthouses.
		Lighthouses: []nebulacfg.Lighthouse{{
			VpnAddr:     netip.MustParseAddr("10.42.0.1"),
			StaticAddrs: []string{"198.51.100.1:4242"},
		}},
		ListenPort:  4242,
		TunDisabled: true,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	validate(t, fragment)

	if !strings.Contains(string(fragment), "am_lighthouse: true") {
		t.Error("lighthouse fragment does not set am_lighthouse")
	}
	if strings.Contains(string(fragment), "memberships:\n        - ") {
		t.Error("lighthouse was told to query other lighthouses")
	}
}

// TestRenderMinimal covers the no-role, no-lighthouse case: the fragment must
// still be valid, because a host is created before it has a role.
func TestRenderMinimal(t *testing.T) {
	dir := t.TempDir()
	paths := writeMesh(t, dir, "10.42.0.9/16")

	fragment, err := nebulacfg.Render(nebulacfg.Input{Paths: paths, ListenPort: 4242})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	validate(t, fragment)
}

// TestDisconnectInvalidAlwaysSet guards the setting whose absence silently
// disables the expiry backstop that bounds revocation for a partitioned host.
// Nothing else in the system notices if this regresses.
func TestDisconnectInvalidAlwaysSet(t *testing.T) {
	dir := t.TempDir()
	paths := writeMesh(t, dir, "10.42.0.7/16")

	fragment, err := nebulacfg.Render(nebulacfg.Input{Paths: paths, ListenPort: 4242})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(fragment), "disconnect_invalid: true") {
		t.Fatal("pki.disconnect_invalid is not set; expiry will not tear down live tunnels")
	}

	// And confirm nebula actually reads it as true, rather than us matching a
	// string that happens to appear.
	c := config.NewC(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := c.LoadString(string(fragment)); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !c.GetBool("pki.disconnect_invalid", false) {
		t.Error("nebula reads pki.disconnect_invalid as false")
	}
}

// TestRenderIsDeterministic is what lets an agent hash the fragment to decide
// whether anything changed. Go map iteration is randomised, so a static_host_map
// or blocklist emitted straight from a map would differ on every render and
// every host would see a spurious update on every poll.
func TestRenderIsDeterministic(t *testing.T) {
	in := nebulacfg.Input{
		Paths: nebulacfg.DefaultPaths(),
		Lighthouses: []nebulacfg.Lighthouse{
			{VpnAddr: netip.MustParseAddr("10.42.0.3"), StaticAddrs: []string{"c:4242", "a:4242"}},
			{VpnAddr: netip.MustParseAddr("10.42.0.1"), StaticAddrs: []string{"b:4242"}},
			{VpnAddr: netip.MustParseAddr("10.42.0.2"), StaticAddrs: []string{"d:4242"}},
		},
		Relays:     []netip.Addr{netip.MustParseAddr("10.42.0.9"), netip.MustParseAddr("10.42.0.4")},
		Blocklist:  []string{"ffff", "0000", "aaaa"},
		ListenPort: 4242,
	}

	first, err := nebulacfg.Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for i := 0; i < 25; i++ {
		got, err := nebulacfg.Render(in)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if string(got) != string(first) {
			t.Fatalf("render %d differs from the first:\n--- first ---\n%s\n--- got ---\n%s", i, first, got)
		}
	}

	// Sorting must be by value, not insertion order.
	s := string(first)
	if idx1, idx2 := strings.Index(s, "10.42.0.1"), strings.Index(s, "10.42.0.3"); idx1 > idx2 {
		t.Error("static_host_map is not sorted by address")
	}
}

// TestUnreachableLighthouseSkipped covers a lighthouse that has no underlay
// address yet. Emitting it would make every host retry forever against nothing.
func TestUnreachableLighthouseSkipped(t *testing.T) {
	fragment, err := nebulacfg.Render(nebulacfg.Input{
		Paths: nebulacfg.DefaultPaths(),
		Lighthouses: []nebulacfg.Lighthouse{
			{VpnAddr: netip.MustParseAddr("10.42.0.1"), StaticAddrs: []string{"good:4242"}},
			{VpnAddr: netip.MustParseAddr("10.42.0.2")}, // not yet enrolled
		},
		ListenPort: 4242,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := string(fragment)
	if !strings.Contains(s, "10.42.0.1") {
		t.Error("reachable lighthouse missing")
	}
	if strings.Contains(s, "10.42.0.2") {
		t.Error("lighthouse with no underlay address was emitted")
	}
}

// TestRelayDoesNotUseRelays pins the coupling nebula enforces internally
// (relay_manager.go sets useRelays false when am_relay is true). Rendering it
// explicitly keeps the config honest about what the host will do.
func TestRelayDoesNotUseRelays(t *testing.T) {
	fragment, err := nebulacfg.Render(nebulacfg.Input{
		Paths: nebulacfg.DefaultPaths(), AmRelay: true, ListenPort: 4242,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := string(fragment)
	if !strings.Contains(s, "am_relay: true") || !strings.Contains(s, "use_relays: false") {
		t.Errorf("relay section is inconsistent:\n%s", s)
	}
}

func TestParseFirewall(t *testing.T) {
	t.Run("empty yields deny-inbound default", func(t *testing.T) {
		fw, err := nebulacfg.ParseFirewall(nil)
		if err != nil {
			t.Fatalf("ParseFirewall: %v", err)
		}
		if len(fw.Inbound) != 0 {
			t.Errorf("default inbound = %d rules, want 0 (deny by default)", len(fw.Inbound))
		}
		if len(fw.Outbound) != 1 {
			t.Errorf("default outbound = %d rules, want 1 (allow any)", len(fw.Outbound))
		}
	})

	t.Run("round trips a role definition", func(t *testing.T) {
		raw := []byte(`{"inbound":[{"port":"443","proto":"tcp","groups":["web"]}],
		                "outbound":[{"port":"any","proto":"any","host":"any"}]}`)
		fw, err := nebulacfg.ParseFirewall(raw)
		if err != nil {
			t.Fatalf("ParseFirewall: %v", err)
		}
		if len(fw.Inbound) != 1 || fw.Inbound[0].Port != "443" {
			t.Fatalf("inbound = %+v", fw.Inbound)
		}
		if len(fw.Inbound[0].Groups) != 1 || fw.Inbound[0].Groups[0] != "web" {
			t.Errorf("groups = %v", fw.Inbound[0].Groups)
		}
	})
}
