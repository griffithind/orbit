package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/service"

	orbitca "github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/fwmatch"
)

// The cross-check that keeps `orbit why` honest.
//
// The explainer re-implements nebula's rule matching, because
// FirewallTable.match is unexported and Firewall.Drop needs a *HostInfo whose
// fields are unexported. Second implementations drift, and a diagnostic that
// confidently reports the wrong answer is worse than no diagnostic at all.
//
// So this does not test the explainer against a model of nebula. It boots TWO
// real nebula instances, opens real TCP connections between them through real
// firewall tables, and asserts that what the explainer predicted is what
// happened. When upstream changes the matching, this fails.
//
// Userspace devices (overlay.NewUserDeviceFromConfig, nil) rather than tun, so it
// needs no root and runs in ordinary CI — the firewall is in the packet path
// either way, since Drop does not care what the device is.

const (
	lighthouseAddr = "10.99.0.1"
	clientAddr     = "10.99.0.2"
)

// testCA is a certificate authority and the hosts under it.
type testCA struct {
	cert cert.Certificate
	// ECDSA P-256, not Ed25519: every Orbit network is P-256 (migration 0021),
	// and a certificate whose curve differs from its signer's is refused by
	// nebula's own ca_pool. Raw bytes because that is what cert.Sign takes.
	key  []byte
	dir  string
	path string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	pub, priv, err := orbitca.GenerateCAKey(cert.Curve_P256)
	if err != nil {
		t.Fatal(err)
	}
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      "why-test-ca",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")},
		IsCA:      true,
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  time.Now().Add(48 * time.Hour),
		PublicKey: pub,
		Curve:     cert.Curve_P256,
	}
	c, err := tbs.Sign(nil, cert.Curve_P256, priv)
	if err != nil {
		t.Fatal(err)
	}

	dir := shortTempDir(t)
	pem, err := c.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: priv, dir: dir, path: path}
}

// host writes a signed certificate and its key, returning their paths.
func (ca *testCA) host(t *testing.T, name, addr string, groups []string) (certPath, keyPath string) {
	t.Helper()
	// A HANDSHAKE keypair, not a signing one. The CA signs with ECDSA P-256,
	// but a host certificate carries the Noise DH key and pki.key is its
	// private half — handing nebula a signing key here fails at load with a
	// message about key length, which names the symptom and not the
	// distinction.
	pub, priv, err := orbitca.GenerateHostKey(cert.Curve_P256)
	if err != nil {
		t.Fatal(err)
	}
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      name,
		Networks:  []netip.Prefix{netip.MustParsePrefix(addr + "/24")},
		Groups:    groups,
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		PublicKey: pub,
		Curve:     cert.Curve_P256,
	}
	c, err := tbs.Sign(ca.cert, cert.Curve_P256, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := c.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(ca.dir, name+".crt")
	keyPath = filepath.Join(ca.dir, name+".key")
	if err := os.WriteFile(certPath, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, cert.MarshalPrivateKeyToPEM(cert.Curve_P256, priv), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// nodeConfig renders a nebula configuration for one end.
//
// inbound_action and outbound_action are `reject` rather than the default
// `drop` purely for speed: a rejected connection fails immediately with a RST
// where a dropped one waits for a dial timeout, and across a matrix of ports
// that is the difference between seconds and minutes. It does not change what
// is permitted, only how a denial is announced.
func nodeConfig(caPath, certPath, keyPath string, isLighthouse bool, port, lhPort int, inbound, outbound string) string {
	lhHosts := `["` + lighthouseAddr + `"]`
	if isLighthouse {
		lhHosts = "[]"
	}
	return fmt.Sprintf(`
pki:
  ca: %s
  cert: %s
  key: %s
static_host_map:
  "%s": ["127.0.0.1:%d"]
lighthouse:
  am_lighthouse: %t
  interval: 1
  hosts: %s
listen:
  host: 127.0.0.1
  port: %d
punchy:
  punch: false
relay:
  am_relay: false
  use_relays: false
tun:
  disabled: false
  dev: nebula-why-test
  mtu: 1300
firewall:
  inbound_action: reject
  outbound_action: reject
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m
  inbound:
%s
  outbound:
%s
logging:
  level: error
`, caPath, certPath, keyPath, lighthouseAddr, lhPort, isLighthouse, lhHosts, port, inbound, outbound)
}

// allowAll is the wide-open rule list, used on whichever side is not under test
// so that a verdict is attributable to one table.
const allowAll = "    - port: any\n      proto: any\n      host: any\n"

func bootNode(t *testing.T, name, cfgYAML string) (*service.Service, string) {
	t.Helper()
	dir := shortTempDir(t)
	path := filepath.Join(dir, "nebula.yml")
	if err := os.WriteFile(path, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	quiet := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	c := config.NewC(quiet)
	if err := c.Load(path); err != nil {
		t.Fatalf("%s: load config: %v\n%s", name, err, cfgYAML)
	}
	ctrl, err := nebula.Main(c, false, "why-"+name, quiet, overlay.NewUserDeviceFromConfig, nil)
	if err != nil {
		t.Fatalf("%s: nebula refused the config: %v\n%s", name, err, cfgYAML)
	}
	svc, err := service.New(ctrl)
	if err != nil {
		t.Fatalf("%s: service: %v", name, err)
	}
	stopNebulaOnCleanup(t, svc)
	return svc, path
}

// reachable reports whether a TCP connection actually completes.
func reachable(t *testing.T, from *service.Service, addr string, port int) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	conn, err := from.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// serveOn accepts and closes connections on a port, so a successful dial means
// the firewall let it through rather than that nothing was listening.
func serveOn(t *testing.T, svc *service.Service, port int) {
	t.Helper()
	ln, err := svc.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("listen on %d: %v", port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
}

// waitForTunnel blocks until the two ends have handshaked, using a port both
// sides permit. Without it the first case in a matrix measures handshake
// latency rather than the firewall.
func waitForTunnel(t *testing.T, from *service.Service, port int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if reachable(t, from, lighthouseAddr, port) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the two nebula instances never established a tunnel")
}

// TestExplainerAgreesWithNebulaOnOutbound varies the CLIENT's outbound table
// while the far side permits everything, so each verdict is attributable.
func TestExplainerAgreesWithNebulaOnOutbound(t *testing.T) {
	ca := newTestCA(t)
	lhCert, lhKey := ca.host(t, "lighthouse", lighthouseAddr, []string{"lh", "infra"})
	cliCert, cliKey := ca.host(t, "client", clientAddr, []string{"app"})

	lhPort, cliPort := freeUDPPort(t), freeUDPPort(t)

	// A deliberately awkward outbound table: an exact port, a range, a
	// group selector, a host selector, and a rule for a peer that is not this
	// one. Between them they exercise every term the matcher implements.
	outbound := `    - port: 443
      proto: tcp
      cidr: ` + lighthouseAddr + `/32
    - port: 9000-9100
      proto: tcp
      cidr: ` + lighthouseAddr + `/32
    - port: 8080
      proto: tcp
      groups: [lh, infra]
    - port: 7000
      proto: tcp
      host: lighthouse
    - port: 6000
      proto: tcp
      groups: [nonexistent]
    - port: 5000
      proto: tcp
      cidr: 10.99.0.99/32
`

	lhSvc, _ := bootNode(t, "lighthouse",
		nodeConfig(ca.path, lhCert, lhKey, true, lhPort, lhPort, allowAll, allowAll))
	cliSvc, cliCfg := bootNode(t, "client",
		nodeConfig(ca.path, cliCert, cliKey, false, cliPort, lhPort, allowAll, outbound))

	ports := []int{443, 9050, 8080, 7000, 6000, 5000, 80, 9101}
	for _, p := range ports {
		serveOn(t, lhSvc, p)
	}
	waitForTunnel(t, cliSvc, 443)

	_, out, err := fwmatch.LoadRules(cliCfg)
	if err != nil {
		t.Fatal(err)
	}

	// The peer's certificate IS known here: the tunnel is up, which is what
	// lets group and host rules be decided at all.
	var allowed, denied bool
	for _, p := range ports {
		q := fwmatch.Query{
			PeerAddr:      netip.MustParseAddr(lighthouseAddr),
			LocalAddr:     netip.MustParseAddr(clientAddr),
			Proto:         firewall.ProtoTCP,
			Port:          int32(p),
			PeerCertKnown: true,
			PeerName:      "lighthouse",
			PeerGroups:    []string{"lh", "infra"},
		}
		predicted := fwmatch.Decide(out, q).Allowed
		actual := reachable(t, cliSvc, lighthouseAddr, p)
		t.Logf("tcp/%-5d predicted=%-5v actual=%v", p, predicted, actual)
		allowed, denied = allowed || actual, denied || !actual

		if predicted != actual {
			t.Errorf("tcp/%d: the explainer said allowed=%v, nebula did allowed=%v.\n"+
				"`orbit why` would tell an operator the opposite of what happens.",
				p, predicted, actual)
		}
	}
	requireBothOutcomes(t, allowed, denied)
}

// TestExplainerAgreesWithNebulaOnInbound is the mirror: the client sends
// everything and the far side decides, so this exercises the inbound table.
func TestExplainerAgreesWithNebulaOnInbound(t *testing.T) {
	ca := newTestCA(t)
	lhCert, lhKey := ca.host(t, "lighthouse", lighthouseAddr, []string{"lh"})
	cliCert, cliKey := ca.host(t, "client", clientAddr, []string{"app", "edge"})

	lhPort, cliPort := freeUDPPort(t), freeUDPPort(t)

	inbound := `    - port: 443
      proto: tcp
      groups: [app, edge]
    - port: 8443
      proto: tcp
      cidr: ` + clientAddr + `/32
    - port: 1000-1010
      proto: any
      host: client
    - port: 22
      proto: tcp
      groups: [app, missing]
`

	lhSvc, lhCfg := bootNode(t, "lighthouse",
		nodeConfig(ca.path, lhCert, lhKey, true, lhPort, lhPort, inbound, allowAll))
	cliSvc, _ := bootNode(t, "client",
		nodeConfig(ca.path, cliCert, cliKey, false, cliPort, lhPort, allowAll, allowAll))

	ports := []int{443, 8443, 1005, 22, 80, 1011}
	for _, p := range ports {
		serveOn(t, lhSvc, p)
	}
	waitForTunnel(t, cliSvc, 443)

	in, _, err := fwmatch.LoadRules(lhCfg)
	if err != nil {
		t.Fatal(err)
	}

	var allowed, denied bool
	for _, p := range ports {
		q := fwmatch.Query{
			PeerAddr:      netip.MustParseAddr(clientAddr),
			LocalAddr:     netip.MustParseAddr(lighthouseAddr),
			Proto:         firewall.ProtoTCP,
			Port:          int32(p),
			PeerCertKnown: true,
			PeerName:      "client",
			PeerGroups:    []string{"app", "edge"},
		}
		predicted := fwmatch.Decide(in, q).Allowed
		actual := reachable(t, cliSvc, lighthouseAddr, p)
		t.Logf("tcp/%-5d predicted=%-5v actual=%v", p, predicted, actual)
		allowed, denied = allowed || actual, denied || !actual

		if predicted != actual {
			t.Errorf("tcp/%d inbound: the explainer said allowed=%v, nebula did allowed=%v",
				p, predicted, actual)
		}
	}
	requireBothOutcomes(t, allowed, denied)
}

// requireBothOutcomes is what stops the cross-check passing vacuously.
//
// If every port were denied — a tunnel that never came up would do it — the
// explainer and nebula would agree on "no" everywhere and the test would go
// green having compared nothing. The matrix has to produce both answers for the
// agreement to mean anything.
func requireBothOutcomes(t *testing.T, allowed, denied bool) {
	t.Helper()
	if !allowed {
		t.Error("no port was reachable: the tunnel never carried traffic, so this " +
			"compared nothing and would agree with any matcher at all")
	}
	if !denied {
		t.Error("every port was reachable: the firewall permitted everything, so " +
			"this compared nothing")
	}
}

// TestLoadRulesUsesNebulasParser.
//
// The parsing half is delegated on purpose — nebula reads the config and calls
// AddRule on a collector — so this asserts the delegation is real by feeding it
// forms only nebula's parser handles: `group` singular, a port range, `any`,
// and ICMP, whose ports nebula coerces before the collector ever sees them.
func TestLoadRulesUsesNebulasParser(t *testing.T) {
	dir := shortTempDir(t)
	path := filepath.Join(dir, "fw.yml")
	if err := os.WriteFile(path, []byte(`
firewall:
  outbound:
    - port: 80-90
      proto: tcp
      group: web
    - port: any
      proto: icmp
      host: any
  inbound: []
`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, out, err := fwmatch.LoadRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d outbound rules, want 2: %+v", len(out), out)
	}

	// `group:` singular flattened into Groups — a form our own parser would
	// have had to know about.
	if len(out[0].Groups) != 1 || out[0].Groups[0] != "web" {
		t.Errorf("singular `group` did not flatten: %+v", out[0].Groups)
	}
	if out[0].StartPort != 80 || out[0].EndPort != 90 {
		t.Errorf("port range = %d-%d, want 80-90", out[0].StartPort, out[0].EndPort)
	}
	// ICMP ports are coerced to any by nebula before AddRule is called.
	if out[1].StartPort != firewall.PortAny {
		t.Errorf("icmp port = %d, want PortAny; nebula coerces it and we should "+
			"see the coerced value", out[1].StartPort)
	}
}
