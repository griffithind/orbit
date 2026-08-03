// Package e2e exercises the whole phase-2 path: bootstrap, host creation,
// enrollment code, agent enrollment, config apply, and two real nebula nodes
// establishing an encrypted tunnel using the certificates Orbit issued.
//
// Nebula runs here with a userspace device (overlay.NewUserDeviceFromConfig,
// the same mechanism examples/go_service uses), so no tun device and no root
// are required and the test is safe in CI.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/service"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/db"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/mesh"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

const (
	adminDSN = "postgres://postgres:orbit@localhost:5433/orbit?sslmode=disable"
	appDSN   = "postgres://orbit_app:orbit_app_test@localhost:5433/orbit?sslmode=disable"
)

func dsn(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return def
}

// harness is a running control plane backed by a real database.
type harness struct {
	t       *testing.T
	store   *store.Store
	server  *httptest.Server
	netID   uuid.UUID
	netName string
	roleID  uuid.UUID
	token   string
	caKey   string
}

func setup(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, dsn("ORBIT_TEST_DSN", adminDSN))
	if err != nil {
		t.Skipf("postgres unavailable, skipping e2e: %v", err)
	}
	defer admin.Close(ctx)

	if _, err := db.Migrate(ctx, admin); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Serialized on the migration advisory lock: e2e and internal/store run as
	// separate packages, go test runs packages in parallel, and two concurrent
	// ALTER ROLEs against the same role fail with "tuple concurrently updated".
	if err := db.EnsureRoleLogin(ctx, admin, "orbit_app", "orbit_app_test"); err != nil {
		t.Fatalf("grant login: %v", err)
	}

	st, err := store.Open(ctx, dsn("ORBIT_TEST_APP_DSN", appDSN))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)

	h := &harness{t: t, store: st}
	h.bootstrap(t)
	return h
}

// bootstrap mirrors what `orbitd bootstrap` does, in-process. Each call creates
// its own network so tests never collide.
func (h *harness) bootstrap(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	caPub, caPriv, err := ca.GenerateCAKey(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	h.caKey = filepath.Join(dir, "ca.key")
	if err := os.WriteFile(h.caKey, cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, caPriv), 0o600); err != nil {
		t.Fatalf("write ca key: %v", err)
	}

	signer := ca.NewMemorySigner(cert.Curve_CURVE25519, caPub, caPriv)
	now := time.Now()
	caCert, err := ca.CreateCA(ctx, signer, ca.CAParams{
		Name:      "e2e-ca",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		Groups:    []string{"default"},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caPEM, _ := caCert.MarshalPEM()
	fingerprint, _ := caCert.Fingerprint()

	token, tokenHash, err := store.NewAPIToken()
	if err != nil {
		t.Fatalf("new token: %v", err)
	}
	h.token = token
	h.netName = "e2e-" + uuid.NewString()[:8]

	err = h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		net := store.Network{
			Name:    h.netName,
			CIDRs:   []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
			CertVer: int16(cert.Version2),
			Curve:   cert.Curve_CURVE25519.String(),
			CertTTL: 24 * time.Hour,
		}
		if err := tx.CreateNetwork(ctx, &net); err != nil {
			return err
		}
		h.netID = net.ID

		caRow := store.CA{
			NetworkID: net.ID, Name: "e2e-ca", Fingerprint: fingerprint,
			CertPEM: string(caPEM), SignerRef: "file://" + h.caKey,
			Curve:     cert.Curve_CURVE25519.String(),
			NotBefore: caCert.NotBefore(), NotAfter: caCert.NotAfter(),
		}
		if err := tx.CreateCA(ctx, &caRow); err != nil {
			return err
		}
		if err := tx.ActivateCA(ctx, net.ID, caRow.ID); err != nil {
			return err
		}

		role := store.Role{
			NetworkID: net.ID, Name: "default", Groups: []string{"default"},
			FirewallRules: []byte(`{
				"inbound":  [{"port":"any","proto":"any","host":"any"}],
				"outbound": [{"port":"any","proto":"any","host":"any"}]
			}`),
		}
		if err := tx.CreateRole(ctx, &role); err != nil {
			return err
		}
		h.roleID = role.ID

		_, err := tx.CreateAPIToken(ctx, "e2e", tokenHash, []string{"*"}, nil)
		return err
	})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
}

// serve starts the HTTP surfaces with the given nebula listen port baked into
// rendered configs.
//
// Two hosts on one machine cannot share a UDP port, so the test runs a service
// per port. In a real deployment every host uses the same port and one service
// suffices; here it is the cheapest way to keep the rendered configs authentic
// rather than editing them after the fact.
func (h *harness) serve(t *testing.T, nebulaPort int) *httptest.Server {
	t.Helper()

	hasher, err := enroll.NewHasher([]byte(strings.Repeat("pepper-for-tests", 4)))
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	registry := ca.NewRegistry(ca.FileSignerFactory)
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, hasher, enroll.Config{
		Paths:      nebulacfg.DefaultPaths(),
		ListenPort: nebulaPort,
	})

	srv := api.New(h.store, svc, api.Config{
		Agent:         &api.AgentListener{NetworkID: h.netID},
		SignerFactory: ca.FileSignerFactory,
		// Off by default in the harness: most tests enroll many hosts in a
		// tight loop from one address, which is exactly what the limiter is
		// meant to stop. TestEnrollmentIsRateLimited opts back in.
		DisableEnrollLimit: true,
		// Test-only. Lets a test assert an overlay source address without
		// booting nebula. Never enable this on a directly-exposed listener:
		// a client that sets its own header can claim any identity.
		TrustForwardedFor: true,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// serveOverlay runs the agent API on a nebula node's overlay listener.
//
// This is the real phase-5 architecture, not a simulation: the handler's
// r.RemoteAddr is the peer's overlay address, and nebula's firewall has already
// verified on every packet that the peer's certificate actually contains that
// address (firewall.go Drop). Nothing here trusts a header.
func (h *harness) serveOverlay(t *testing.T, n *nebulaNode, port, nebulaPort int) string {
	t.Helper()

	hasher, err := enroll.NewHasher([]byte(strings.Repeat("pepper-for-tests", 4)))
	if err != nil {
		t.Fatal(err)
	}
	registry := ca.NewRegistry(ca.FileSignerFactory)
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, hasher, enroll.Config{
		Paths:      nebulacfg.DefaultPaths(),
		ListenPort: nebulaPort,
	})
	handler := api.New(h.store, svc, api.Config{
		Agent: &api.AgentListener{NetworkID: h.netID},
	}, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()

	ln, err := n.svc.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("listen on overlay: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return fmt.Sprintf("http://%s:%d", n.addr, port)
}

// serveOverlayWithPush is serveOverlay with the notifier attached, enabling
// /agent/v1/watch.
func (h *harness) serveOverlayWithPush(t *testing.T, n *nebulaNode, port, nebulaPort int, notifier *notify.Notifier) string {
	t.Helper()

	hasher, err := enroll.NewHasher([]byte(strings.Repeat("pepper-for-tests", 4)))
	if err != nil {
		t.Fatal(err)
	}
	registry := ca.NewRegistry(ca.FileSignerFactory)
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, hasher, enroll.Config{
		Paths:      nebulacfg.DefaultPaths(),
		ListenPort: nebulaPort,
	})
	handler := api.New(h.store, svc, api.Config{
		Agent:       &api.AgentListener{NetworkID: h.netID},
		Notifier:    notifier,
		MaxWatchers: 1000,
	}, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()

	ln, err := n.svc.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("listen on overlay: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return fmt.Sprintf("http://%s:%d", n.addr, port)
}

// overlayHTTPClient dials through a nebula node, so requests reach an overlay
// listener and carry the node's overlay address as their source.
func overlayHTTPClient(n *nebulaNode) *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{DialContext: n.svc.DialContext},
	}
}

// serveRateLimited is harness.serve with the enrollment limiter active.
func (h *harness) serveRateLimited(t *testing.T, nebulaPort int) *httptest.Server {
	t.Helper()

	hasher, err := enroll.NewHasher([]byte(strings.Repeat("pepper-for-tests", 4)))
	if err != nil {
		t.Fatal(err)
	}
	registry := ca.NewRegistry(ca.FileSignerFactory)
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, hasher, enroll.Config{
		Paths:      nebulacfg.DefaultPaths(),
		ListenPort: nebulaPort,
	})
	srv := api.New(h.store, svc, api.Config{
		EnrollLimit: api.LimiterConfig{PerMinute: 6, Burst: 6, GlobalPerMinute: 600, GlobalBurst: 200},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mux := http.NewServeMux()
	srv.EnrollRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func (h *harness) adminPost(t *testing.T, url string, body, out any) int {
	t.Helper()
	return h.adminReq(t, http.MethodPost, url, body, out)
}

func (h *harness) adminReq(t *testing.T, method, url string, body, out any) int {
	t.Helper()
	return h.reqAs(t, h.token, method, url, body, out)
}

// reqAs issues a request with a specific token, for exercising scope
// enforcement. The bootstrap token holds "*", so it can never prove that a
// route checks the scope it declares.
func (h *harness) reqAs(t *testing.T, token, method, url string, body, out any) int {
	t.Helper()

	var rdr io.Reader
	if body != nil {
		b, err := jsonMarshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := jsonUnmarshal(raw, out); err != nil {
			t.Fatalf("decode %s: %v (%s)", url, err, raw)
		}
	}
	if resp.StatusCode >= 300 {
		t.Logf("%s %s -> %d: %s", method, url, resp.StatusCode, raw)
	}
	return resp.StatusCode
}

// freeUDPPort asks the kernel for an unused port. There is a small race between
// releasing it and nebula binding it, which is acceptable in a test and much
// better than hardcoding ports that collide with whatever else is running.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// enrolledHost is a host that has been created, enrolled, and had its
// configuration written to disk by the real agent applier.
type enrolledHost struct {
	name    string
	addr    netip.Addr
	dir     string
	id      string
	respons *wire.EnrollResponse
}

// createAndEnroll runs the full operator-then-agent flow.
func (h *harness) createAndEnroll(t *testing.T, ts *httptest.Server, name, addr string, lighthouse, relay bool, staticAddrs []string) *enrolledHost {
	t.Helper()
	ctx := context.Background()

	var host wire.HostResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts", wire.CreateHostRequest{
		NetworkID:    h.netID.String(),
		Name:         name,
		OverlayAddr:  addr,
		RoleID:       h.roleID.String(),
		IsLighthouse: lighthouse,
		IsRelay:      relay,
		StaticAddrs:  staticAddrs,
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host %s: status %d", name, code)
	}

	var codeResp wire.EnrollmentCodeResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts/"+host.ID+"/enrollment-code", nil, &codeResp); code != http.StatusCreated {
		t.Fatalf("enrollment code for %s: status %d", name, code)
	}
	if codeResp.Code == "" {
		t.Fatal("empty enrollment code")
	}

	// From here on this is exactly what `orbit agent enroll` does.
	kp, err := agent.GenerateKeypair(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	client := agent.NewClient(ts.URL)
	resp, err := client.Enroll(ctx, codeResp.Code, kp, "e2e")
	if err != nil {
		t.Fatalf("enroll %s: %v", name, err)
	}

	dir := t.TempDir()
	applier := &agent.Applier{
		Layout:   agent.DefaultLayout(dir),
		Reloader: agent.NoopReloader{},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := applier.Apply(ctx, agent.MaterialFromEnroll(resp, kp.PrivatePEM)); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}

	// The real CLI persists state after applying; tests that later drive the
	// agent loop need it too.
	if err := agent.WriteState(dir, agent.State{
		BaseURL:        ts.URL,
		HostID:         resp.HostID,
		ConfigEpoch:    resp.ConfigEpoch,
		BlocklistEpoch: resp.BlocklistEpoch,
	}); err != nil {
		t.Fatalf("write agent state: %v", err)
	}

	return &enrolledHost{
		name: name, addr: netip.MustParseAddr(addr), dir: dir,
		id: host.ID, respons: resp,
	}
}

// TestEnrollmentEndToEnd is the phase-2 acceptance test. It ends with two real
// nebula nodes exchanging bytes over a tunnel whose certificates Orbit issued
// and whose configuration Orbit rendered.
func TestEnrollmentEndToEnd(t *testing.T) {
	h := setup(t)

	lhPort := freeUDPPort(t)
	clientPort := freeUDPPort(t)

	lhServer := h.serve(t, lhPort)
	clientServer := h.serve(t, clientPort)

	// The lighthouse is also a relay so that it keeps a tun device; a
	// tun-disabled lighthouse cannot be driven by the userspace stack this test
	// uses to prove connectivity.
	lh := h.createAndEnroll(t, lhServer, "lighthouse", "10.42.0.1", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})
	client := h.createAndEnroll(t, clientServer, "client", "10.42.0.7", false, false, nil)

	// The agent wrote real files. Confirm the shape before booting anything.
	for _, hst := range []*enrolledHost{lh, client} {
		for _, f := range []string{
			"ca.crt", "host.crt", "host.key",
			"nebula.yml",
		} {
			p := filepath.Join(hst.dir, f)
			info, err := os.Stat(p)
			if err != nil {
				t.Fatalf("%s: missing %s: %v", hst.name, f, err)
			}
			if strings.HasSuffix(f, ".key") && info.Mode().Perm() != 0o600 {
				t.Errorf("%s: private key mode is %v, want 0600", hst.name, info.Mode().Perm())
			}
		}
	}

	// The client's config must point at the lighthouse; the lighthouse's must
	// not point at itself.
	clientCfg := readFile(t, agent.DefaultLayout(client.dir).ConfigPath())
	if !strings.Contains(clientCfg, "10.42.0.1") {
		t.Fatalf("client config does not reference the lighthouse:\n%s", clientCfg)
	}
	if !strings.Contains(clientCfg, fmt.Sprintf("127.0.0.1:%d", lhPort)) {
		t.Fatalf("client config lacks the lighthouse underlay address:\n%s", clientCfg)
	}

	lhCfg := readFile(t, agent.DefaultLayout(lh.dir).ConfigPath())
	if strings.Contains(lhCfg, "hosts:\n        - ") {
		t.Errorf("lighthouse was told to query a lighthouse:\n%s", lhCfg)
	}

	// Boot both nodes.
	lhSvc := startNebula(t, lh.dir)
	clientSvc := startNebula(t, client.dir)

	// Prove an actual tunnel: the lighthouse listens on the overlay, the client
	// dials it. Nothing here can succeed unless the certificates verify against
	// a common CA, the firewall rules permit the flow, and the handshake
	// completes.
	const port = 9999
	ln, err := lhSvc.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("lighthouse listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("orbit-ok"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var conn net.Conn
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = clientSvc.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", lh.addr, port))
		if err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("client could not reach the lighthouse over the overlay: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read over tunnel: %v", err)
	}
	if got := string(buf[:n]); got != "orbit-ok" {
		t.Fatalf("read %q over the tunnel, want %q", got, "orbit-ok")
	}

	_ = ln.Close()
	wg.Wait()

	t.Log("tunnel established using Orbit-issued certificates and Orbit-rendered config")
}

// nebulaNode is a running nebula plus the config handle that drives its
// reloads, so a test can exercise the same hot-reload path SIGHUP uses.
type nebulaNode struct {
	cfg  *config.C
	svc  *service.Service
	ctrl *nebula.Control
	addr netip.Addr
}

// HasTunnelTo reports whether this node currently holds a tunnel to addr.
//
// Read straight from nebula's hostmap, so it observes the data plane's actual
// state rather than anything Orbit believes. This is what makes the propagation
// measurement honest: the clock stops when the tunnel is genuinely gone, not
// when a config was written.
func (n *nebulaNode) HasTunnelTo(addr netip.Addr) bool {
	for _, h := range n.ctrl.ListHostmapHosts(false) {
		for _, a := range h.VpnAddrs {
			if a == addr {
				return true
			}
		}
	}
	return false
}

// bootNebula starts a nebula node from an agent-written directory, using the
// userspace device so no tun and no root are needed.
func bootNebula(t *testing.T, dir string, addr netip.Addr) (*nebulaNode, error) {
	t.Helper()

	c := config.NewC(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := c.Load(agent.DefaultLayout(dir).NebulaConfigArg()); err != nil {
		return nil, fmt.Errorf("load config from %s: %w", dir, err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	ctrl, err := nebula.Main(c, false, "orbit-e2e", logger, overlay.NewUserDeviceFromConfig)
	if err != nil {
		return nil, fmt.Errorf("start nebula in %s: %w", dir, err)
	}

	svc, err := service.New(ctrl)
	if err != nil {
		return nil, fmt.Errorf("start nebula service: %w", err)
	}
	stopNebulaOnCleanup(t, svc)
	return &nebulaNode{cfg: c, svc: svc, ctrl: ctrl, addr: addr}, nil
}

// stopNebulaOnCleanup tears an in-process nebula down, and gives up if it does
// not finish.
//
// The bound is the point. service.Wait blocks until every nebula reader
// goroutine has exited and the interface has released its construction token,
// and a shutdown race that leaves one of them parked makes it block forever.
// In a t.Cleanup that does not fail one test — it hangs the whole package until
// the go test timeout, and every other test's result is lost with it. That is
// exactly what happened: one stalled teardown produced
// "FAIL github.com/griffithind/orbit/e2e 600.017s" with every other package ok,
// on a runner slow enough to lose the race a developer's machine wins.
//
// Leaking goroutines into a test binary that is about to exit costs nothing.
// Losing the whole suite's result costs everything.
func stopNebulaOnCleanup(t *testing.T, svc *service.Service) {
	t.Helper()
	t.Cleanup(func() {
		_ = svc.Close()

		done := make(chan struct{})
		go func() {
			_ = svc.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(mesh.ShutdownGrace):
			// Not t.Error: nebula's shutdown is not what any of these tests are
			// about, and failing an unrelated assertion on it would make the
			// suite lie about which thing broke. Visible in -v, and the
			// production path logs the same thing.
			t.Logf("nebula did not finish shutting down within %s; continuing", mesh.ShutdownGrace)
		}
	})
}

// startNebula is bootNebula for callers that treat a failure as fatal.
func startNebula(t *testing.T, dir string) *service.Service {
	t.Helper()
	n, err := bootNebula(t, dir, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	return n.svc
}

// TestEnrollmentCodeIsSingleUse proves at the HTTP layer what the store test
// proves at the database layer: a redeemed code is spent.
func TestEnrollmentCodeIsSingleUse(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	var host wire.HostResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts", wire.CreateHostRequest{
		NetworkID: h.netID.String(), Name: "single-use", OverlayAddr: "10.42.0.20",
		RoleID: h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	var codeResp wire.EnrollmentCodeResponse
	h.adminPost(t, ts.URL+"/v1/hosts/"+host.ID+"/enrollment-code", nil, &codeResp)

	client := agent.NewClient(ts.URL)
	kp1, _ := agent.GenerateKeypair(cert.Curve_CURVE25519)
	if _, err := client.Enroll(ctx, codeResp.Code, kp1, "e2e"); err != nil {
		t.Fatalf("first enrollment failed: %v", err)
	}

	kp2, _ := agent.GenerateKeypair(cert.Curve_CURVE25519)
	_, err := client.Enroll(ctx, codeResp.Code, kp2, "e2e")
	if err == nil {
		t.Fatal("second enrollment with the same code succeeded")
	}
	var apiErr *agent.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("second enrollment error = %v, want 401", err)
	}
	if apiErr.Retryable() {
		t.Error("a spent code was reported as retryable; the agent would loop")
	}
}

// TestBlockedHostCannotEnroll proves blocking is not merely cosmetic: a blocked
// host cannot obtain a new identity.
func TestBlockedHostCannotEnroll(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	var host wire.HostResponse
	h.adminPost(t, ts.URL+"/v1/hosts", wire.CreateHostRequest{
		NetworkID: h.netID.String(), Name: "to-block", OverlayAddr: "10.42.0.30",
		RoleID: h.roleID.String(),
	}, &host)

	var codeResp wire.EnrollmentCodeResponse
	h.adminPost(t, ts.URL+"/v1/hosts/"+host.ID+"/enrollment-code", nil, &codeResp)

	var blocked wire.BlockResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts/"+host.ID+"/block", nil, &blocked); code != http.StatusOK {
		t.Fatalf("block: %d", code)
	}
	if blocked.BlocklistEpoch == 0 {
		t.Error("block did not advance the blocklist epoch")
	}

	kp, _ := agent.GenerateKeypair(cert.Curve_CURVE25519)
	_, err := agent.NewClient(ts.URL).Enroll(ctx, codeResp.Code, kp, "e2e")
	if err == nil {
		t.Fatal("a blocked host enrolled successfully")
	}
}

// TestAdminRequiresToken confirms the admin surface is closed by default.
func TestAdminRequiresToken(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	resp, err := http.Post(ts.URL+"/v1/hosts", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated host creation = %d, want 401", resp.StatusCode)
	}
}

// stubNebula writes an executable standing in for the nebula binary, exiting
// with code and printing msg.
//
// The agent validates by running `nebula -test -config`, so a test about
// validation needs a binary to run. A real one rather than a stubbed
// ConfigValidator, because what these assert is the whole path: Applier decides
// to validate, writes a candidate file, executes something, and reads the
// verdict.
func stubNebula(t *testing.T, code int, msg string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nebula")
	body := "#!/bin/sh\nprintf '%s' '" + msg + "' >&2\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func badMaterial() agent.Material {
	return agent.Material{
		Config:      "pki:\n  ca: /nonexistent/ca.crt\n  cert: /nonexistent/host.crt\n",
		CABundle:    "not a certificate",
		Certificate: "also not a certificate",
		PrivateKey:  "nope",
	}
}

// TestApplyRejectsBadConfig proves the agent validates before touching the live
// generation. A config nebula rejects must never reach the running node.
func TestApplyRejectsBadConfig(t *testing.T) {
	dir := t.TempDir()
	applier := &agent.Applier{
		Layout:       agent.DefaultLayout(dir),
		Reloader:     agent.NoopReloader{},
		NebulaBinary: stubNebula(t, 1, "invalid pki.ca: open /nonexistent/ca.crt: no such file"),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := applier.Apply(context.Background(), badMaterial())
	if err == nil {
		t.Fatal("applied a configuration nebula rejected")
	}
	if !strings.Contains(err.Error(), "refusing to apply") {
		t.Errorf("error = %v, want a pre-apply validation failure", err)
	}
	// Nebula's own reason has to survive the trip, or an operator reads
	// "rejected" and has to reproduce by hand what the agent was already told.
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("nebula's reason was dropped: %v", err)
	}

	// Nothing may have been installed.
	if _, err := os.Stat(agent.DefaultLayout(dir).ConfigPath()); !os.IsNotExist(err) {
		t.Error("a rejected configuration was installed anyway")
	}
}

// TestApplyProceedsWhenNebulaAccepts is the other half, and it is what keeps
// the test above honest: a validator that refused everything would pass it.
func TestApplyProceedsWhenNebulaAccepts(t *testing.T) {
	dir := t.TempDir()
	applier := &agent.Applier{
		Layout:       agent.DefaultLayout(dir),
		Reloader:     agent.NoopReloader{},
		NebulaBinary: stubNebula(t, 0, ""),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := applier.Apply(context.Background(), badMaterial()); err != nil {
		t.Fatalf("nebula accepted the configuration and the agent refused it anyway: %v", err)
	}
	if _, err := os.Stat(agent.DefaultLayout(dir).ConfigPath()); err != nil {
		t.Errorf("an accepted configuration was not installed: %v", err)
	}
}

// TestApplyProceedsWhenValidationCannotRun pins a deliberate choice, and one
// that looks wrong at a glance: an agent that cannot find nebula applies
// anyway.
//
// The alternative is worse. A host where nebula lives somewhere unexpected, or
// where it is not installed yet at first enrollment, would refuse every
// generation forever — never converging, while reporting a configuration
// problem that does not exist. Validation is not the only guard: a generation
// that breaks the host is reverted and quarantined after verification fails.
// It makes that rarer and cheaper; it is not what makes it survivable.
func TestApplyProceedsWhenValidationCannotRun(t *testing.T) {
	dir := t.TempDir()
	applier := &agent.Applier{
		Layout:       agent.DefaultLayout(dir),
		Reloader:     agent.NoopReloader{},
		NebulaBinary: filepath.Join(t.TempDir(), "no-nebula-here"),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := applier.Apply(context.Background(), badMaterial()); err != nil {
		t.Fatalf("an agent that cannot validate refused to apply: %v\n"+
			"That host can never converge, and the reason it reports is a "+
			"configuration problem it never actually observed.", err)
	}
	if _, err := os.Stat(agent.DefaultLayout(dir).ConfigPath()); err != nil {
		t.Errorf("nothing was installed: %v", err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
