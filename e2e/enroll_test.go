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
	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/mesh"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/secrets"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/vault"
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

	// vault is this deployment's key store. Every private key the control plane
	// holds is sealed in it — there is no file path any more.
	vault *vault.Vault

	// netSlug and networkID are this network's two immutable references: the
	// directory name on every machine, and the verifiable ID a joining machine
	// can check the control plane against.
	netSlug   string
	networkID string

	roleID uuid.UUID
	token  string
	caKey  string

	// membershipDevices remembers the device key each test host joined with, so a
	// test that needs to act AS that machine — claiming, re-reporting — can.
	membershipDevices map[string]*device.Identity

	// curve is this network's curve. P-256 for every network now — the choice
	// is gone, and migration 0021 refuses anything else — but it stays a field
	// because certificates, CA keys and mesh keypairs all have to be generated
	// with it, and reading it from one place is what stops a test hardcoding a
	// curve its network does not use.
	curve cert.Curve

	// unsafeNetworks is what this harness's CA permits gateways to route.
	// Empty unless a test asked, because that is what a real CA is created
	// with — the authority has to be granted deliberately.
	unsafeNetworks []netip.Prefix
}

func setup(t *testing.T) *harness {
	t.Helper()
	return setupCurve(t, cert.Curve_P256)
}

// setupRoutable is setup on a network whose CA permits routing the given
// prefixes.
//
// A separate constructor rather than a flag on setup, because it is the
// unusual case and should read as one: a CA that permits external routes has
// been granted authority no ordinary network's CA has.
func setupRoutable(t *testing.T, prefixes ...string) *harness {
	t.Helper()
	var ps []netip.Prefix
	for _, p := range prefixes {
		ps = append(ps, netip.MustParsePrefix(p))
	}
	return setupWith(t, cert.Curve_P256, ps)
}

// setupCurve is setup on a network of the given curve.
//
// Only P-256 is valid now. The parameter survives so the curve reaches every
// generator through the harness rather than being written out at each call
// site — the shape that let bootstrap default to P256 while every agent
// defaulted to CURVE25519 without either noticing.
func setupCurve(t *testing.T, curve cert.Curve) *harness {
	return setupWith(t, curve, nil)
}

func setupWith(t *testing.T, curve cert.Curve, unsafe []netip.Prefix) *harness {
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

	h := &harness{t: t, store: st, curve: curve, unsafeNetworks: unsafe, membershipDevices: map[string]*device.Identity{}}

	// The vault, exactly as `orbitd bootstrap` and `orbitd serve` build it.
	// There is no other key path: every private key this control plane holds is
	// sealed in Postgres under the KEK.
	//
	// Init once per database — the KEK is deployment-wide — so every harness
	// after the first opens the existing one.
	t.Setenv("ORBIT_KEK_PASSPHRASE", "e2e-deployment-passphrase")
	if h.vault, err = vault.Open(ctx, st); err != nil {
		if !errors.Is(err, store.ErrNoKEK) {
			t.Fatalf("open the key vault: %v", err)
		}
		if h.vault, err = vault.Init(ctx, st); err != nil {
			t.Fatalf("initialise the key vault: %v", err)
		}
	}

	h.bootstrap(t)
	return h
}

// bootstrap mirrors what `orbitd bootstrap` does, in-process. Each call creates
// its own network so tests never collide.
func (h *harness) bootstrap(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	caPub, caPriv, err := ca.GenerateCAKey(h.curve)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caKeyPEM := cert.MarshalSigningPrivateKeyToPEM(h.curve, caPriv)

	signer := ca.NewMemorySigner(h.curve, caPub, caPriv)
	now := time.Now()
	caCert, err := ca.CreateCA(ctx, signer, ca.CAParams{
		Name:     "e2e-ca",
		Networks: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		// Empty for every test but the route ones, which is the real default:
		// a CA permits no external routes unless somebody said so.
		UnsafeNetworks: h.unsafeNetworks,
		Groups:         []string{"default"},
		NotBefore:      now.Add(-time.Minute),
		NotAfter:       now.Add(90 * 24 * time.Hour),
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

	identityPub, identityPriv, err := ca.GenerateNetworkIdentity()
	if err != nil {
		t.Fatalf("generate network identity: %v", err)
	}

	err = h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		identityRef, err := h.vault.PutTx(ctx, tx, secrets.KindNetworkIdentity, nil,
			ca.MarshalNetworkIdentityPEM(identityPriv))
		if err != nil {
			return err
		}
		net := store.Network{
			Name:              h.netName,
			CIDRs:             []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
			CertVer:           int16(cert.Version2),
			Curve:             h.curve.String(),
			CertTTL:           24 * time.Hour,
			IdentityPublicKey: identityPub,
			IdentitySignerRef: identityRef,
		}
		if err := tx.CreateNetwork(ctx, &net); err != nil {
			return err
		}
		caRef, err := h.vault.PutTx(ctx, tx, secrets.KindCASigning, &net.ID, caKeyPEM)
		if err != nil {
			return err
		}
		h.netID = net.ID
		h.netSlug = net.Slug
		h.networkID = net.NetworkID

		caRow := store.CA{
			NetworkID: net.ID, Name: "e2e-ca", Fingerprint: fingerprint,
			CertPEM: string(caPEM), SignerRef: caRef,
			Curve:     h.curve.String(),
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

		_, err = tx.CreateAPIToken(ctx, "e2e", tokenHash, []string{"*"}, nil)
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

	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      nebulaPort,
	})

	srv := api.New(h.store, svc, api.Config{
		Agent:               &api.AgentListener{NetworkID: h.netID},
		SignerFactory:       h.vault.SignerFactory(),
		SealNetworkIdentity: h.sealNetworkIdentity,
		SealCAKey:           h.sealCAKey,
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

	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      nebulaPort,
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

	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      nebulaPort,
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

	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      nebulaPort,
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
		// A test asserting on an error MESSAGE gets one, and only then: out is
		// otherwise a success type, and filling it from an error body would hand
		// the caller a zero value that looks like a decoded response.
		if e, ok := out.(*wire.Error); ok {
			_ = jsonUnmarshal(raw, e)
		}
	}
	return resp.StatusCode
}

// freeUDPPort returns a UDP port nothing else in this run will use.
//
// It hands out ports from a private range and NEVER REPEATS ONE within a run,
// which is the part that matters. Asking the kernel for :0 does not do that: the
// probe socket is closed before this function returns, so the very next call can
// legitimately be handed the same port back — and a single test boots several
// nebulas. That is the collision, and it is not rare, it is just quiet: whichever
// nebula binds second fails with "address already in use" on a port the test was
// told was free.
//
// Three things make a candidate safe, and all three are needed:
//
//   - handedOut, so this process never issues a port twice. The dedup, not the
//     probe, is what fixes the common case.
//   - a range BELOW the ephemeral range (Linux 32768-60999, macOS 49152-65535),
//     so the kernel will not hand the same port to some unrelated outbound
//     connection between this probe and nebula's bind. The failing port in the
//     original report, 49213, was squarely inside macOS's ephemeral range.
//   - a PID-derived starting offset, so `go test ./...` running several package
//     binaries at once does not have them all walking the range from the same
//     place.
//
// The probe binds the DUAL-STACK wildcard, matching what nebula does (the
// rendered config sets listen.host to "::"). The old probe bound 127.0.0.1,
// which cannot see a conflict on any other address — so it could call a port
// free that nebula then failed to bind.
//
// A residual window remains between the probe closing and nebula binding, and it
// cannot be removed: nebula has to bind the port itself, so the probe must let
// go first. Holding the socket open until the caller "released" it would buy
// nothing the dedup does not already buy. What is left is a port outside the
// range the kernel allocates from, that no other test in this run will pick.
const (
	portLo = 20000
	portHi = 32000
)

var (
	portMu    sync.Mutex
	handedOut = map[int]bool{}
	nextPort  int
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	portMu.Lock()
	defer portMu.Unlock()

	if nextPort == 0 {
		// Deterministic rather than random, so a failing run can be reproduced
		// from its pid, and spread so concurrent package binaries do not
		// contend for the same first candidates.
		nextPort = portLo + (os.Getpid()*64)%(portHi-portLo)
	}

	for range portHi - portLo {
		p := nextPort
		nextPort++
		if nextPort >= portHi {
			nextPort = portLo
		}
		if handedOut[p] {
			continue
		}
		c, err := net.ListenPacket("udp", fmt.Sprintf(":%d", p))
		if err != nil {
			continue // in use by something outside this process
		}
		c.Close()
		handedOut[p] = true
		return p
	}
	t.Fatalf("no free UDP port in %d-%d after trying every one", portLo, portHi)
	return 0
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

// rerender fetches freshly-rendered material for a membership.
//
// Enrolment again rather than a peek at the database, because the point is
// usually to check what a MACHINE would actually receive — including the
// signature and the sections the render decides on. A second enrollment is what
// a renewal does anyway.
func (h *harness) rerender(t *testing.T, ts *httptest.Server, host *enrolledHost) wire.EnrollResponse {
	t.Helper()

	var code wire.EnrollmentCodeResponse
	if c := h.adminPost(t, ts.URL+"/v1/memberships/"+host.id+"/enrollment-code", nil, &code); c != http.StatusCreated {
		t.Fatalf("enrollment code for %s: status %d", host.name, c)
	}
	kp, err := agent.GenerateKeypair(h.curve)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := agent.NewClient(ts.URL).Enroll(context.Background(), code.Code, kp, "e2e")
	if err != nil {
		t.Fatalf("re-enroll %s: %v", host.name, err)
	}
	return *resp
}

// createAndEnroll runs the full operator-then-agent flow.
func (h *harness) createAndEnroll(t *testing.T, ts *httptest.Server, name, addr string, lighthouse, relay bool, staticAddrs []string) *enrolledHost {
	t.Helper()
	ctx := context.Background()

	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
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
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+host.ID+"/enrollment-code", nil, &codeResp); code != http.StatusCreated {
		t.Fatalf("enrollment code for %s: status %d", name, code)
	}
	if codeResp.Code == "" {
		t.Fatal("empty enrollment code")
	}

	// From here on this is exactly what `orbit agent enroll` does.
	kp, err := agent.GenerateKeypair(h.curve)
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
		MembershipID:   resp.MembershipID,
		ConfigEpoch:    resp.ConfigEpoch,
		BlocklistEpoch: resp.BlocklistEpoch,
		// Pinned exactly as `orbit agent enroll` pins it. Without this the
		// harness would build hosts that can never verify a generation, and
		// every test here would be exercising the unpinned path.
		NetworkKey: resp.NetworkKey,
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
	if strings.Contains(lhCfg, "memberships:\n        - ") {
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
	if err := c.Load(agent.DefaultLayout(dir).ConfigPath()); err != nil {
		return nil, fmt.Errorf("load config from %s: %w", dir, err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	ctrl, err := nebula.Main(c, false, "orbit-e2e", logger, overlay.NewUserDeviceFromConfig, nil)
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

	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "single-use", OverlayAddr: "10.42.0.20",
		RoleID: h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	var codeResp wire.EnrollmentCodeResponse
	h.adminPost(t, ts.URL+"/v1/memberships/"+host.ID+"/enrollment-code", nil, &codeResp)

	client := agent.NewClient(ts.URL)
	kp1, _ := agent.GenerateKeypair(cert.Curve_P256)
	if _, err := client.Enroll(ctx, codeResp.Code, kp1, "e2e"); err != nil {
		t.Fatalf("first enrollment failed: %v", err)
	}

	kp2, _ := agent.GenerateKeypair(cert.Curve_P256)
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

	var host wire.MembershipResponse
	h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "to-block", OverlayAddr: "10.42.0.30",
		RoleID: h.roleID.String(),
	}, &host)

	var codeResp wire.EnrollmentCodeResponse
	h.adminPost(t, ts.URL+"/v1/memberships/"+host.ID+"/enrollment-code", nil, &codeResp)

	var blocked wire.BlockResponse
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+host.ID+"/block", nil, &blocked); code != http.StatusOK {
		t.Fatalf("block: %d", code)
	}
	if blocked.BlocklistEpoch == 0 {
		t.Error("block did not advance the blocklist epoch")
	}

	kp, _ := agent.GenerateKeypair(cert.Curve_P256)
	_, err := agent.NewClient(ts.URL).Enroll(ctx, codeResp.Code, kp, "e2e")
	if err == nil {
		t.Fatal("a blocked host enrolled successfully")
	}
}

// TestAdminRequiresToken confirms the admin surface is closed by default.
func TestAdminRequiresToken(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	// A route that MUTATES, so a missing token cannot be mistaken for a
	// harmless read being refused. Reserving is what admits a machine to the
	// network now, which makes it the one worth proving is closed.
	resp, err := http.Post(ts.URL+"/v1/networks/"+h.netID.String()+"/reservations",
		"application/json", strings.NewReader(`{"name":"unauthenticated"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated reservation = %d, want 401", resp.StatusCode)
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

// membershipSpec is what a test wants a membership to be.
//
// It carries the same fields POST /v1/memberships took, because the tests that use it
// want the same outcome: a membership that exists, has an address, and has never
// held a certificate. What changed is how it gets there — see createHost.
type membershipSpec struct {
	NetworkID    string
	Name         string
	OverlayAddr  string
	RoleID       string
	IsLighthouse bool
	IsRelay      bool
	// StaticAddrs are the machine's PUBLIC addresses, with ports, in the form
	// nebula renders. The helper splits them: the host part becomes the device's
	// public address and the port is left to the membership, which is where
	// migration 0019 put each half.
	StaticAddrs []string
	Tags        []string

	// advertisePort is derived from StaticAddrs by createHost, not set by a
	// caller.
	advertisePort int
}

// createHost produces a membership the way the product now does it: an operator
// reserves a place, and a machine takes it.
//
// This replaced a single POST /v1/memberships, and the reason the replacement is three
// calls rather than one is the invariant it buys. There is no longer any moment
// at which a membership exists without a device — the row is created at
// redemption, already naming the machine that presented the code. That is what
// makes device_id NOT NULL reachable (docs/model.md §5, invariant 1).
//
// The end state is identical to what POST /v1/memberships produced: state `created`,
// an allocated or pinned address, no certificate. Tests that assert on that
// state did not need to change.
//
// Topology flags are PATCHed afterwards rather than reserved. A reservation
// carries name, address and role — the things an unattended machine must have
// decided for it — and a lighthouse is set up by an operator who is present.
// The signature mirrors adminPost — spec in, response out, status returned —
// so the call sites that used to POST /v1/memberships read the same as they did.
func (h *harness) createHost(t *testing.T, baseURL string, spec membershipSpec, out *wire.MembershipResponse) int {
	t.Helper()
	ctx := context.Background()

	var code wire.EnrollmentCodeResponse
	networkRef := spec.NetworkID
	if networkRef == "" {
		networkRef = h.netID.String()
	}
	if status := h.adminPost(t, baseURL+"/v1/networks/"+networkRef+"/reservations",
		wire.ReserveRequest{
			Name:        spec.Name,
			OverlayAddr: spec.OverlayAddr,
			RoleID:      spec.RoleID,
		}, &code); status != http.StatusCreated {
		return status
	}

	// A fresh device per host. Real machines each have their own, and sharing
	// one here would make every test host the same device — which would hide
	// exactly the bugs the device model exists to prevent.
	id, err := device.Generate()
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	client := agent.NewClient(baseURL)
	joined, err := client.JoinWithCode(ctx, id, networkRef, spec.Name, "", code.Code, time.Now())
	if err != nil {
		t.Fatalf("join %s: %v", spec.Name, err)
	}

	var host wire.MembershipResponse
	if status := h.adminReq(t, http.MethodGet,
		baseURL+"/v1/memberships/"+joined.MembershipID, nil, &host); status != http.StatusOK {
		t.Fatalf("read %s after join: status %d", spec.Name, status)
	}

	// The addresses go on the DEVICE, before the topology PATCH — a membership
	// cannot become a lighthouse while its machine has nowhere to be reached.
	if len(spec.StaticAddrs) > 0 {
		hosts, ports := splitHostPorts(t, spec.StaticAddrs)
		var dev wire.DeviceResponse
		if status := h.adminReq(t, http.MethodPatch,
			baseURL+"/v1/devices/"+joined.DeviceID+"/addrs",
			wire.SetDeviceAddrsRequest{PublicAddrs: hosts}, &dev); status != http.StatusOK {
			t.Fatalf("set public addrs on %s: status %d", spec.Name, status)
		}
		// A port that differs from the bound one is what advertise_port is for.
		if len(ports) > 0 && ports[0] != 0 {
			spec.advertisePort = ports[0]
		}
	}

	if spec.IsLighthouse || spec.IsRelay || len(spec.Tags) > 0 || spec.advertisePort != 0 {
		req := wire.UpdateHostRequest{
			IsLighthouse: &spec.IsLighthouse,
			IsRelay:      &spec.IsRelay,
		}
		if spec.advertisePort != 0 {
			req.AdvertisePort = &spec.advertisePort
		}
		if len(spec.Tags) > 0 {
			req.Tags = &spec.Tags
		}
		if status := h.adminReq(t, http.MethodPatch,
			baseURL+"/v1/memberships/"+host.ID, req, &host); status != http.StatusOK {
			t.Fatalf("set topology on %s: status %d", spec.Name, status)
		}
	}

	// The device that joined keeps its key: `orbit agent enroll` with a code
	// still works for a membership created this way, which is what lets the
	// existing enrollment tests go on testing enrollment.
	h.membershipDevices[host.ID] = id
	if out != nil {
		*out = host
	}
	return http.StatusCreated
}

// testDeviceKey is a control plane's own device identity for a test.
//
// The control plane is a machine on its own network like any other, so its
// membership names a device — there is no "system" exemption, and adding one
// would mean a nullable column and a nil branch on every read for exactly one
// row. Each test gets its own, because each spins up its own control plane.
func testDeviceKey(t *testing.T) []byte {
	t.Helper()
	id, err := device.Generate()
	if err != nil {
		t.Fatalf("control plane device key: %v", err)
	}
	return id.PublicKey()
}

// sealNetworkIdentity is what POST /v1/networks uses to store the identity key
// it generates. Wired the way orbitd wires it, so the tests exercise the real
// path rather than a shortcut around it.
func (h *harness) sealNetworkIdentity(ctx context.Context, tx *store.Tx, plaintext []byte) (string, error) {
	return h.vault.PutTx(ctx, tx, secrets.KindNetworkIdentity, nil, plaintext)
}

// stubSignerRef is a well-formed vault reference for CA rows that are staged
// directly in the database and never asked to sign.
//
// A real reference rather than a placeholder string: `file://` is no longer a
// scheme anything accepts, and a row carrying one would be testing that the
// resolver rejects garbage rather than whatever the case is actually about.
const stubSignerRef = "db://00000000-0000-0000-0000-000000000001"

// sealCAKey is what POST /v1/cas uses to store the signing key it generates.
func (h *harness) sealCAKey(ctx context.Context, tx *store.Tx, networkID uuid.UUID, plaintext []byte) (string, error) {
	return h.vault.PutTx(ctx, tx, secrets.KindCASigning, &networkID, plaintext)
}

// splitHostPorts separates `host:port` entries into the two nouns that own them.
//
// The host is the machine's public address (a device fact) and the port is which
// nebula instance answers there (a membership fact). Tests still write the
// joined form because that is what a reader recognises from nebula's
// static_host_map; this is where it comes apart.
func splitHostPorts(t *testing.T, entries []string) (hosts []string, ports []int) {
	t.Helper()
	for _, e := range entries {
		host, port, err := net.SplitHostPort(e)
		if err != nil {
			// No port: the whole thing is a host.
			hosts = append(hosts, e)
			ports = append(ports, 0)
			continue
		}
		n, err := strconv.Atoi(port)
		if err != nil {
			t.Fatalf("static addr %q has a non-numeric port", e)
		}
		hosts = append(hosts, host)
		ports = append(ports, n)
	}
	return hosts, ports
}
