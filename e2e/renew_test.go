package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"

	"github.com/griffithind/orbit/internal/agent"
)

// configReloader reloads an in-process nebula the same way SIGHUP does.
//
// nebula's SIGHUP handler calls exactly this (config.C CatchHUP -> ReloadConfig),
// so a renewal that survives here survives a real SIGHUP. Using it means the
// test exercises nebula's actual hot-reload path rather than restarting the
// node and calling that a successful renewal.
type configReloader struct {
	c    *config.C
	name string
}

func (r configReloader) Reload(context.Context) error {
	r.c.ReloadConfig()
	return nil
}
func (r configReloader) Describe() string { return "in-process reload of " + r.name }

// TestRenewalKeepsTunnelAlive is the phase-3 acceptance test.
//
// It establishes a real tunnel, rotates the client's certificate AND its
// keypair, reloads nebula the way SIGHUP does, and confirms the tunnel still
// carries traffic afterwards. This is the property the whole renewal design
// exists to deliver: rotation is routine and invisible.
func TestRenewalKeepsTunnelAlive(t *testing.T) {
	h := setup(t)

	lhPort := freeUDPPort(t)
	clientPort := freeUDPPort(t)
	lhServer := h.serve(t, lhPort)
	clientServer := h.serve(t, clientPort)

	lh := h.createAndEnroll(t, lhServer, "lh-renew", "10.42.1.1", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})
	client := h.createAndEnroll(t, clientServer, "client-renew", "10.42.1.7", false, false, nil)

	lhNode, err := bootNebula(t, lh.dir, lh.addr)
	if err != nil {
		t.Fatalf("start lighthouse: %v", err)
	}
	clientNode, err := bootNebula(t, client.dir, client.addr)
	if err != nil {
		t.Fatalf("start client: %v", err)
	}

	// Baseline connectivity.
	const port = 9998
	stop := serveEcho(t, lhNode, port, "before")
	assertReachable(t, clientNode, lh.addr, port, "before")
	stop()

	certBefore := readFile(t, filepath.Join(client.dir, "orbit-host.crt"))
	keyBefore := readFile(t, filepath.Join(client.dir, "orbit-host.key"))

	// Renew, through the real agent loop: new keypair, new certificate, and an
	// in-process reload standing in for SIGHUP.
	st, err := agent.ReadState(client.dir)
	if err != nil {
		t.Fatalf("read agent state: %v", err)
	}
	// Serve the agent API on the lighthouse's OVERLAY address and reach it
	// through the client's own nebula stack. Identity therefore comes from the
	// verified source address, exactly as the design intends; nothing here
	// trusts a header or a token.
	overlayURL := h.serveOverlay(t, lhNode, 8443, clientPort)
	overlayClient := agent.NewClient(overlayURL)
	overlayClient.HTTP = overlayHTTPClient(clientNode)

	layout := agent.DefaultLayout(client.dir)
	loop := &agent.Loop{
		Client: overlayClient,
		Applier: &agent.Applier{
			Layout:   layout,
			Reloader: configReloader{c: clientNode.cfg, name: "client"},
			Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		Policy: agent.DefaultRenewalPolicy(),
		Layout: layout,
		Curve:  cert.Curve_CURVE25519,
		State:  st,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := loop.RenewNow(context.Background()); err != nil {
		t.Fatalf("renew: %v", err)
	}

	certAfter := readFile(t, filepath.Join(client.dir, "orbit-host.crt"))
	keyAfter := readFile(t, filepath.Join(client.dir, "orbit-host.key"))

	if certAfter == certBefore {
		t.Fatal("renewal did not install a new certificate")
	}
	if keyAfter == keyBefore {
		t.Error("renewal reused the private key; the default should rotate it")
	}

	// The new certificate must keep the same overlay address, or nebula would
	// have rejected the reload outright.
	nbBefore, naBefore, _ := agent.CertificateWindow(certBefore)
	_, naAfter, _ := agent.CertificateWindow(certAfter)
	// Nebula encodes validity to second granularity, so a renewal issued in the
	// same second as the original legitimately shares its NotAfter. The
	// meaningful assertions are that the certificate changed and that the window
	// did not go backwards.
	if naAfter.Before(naBefore) {
		t.Errorf("renewed certificate expires earlier than the old one: %s then %s", naBefore, naAfter)
	}
	mode, err := agent.ModeFor(certBefore, certAfter)
	if err != nil {
		t.Fatalf("ModeFor: %v", err)
	}
	if mode != agent.ModeReload {
		t.Errorf("renewal required %v; a routine renewal must be hot-loadable", mode)
	}
	_ = nbBefore

	// The tunnel must still carry traffic on the rotated identity.
	stop2 := serveEcho(t, lhNode, port+1, "after")
	assertReachable(t, clientNode, lh.addr, port+1, "after")
	stop2()

	t.Log("certificate and keypair rotated on a live tunnel with no loss of connectivity")
}

// TestRollbackRestoresPreviousGeneration proves the rollback path works, which
// is what makes post-apply verification meaningful. Without a working rollback,
// a verifier that fails just leaves the host broken with an extra log line.
func TestRollbackRestoresPreviousGeneration(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "rollback", "10.42.2.5", false, false, nil)

	certBefore := readFile(t, filepath.Join(host.dir, "orbit-host.crt"))
	configBefore := readFile(t, filepath.Join(host.dir, "config.d", agent.FragmentName))

	// Renew with a verifier that always fails, standing in for "the host lost
	// contact with the control plane after applying".
	st, err := agent.ReadState(host.dir)
	if err != nil {
		t.Fatal(err)
	}
	layout := agent.DefaultLayout(host.dir)

	var reloads int
	loop := &agent.Loop{
		Client: xffClient(t, ts.URL, host.addr),
		Applier: &agent.Applier{
			Layout: layout,
			Reloader: agent.ReloaderFunc{Name: "count", Fn: func() error {
				reloads++
				return nil
			}},
			Verifier: agent.VerifierFunc{
				Name: "always-fails",
				Fn:   func(context.Context) error { return fmt.Errorf("simulated connectivity loss") },
			},
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		Policy: agent.DefaultRenewalPolicy(),
		Layout: layout,
		Curve:  cert.Curve_CURVE25519,
		State:  st,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err = loop.RenewNow(context.Background())
	if err == nil {
		t.Fatal("renewal reported success despite failing verification")
	}

	certAfter := readFile(t, filepath.Join(host.dir, "orbit-host.crt"))
	configAfter := readFile(t, filepath.Join(host.dir, "config.d", agent.FragmentName))

	if certAfter != certBefore {
		t.Error("certificate was not rolled back")
	}
	if configAfter != configBefore {
		t.Error("configuration was not rolled back")
	}
	// Once to apply, once to restore.
	if reloads != 2 {
		t.Errorf("reload count = %d, want 2 (apply then rollback)", reloads)
	}
}

// TestRenewReuseKeyKeepsPrivateKey covers the hardware-backed path, where the
// private key cannot be regenerated and only a new certificate is wanted.
func TestRenewReuseKeyKeepsPrivateKey(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "reuse-key", "10.42.2.9", false, false, nil)

	certBefore := readFile(t, filepath.Join(host.dir, "orbit-host.crt"))
	keyBefore := readFile(t, filepath.Join(host.dir, "orbit-host.key"))

	st, _ := agent.ReadState(host.dir)
	layout := agent.DefaultLayout(host.dir)
	loop := &agent.Loop{
		Client: xffClient(t, ts.URL, host.addr),
		Applier: &agent.Applier{
			Layout: layout, Reloader: agent.NoopReloader{},
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		Policy:   agent.DefaultRenewalPolicy(),
		Layout:   layout,
		Curve:    cert.Curve_CURVE25519,
		ReuseKey: true,
		State:    st,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// Wait past a second boundary. Nebula encodes validity to second
	// granularity, so reusing the key inside the same second reproduces a
	// byte-identical certificate, which InsertCertificate correctly treats as
	// idempotent. Real renewals happen hours apart.
	time.Sleep(1100 * time.Millisecond)

	if err := loop.RenewNow(context.Background()); err != nil {
		t.Fatalf("renew with reuse-key: %v", err)
	}

	if got := readFile(t, filepath.Join(host.dir, "orbit-host.key")); got != keyBefore {
		t.Error("reuse-key renewal replaced the private key")
	}
	if got := readFile(t, filepath.Join(host.dir, "orbit-host.crt")); got == certBefore {
		t.Error("reuse-key renewal did not issue a new certificate")
	}
}

// TestAddressChangeRefusedWithoutRestarter covers the silent-failure guard.
// Nebula cannot hot-load a certificate whose networks changed; installing one
// anyway leaves the host running the old certificate until it expires, with
// only a reload error in nebula's log to explain it.
func TestAddressChangeRefusedWithoutRestarter(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "readdress", "10.42.3.5", false, false, nil)
	certBefore := readFile(t, filepath.Join(host.dir, "orbit-host.crt"))

	// Fabricate a generation carrying a certificate for a different address.
	other := h.createAndEnroll(t, ts, "readdress-other", "10.42.3.6", false, false, nil)
	otherCert := readFile(t, filepath.Join(other.dir, "orbit-host.crt"))

	layout := agent.DefaultLayout(host.dir)
	applier := &agent.Applier{
		Layout: layout, Reloader: agent.NoopReloader{},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := applier.Apply(context.Background(), agent.Material{
		Config:      readFile(t, filepath.Join(host.dir, "config.d", agent.FragmentName)),
		CABundle:    readFile(t, filepath.Join(host.dir, "orbit-ca.crt")),
		Certificate: otherCert,
		PrivateKey:  readFile(t, filepath.Join(other.dir, "orbit-host.key")),
	})
	if err == nil {
		t.Fatal("applied an address change with no restarter configured")
	}

	if got := readFile(t, filepath.Join(host.dir, "orbit-host.crt")); got != certBefore {
		t.Error("the refused generation was installed anyway")
	}
}

//------------------------------------------------------------------------------
// helpers
//------------------------------------------------------------------------------

// serveEcho starts a listener on the overlay and returns a stop function.
func serveEcho(t *testing.T, n *nebulaNode, port int, payload string) func() {
	t.Helper()
	ln, err := n.svc.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("listen on overlay: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte(payload))
			conn.Close()
		}
	}()

	return func() {
		_ = ln.Close()
		wg.Wait()
	}
}

func assertReachable(t *testing.T, from *nebulaNode, to interface{ String() string }, port int, want string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var (
		conn net.Conn
		err  error
	)
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = from.svc.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", to.String(), port))
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("%s: could not reach %s:%d over the overlay: %v", want, to.String(), port, err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("%s: read over tunnel: %v", want, err)
	}
	if got := string(buf[:n]); got != want {
		t.Fatalf("%s: read %q over the tunnel, want %q", want, got, want)
	}
}

// xffClient asserts an overlay source address via X-Forwarded-For.
//
// A TEST-ONLY shim, for cases that exercise apply and rollback logic without
// the cost of booting two nebula nodes. It works only because the harness
// enables TrustForwardedFor. In production that flag must stay off on any
// directly-exposed listener: a client that can set its own header can claim any
// identity. TestRenewalKeepsTunnelAlive uses the real overlay path instead.
func xffClient(t *testing.T, baseURL string, addr netip.Addr) *agent.Client {
	t.Helper()
	c := agent.NewClient(baseURL)
	c.HTTP = &http.Client{
		Timeout:   30 * time.Second,
		Transport: xffTransport{addr: addr.String(), base: http.DefaultTransport},
	}
	return c
}

type xffTransport struct {
	addr string
	base http.RoundTripper
}

func (x xffTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Forwarded-For", x.addr)
	return x.base.RoundTrip(r)
}
