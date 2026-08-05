package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// TestP256NetworkEndToEnd.
//
// `orbitd bootstrap` defaults to P-256, because it is the only curve on which a
// host key can live in a TPM or Secure Enclave — TPM 2.0 has no Curve25519 and
// Apple's Secure Enclave is P-256 only. A network's curve is permanent
// (cert/ca_pool.go refuses a leaf whose curve differs from its signer's, and
// nothing updates store.Network.Curve), so the default is unrecoverable if it
// is wrong.
//
// Until this test, nothing exercised it. Every e2e bootstrapped CURVE25519
// explicitly, so the path a new deployment actually takes was the one path with
// no coverage.
//
// This ends where TestEnrollmentEndToEnd ends — two real nebula nodes trading
// bytes — but over a P-256 Noise handshake (Noise_IX_P256_*), with certificates
// this control plane signed using ECDSA P-256 rather than Ed25519.
func TestP256NetworkEndToEnd(t *testing.T) {
	h := setupCurve(t, cert.Curve_P256)

	lhPort := freeUDPPort(t)
	clientPort := freeUDPPort(t)

	lhServer := h.serve(t, lhPort)
	clientServer := h.serve(t, clientPort)

	lh := h.createAndEnroll(t, lhServer, "lighthouse", "10.42.0.1", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})
	client := h.createAndEnroll(t, clientServer, "client", "10.42.0.7", false, false, nil)

	// Assert the curve on the wire, not just in the database. A network row
	// saying "P256" while the CA quietly signed Ed25519 would still produce a
	// working tunnel below, and would be exactly the silent failure the default
	// exists to prevent.
	for _, hst := range []*enrolledHost{lh, client} {
		for _, f := range []string{"ca.crt", "host.crt"} {
			pem, err := os.ReadFile(filepath.Join(hst.dir, f))
			if err != nil {
				t.Fatalf("%s: read %s: %v", hst.name, f, err)
			}
			c, _, err := cert.UnmarshalCertificateFromPEM(pem)
			if err != nil {
				t.Fatalf("%s: parse %s: %v", hst.name, f, err)
			}
			if c.Curve() != cert.Curve_P256 {
				t.Fatalf("%s: %s is on curve %v, want P256 — the network was "+
					"bootstrapped P256 but this certificate is not",
					hst.name, f, c.Curve())
			}
		}
	}

	lhSvc := startNebula(t, lh.dir)
	clientSvc := startNebula(t, client.dir)

	const port = 9998
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
		_, _ = conn.Write([]byte("orbit-p256"))
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
		t.Fatalf("client could not reach the lighthouse over a P-256 overlay: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read over tunnel: %v", err)
	}
	if got := string(buf[:n]); got != "orbit-p256" {
		t.Fatalf("read %q over the tunnel, want %q", got, "orbit-p256")
	}

	_ = ln.Close()
	wg.Wait()

	t.Log("P-256 tunnel established: ECDSA-signed certificates, Noise_IX_P256 handshake")
}
