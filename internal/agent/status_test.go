package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// serveForTest starts a status server on a temporary socket and returns its
// path, shut down on cleanup.
func serveForTest(t *testing.T, rep Report) string {
	t.Helper()
	// t.TempDir() on macOS is under /var/folders/... and long enough to exceed
	// the ~104-byte sun_path limit once a socket name is appended, which fails
	// as "invalid argument" and looks like a bug in the listener.
	dir, err := os.MkdirTemp("", "orbit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := SocketPath(dir)
	srv := &StatusServer{
		Path:   path,
		Report: func(context.Context) Report { return rep },
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("the status server did not shut down")
		}
	})

	// Serve binds asynchronously; wait for the socket rather than sleeping.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
			return path
		}
		if time.Now().After(deadline) {
			t.Fatal("the status socket never came up")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStatusRoundTrip(t *testing.T) {
	want := Report{
		Version: "9.9.9",
		Root:    "/var/lib/orbit",
		PID:     4242,
		Networks: []NetworkStatus{{
			Network:     "prod",
			Ready:       true,
			HostID:      "abc",
			ConfigEpoch: 41,
			Nebula:      NebulaStatus{Known: true, Running: true, Instance: "gen-1"},
		}},
	}
	path := serveForTest(t, want)

	got, err := FetchStatus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || got.PID != want.PID {
		t.Errorf("header did not survive: %+v", got)
	}
	if len(got.Networks) != 1 {
		t.Fatalf("got %d networks, want 1", len(got.Networks))
	}
	n := got.Networks[0]
	if n.Network != "prod" || n.ConfigEpoch != 41 || !n.Nebula.Running {
		t.Errorf("network did not survive: %+v", n)
	}
}

// TestSocketIsNotReadableByOthers. The report names every network this host has
// joined, its control plane and its certificate. chmod has to happen after
// Listen — the socket does not exist before it — and a umask of 0022 would
// otherwise leave this world-readable.
func TestSocketIsNotReadableByOthers(t *testing.T) {
	path := serveForTest(t, Report{})

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != SocketMode {
		t.Errorf("socket mode is %04o, want %04o", perm, SocketMode)
	}
}

// TestALiveSocketIsNotStolen is the regression that matters most here.
//
// Clearing the path unconditionally would let a second agent bind over a
// running first one: both processes look healthy, status requests go to
// whichever won, and the loser keeps serving networks nobody can see. Only a
// refused connection proves the path is a leftover.
func TestALiveSocketIsNotStolen(t *testing.T) {
	path := serveForTest(t, Report{})

	ln, err := listenUnix(path)
	if err == nil {
		_ = ln.Close()
		t.Fatal("listenUnix bound over a socket another agent was serving")
	}

	// And the live one still answers, which is the property the refusal exists
	// to protect: a failed second bind must not have unlinked the first.
	if _, err := FetchStatus(context.Background(), path); err != nil {
		t.Errorf("the original socket stopped working after a second bind attempt: %v", err)
	}
}

func TestStaleSocketIsCleared(t *testing.T) {
	dir, err := os.MkdirTemp("", "orbit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := SocketPath(dir)

	// A socket file with nothing listening: what a killed agent leaves behind.
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	// Closing a unix listener unlinks it, so put the file back to model the
	// case that actually strands operators — a process killed with SIGKILL.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ln2, err := listenUnix(path)
	if err != nil {
		t.Fatalf("a stale socket was not cleared: %v", err)
	}
	_ = ln2.Close()
}

func TestFetchStatusWithNoAgent(t *testing.T) {
	dir, err := os.MkdirTemp("", "orbit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	_, err = FetchStatus(context.Background(), SocketPath(dir))
	if !errors.Is(err, ErrNoAgent) {
		t.Errorf("got %v, want ErrNoAgent — the caller cannot say "+
			"'the agent is not running' without it", err)
	}
}

func TestReadCertStatus(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := notBefore.Add(48 * time.Hour)

	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      "web-01",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.7/32")},
		Groups:    []string{"env-prod", "tier-app"},
		IsCA:      true,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		PublicKey: pub,
		Curve:     cert.Curve_CURVE25519,
	}
	c, err := tbs.Sign(nil, cert.Curve_CURVE25519, priv)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := c.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "host.crt")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}

	cs, err := ReadCertStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Name != "web-01" {
		t.Errorf("name = %q", cs.Name)
	}
	if len(cs.Groups) != 2 || cs.Groups[0] != "env-prod" {
		t.Errorf("groups = %v", cs.Groups)
	}
	if len(cs.Networks) != 1 || cs.Networks[0] != "10.42.0.7/32" {
		t.Errorf("networks = %v", cs.Networks)
	}
	if cs.Fingerprint == "" {
		t.Error("no fingerprint")
	}
	if cs.Expired(time.Now()) {
		t.Error("a certificate valid for another 47 hours reported as expired")
	}
	if !cs.Expired(notAfter.Add(time.Second)) {
		t.Error("an expired certificate reported as valid")
	}
}

// TestMissingCertificateIsNotAnError, from the caller's point of view: a host
// that has enrolled but not yet been issued one must still produce a status,
// because "no certificate" is the diagnosis rather than a reason to fail.
func TestMissingCertificateIsNotAnError(t *testing.T) {
	_, err := ReadCertStatus(filepath.Join(t.TempDir(), "absent.crt"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("got %v, want a not-exist error the caller can recognise", err)
	}
}
