package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/policy"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The claim a compiled policy makes is that a rule keyed on a peer's ADDRESS is
// bound to that peer's signed certificate exactly as strongly as one keyed on
// its groups, because Firewall.Drop validates the claimed source address
// against the certificate's networks before any rule is consulted. Everything
// in the compiler follows from that, so it is worth proving against real
// nebula rather than against a struct.
//
// These tests run the whole path: the control plane compiles, renders and
// serves; the real agent applies; real nebula boots from the file and moves
// real packets.

// servePolicy is harness.serve with the policy compiler wired in.
//
// The PolicySource closure is what internal/store will provide in one method;
// building it here from ListHosts keeps the e2e honest about the shape without
// waiting on the schema.
func servePolicy(t *testing.T, h *harness, nebulaPort int, doc []byte) *httptest.Server {
	t.Helper()

	registry := ca.NewRegistry(ca.FileSignerFactory)
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		Paths:      nebulacfg.DefaultPaths(),
		ListenPort: nebulaPort,
		Policy: func(ctx context.Context, tx *store.Tx, networkID uuid.UUID) ([]byte, []policy.Membership, error) {
			page, err := tx.ListHosts(ctx, store.MembershipFilter{
				NetworkID: networkID, Limit: store.MembershipPageMax,
			})
			if err != nil {
				return nil, nil, err
			}
			fleet := make([]policy.Membership, 0, len(page.Memberships))
			for _, hh := range page.Memberships {
				fleet = append(fleet, policy.Membership{
					ID:    hh.ID.String(),
					Name:  hh.Name,
					Role:  hh.RoleName,
					Tags:  hh.Tags,
					Addrs: hh.Addrs,
				})
			}
			return doc, fleet, nil
		},
	})

	srv := api.New(h.store, svc, api.Config{
		NetworkKeyDir:      t.TempDir(),
		Agent:              &api.AgentListener{NetworkID: h.netID},
		SignerFactory:      ca.FileSignerFactory,
		DisableEnrollLimit: true,
		TrustForwardedFor:  true,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// createTagged creates a host carrying tags, without enrolling it. Every host a
// policy names has to exist before any of them enrols, or the first host's
// config is compiled against a fleet that is still being built.
func (h *harness) createTagged(t *testing.T, ts *httptest.Server, name, addr string, tags []string, lighthouse bool, staticAddrs []string) string {
	t.Helper()
	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID:    h.netID.String(),
		Name:         name,
		OverlayAddr:  addr,
		Tags:         tags,
		IsLighthouse: lighthouse,
		StaticAddrs:  staticAddrs,
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host %s: status %d", name, code)
	}
	return host.ID
}

// enrollExisting is the agent half of createAndEnroll for a host that already
// exists.
func (h *harness) enrollExisting(t *testing.T, ts *httptest.Server, membershipID, name, addr string) *enrolledHost {
	t.Helper()
	ctx := context.Background()

	var codeResp wire.EnrollmentCodeResponse
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+membershipID+"/enrollment-code", nil, &codeResp); code != http.StatusCreated {
		t.Fatalf("enrollment code for %s: status %d", name, code)
	}
	kp, err := agent.GenerateKeypair(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := agent.NewClient(ts.URL).Enroll(ctx, codeResp.Code, kp, "e2e")
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
	return &enrolledHost{name: name, addr: netip.MustParseAddr(addr), dir: dir, id: membershipID, respons: resp}
}

const twoTierPolicy = `{
  "version": 1,
  "allow": [
    {"src": ["tag:client"], "dst": ["tag:server"], "proto": "tcp", "ports": ["8080"],
     "note": "the only thing this network permits"}
  ]
}`

// TestPolicyCompilesAndNebulaAcceptsIt proves the compiled document survives
// the whole path and that nebula — not a test's idea of nebula — accepts it.
//
// It also pins the two decisions that are easiest to regress silently: the
// rules are keyed on addresses rather than groups, and authoritative mode drops
// the outbound allow-all so the compiled outbound half is not decoration.
func TestPolicyCompilesAndNebulaAcceptsIt(t *testing.T) {
	h := setup(t)
	// One listener per host: two nebula processes cannot share a UDP port, and
	// the port is baked into the rendered config.
	ts := servePolicy(t, h, freeUDPPort(t), []byte(twoTierPolicy))
	tsCli := servePolicy(t, h, freeUDPPort(t), []byte(twoTierPolicy))
	tsOther := servePolicy(t, h, freeUDPPort(t), []byte(twoTierPolicy))

	srvID := h.createTagged(t, ts, "pol-server", "10.42.20.2", []string{"server"}, false, nil)
	cliID := h.createTagged(t, ts, "pol-client", "10.42.20.3", []string{"client"}, false, nil)

	srv := h.enrollExisting(t, ts, srvID, "pol-server", "10.42.20.2")
	cli := h.enrollExisting(t, tsCli, cliID, "pol-client", "10.42.20.3")

	// The destination admits the source by address, and nothing else.
	srvCfg := srv.respons.Config
	if !strings.Contains(srvCfg, "10.42.20.3/32") {
		t.Errorf("the server's config does not admit the client's address:\n%s", srvCfg)
	}
	if strings.Contains(srvCfg, "group:") || strings.Contains(srvCfg, "groups:") {
		t.Errorf("a compiled rule reached the config as a group, which would put the "+
			"policy inside the signed certificate:\n%s", srvCfg)
	}

	// The source's half is real: an outbound rule, and no allow-all beside it.
	cliCfg := cli.respons.Config
	if !strings.Contains(cliCfg, "10.42.20.2/32") {
		t.Errorf("the client's config has no outbound rule to the server:\n%s", cliCfg)
	}
	if strings.Contains(cliCfg, "host: any") {
		t.Errorf("the outbound allow-all survived, which makes every compiled outbound "+
			"rule accomplish nothing:\n%s", cliCfg)
	}

	// And a host the policy never names gets nothing, which in authoritative
	// mode means it talks to nobody. That is the intended, visible failure.
	otherID := h.createTagged(t, ts, "pol-orphan", "10.42.20.9", []string{"unused"}, false, nil)
	other := h.enrollExisting(t, tsOther, otherID, "pol-orphan", "10.42.20.9")
	if strings.Contains(other.respons.Config, "10.42.20.2/32") {
		t.Errorf("a host outside the policy got rules for it:\n%s", other.respons.Config)
	}

	// Real nebula, from the file the agent actually wrote.
	for _, host := range []*enrolledHost{srv, cli, other} {
		if _, err := bootNebula(t, host.dir, host.addr); err != nil {
			t.Fatalf("nebula refused the compiled policy for %s: %v", host.name, err)
		}
	}
}

// TestPolicyEnforcesReachability is the one that cannot be faked: real packets,
// a real firewall table, and a port that is allowed sitting next to a port that
// is not.
func TestPolicyEnforcesReachability(t *testing.T) {
	h := setup(t)
	lhPort := freeUDPPort(t)
	ts := servePolicy(t, h, lhPort, []byte(twoTierPolicy))
	tsSrv := servePolicy(t, h, freeUDPPort(t), []byte(twoTierPolicy))
	tsCli := servePolicy(t, h, freeUDPPort(t), []byte(twoTierPolicy))

	// Every host exists before any of them enrols, so each one's config is
	// compiled against the same fleet.
	lhID := h.createTagged(t, ts, "pol-lh", "10.42.21.1", []string{"infra"}, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})
	srvID := h.createTagged(t, ts, "pol-srv", "10.42.21.2", []string{"server"}, false, nil)
	cliID := h.createTagged(t, ts, "pol-cli", "10.42.21.3", []string{"client"}, false, nil)

	lh := h.enrollExisting(t, ts, lhID, "pol-lh", "10.42.21.1")
	srv := h.enrollExisting(t, tsSrv, srvID, "pol-srv", "10.42.21.2")
	cli := h.enrollExisting(t, tsCli, cliID, "pol-cli", "10.42.21.3")

	// The lighthouse is named by no allowance and needs none: lighthouse and
	// handshake traffic is nebula's own, not tun-routed IP, so it never reaches
	// Firewall.Drop.
	if _, err := bootNebula(t, lh.dir, lh.addr); err != nil {
		t.Fatalf("boot lighthouse: %v", err)
	}
	srvNode, err := bootNebula(t, srv.dir, srv.addr)
	if err != nil {
		t.Fatalf("boot server: %v", err)
	}
	cliNode, err := bootNebula(t, cli.dir, cli.addr)
	if err != nil {
		t.Fatalf("boot client: %v", err)
	}

	// One listener on the allowed port and one on a port the policy does not
	// mention. Same host, same certificate, same tunnel: the only difference is
	// the compiled rule.
	listenAndEcho(t, srvNode, 8080)
	listenAndEcho(t, srvNode, 9090)

	// The allowed flow, retried while the tunnel establishes.
	var conn net.Conn
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err = cliNode.svc.DialContext(ctx, "tcp", "10.42.21.2:8080")
		cancel()
		if err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("the allowed flow never connected: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write on the allowed flow: %v", err)
	}
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("the allowed flow connected but carried no data: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo returned %q", buf)
	}
	_ = conn.Close()

	// The tunnel is up and the certificate is the same one. A flow the policy
	// does not name must still not connect — and it is refused twice, by the
	// client's own outbound rule and by the server's inbound table.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	bad, err := cliNode.svc.DialContext(ctx, "tcp", "10.42.21.2:9090")
	if err == nil {
		_ = bad.Close()
		t.Fatal("a port the policy never names accepted a connection over an established tunnel")
	}
	t.Logf("port 9090 refused over a live tunnel to the same certificate: %v", err)
}

// listenAndEcho serves an echo on one overlay port for the life of the test.
func listenAndEcho(t *testing.T, n *nebulaNode, port int) {
	t.Helper()
	ln, err := n.svc.Listen("tcp", fmt.Sprintf(":%d", port))
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
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
}
