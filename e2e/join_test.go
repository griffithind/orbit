package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/agent/generation"
	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The join path, end to end: a machine asks, an operator says yes, the machine
// collects its certificate.
//
// What this proves that the unit tests cannot is the property the whole design
// rests on — NO SECRET TRAVELS. Nowhere in this test is a credential minted,
// copied, or presented. The machine's only claim is a signature made with a key
// it generated itself, and that is enough to get a real nebula certificate out
// the other end.
//
// See docs/design-device-identity.md §3.

func TestJoinEndToEnd(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	ts := h.serve(t, freeUDPPort(t))

	root := t.TempDir()
	id, err := device.LoadOrCreate(paths.DeviceKeyPath(root))
	if err != nil {
		t.Fatalf("device key: %v", err)
	}

	client := agent.NewClient(ts.URL)
	joined, err := client.Join(ctx, id, h.netID.String(), "joiner", "test-machine", time.Now())
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if joined.State != "pending" {
		t.Fatalf("state = %q, want pending", joined.State)
	}
	if joined.MembershipID == "" || joined.DeviceID == "" {
		t.Fatal("join returned no membership or device id")
	}

	// A pending membership must hold nothing. If it had an address it would be
	// reachable before anyone approved it, which is the entire thing the queue
	// exists to prevent.
	var pending wire.PendingJoinList
	if code := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/networks/"+h.netID.String()+"/pending", nil, &pending); code != http.StatusOK {
		t.Fatalf("list pending: status %d", code)
	}
	if len(pending.Pending) != 1 {
		t.Fatalf("got %d pending, want 1", len(pending.Pending))
	}
	if pending.Pending[0].MembershipID != joined.MembershipID {
		t.Errorf("queue holds %s, joined %s", pending.Pending[0].MembershipID, joined.MembershipID)
	}

	// Claiming before authorization must be refused, and refused with the
	// status an agent loops on rather than one it gives up on.
	kp, err := agent.GenerateKeypair(h.curve)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	_, err = client.Claim(ctx, id, joined.MembershipID, kp, "e2e", time.Now())
	if err == nil {
		t.Fatal("an unauthorized membership was issued a certificate")
	}
	if !agent.IsPendingAuthorization(err) {
		t.Fatalf("claim before authorization gave %v, want a pending-authorization signal", err)
	}

	// The operator says yes.
	var authorized wire.MembershipResponse
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+joined.MembershipID+"/authorize",
		wire.AuthorizeRequest{RoleID: h.roleID.String()}, &authorized); code != http.StatusOK {
		t.Fatalf("authorize: status %d", code)
	}
	if len(authorized.OverlayAddrs) != 1 {
		t.Fatalf("authorization allocated %d addresses, want 1", len(authorized.OverlayAddrs))
	}

	// And now the machine collects. Same device key, no code anywhere.
	resp, err := client.Claim(ctx, id, joined.MembershipID, kp, "e2e", time.Now())
	if err != nil {
		t.Fatalf("claim after authorization: %v", err)
	}
	if resp.Certificate == "" || resp.CABundle == "" {
		t.Fatal("claim returned no certificate material")
	}

	// Real files, the same ones enrollment produces.
	dir := t.TempDir()
	applier := &generation.Applier{
		Layout:   paths.DefaultLayout(dir),
		Reloader: generation.NoopReloader{},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := applier.Apply(ctx, generation.MaterialFromEnroll(resp, kp.PrivatePEM)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for _, f := range []string{"ca.crt", "host.crt", "host.key", "nebula.yml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// TestJoinRejectsAForgedSignature.
//
// The device public key is public — it is in the CLI, the logs and the admin
// UI. Without this check anyone who has seen one could lodge joins on that
// machine's behalf, filling the queue and taking the names those rows claim.
func TestJoinRejectsAForgedSignature(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	ts := h.serve(t, freeUDPPort(t))

	victim, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// The attacker holds the victim's PUBLIC key and signs with their own.
	now := time.Now()
	sig, err := attacker.SignJoin(h.netID.String(), "impostor", now)
	if err != nil {
		t.Fatal(err)
	}
	req := wire.JoinRequest{
		Network:   h.netID.String(),
		Name:      "impostor",
		PublicKey: base64.StdEncoding.EncodeToString(victim.PublicKey()),
		SignedAt:  now.Unix(),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	var resp wire.JoinResponse
	err = postJSON(ctx, ts.URL+"/enroll/v1/join", req, &resp)
	var apiErr *agent.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("a forged join gave %v, want an API error", err)
	}
	if apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("a forged join got status %d, want 401", apiErr.Status)
	}

	// And nothing landed in the queue.
	var pending wire.PendingJoinList
	h.adminReq(t, http.MethodGet, ts.URL+"/v1/networks/"+h.netID.String()+"/pending", nil, &pending)
	if len(pending.Pending) != 0 {
		t.Fatalf("a forged join created %d queue entries", len(pending.Pending))
	}
}

// TestClaimRefusesAnotherDevice.
//
// The membership already names a device, so the claim signature is checked
// against the key in the DATABASE rather than one the request supplies. A second
// machine that learns a membership id must not be able to collect its
// certificate.
func TestClaimRefusesAnotherDevice(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	ts := h.serve(t, freeUDPPort(t))

	joiner, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(ts.URL)
	joined, err := client.Join(ctx, joiner, h.netID.String(), "rightful", "", time.Now())
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	var authorized wire.MembershipResponse
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+joined.MembershipID+"/authorize",
		nil, &authorized); code != http.StatusOK {
		t.Fatalf("authorize: status %d", code)
	}

	thief, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	kp, err := agent.GenerateKeypair(h.curve)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Claim(ctx, thief, joined.MembershipID, kp, "e2e", time.Now()); err == nil {
		t.Fatal("a different device claimed a membership's certificate")
	}

	// The rightful machine still can.
	if _, err := client.Claim(ctx, joiner, joined.MembershipID, kp, "e2e", time.Now()); err != nil {
		t.Fatalf("the rightful device could not claim: %v", err)
	}
}

// TestJoinIsIdempotentOverHTTP.
//
// An agent that retries after a timeout it could not distinguish from a failure
// must not produce a second queue entry. An operator staring at two rows for one
// laptop has to guess which to authorize.
func TestJoinIsIdempotentOverHTTP(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	ts := h.serve(t, freeUDPPort(t))

	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(ts.URL)

	first, err := client.Join(ctx, id, h.netID.String(), "retrier", "", time.Now())
	if err != nil {
		t.Fatalf("first join: %v", err)
	}
	second, err := client.Join(ctx, id, h.netID.String(), "retrier", "", time.Now())
	if err != nil {
		t.Fatalf("second join: %v", err)
	}
	if first.MembershipID != second.MembershipID {
		t.Fatalf("a retried join created a second membership: %s then %s",
			first.MembershipID, second.MembershipID)
	}

	var pending wire.PendingJoinList
	h.adminReq(t, http.MethodGet, ts.URL+"/v1/networks/"+h.netID.String()+"/pending", nil, &pending)
	if len(pending.Pending) != 1 {
		t.Fatalf("got %d queue entries for one machine, want 1", len(pending.Pending))
	}
}

// TestPostureFlowsToTheDevice.
//
// The property under test is the one the device noun exists for: a machine on N
// networks reports posture N times and the control plane holds ONE answer. Under
// the old model the reading landed per-membership, which meant N rows, N chances
// to disagree, and no answer to "is this laptop encrypted" that did not involve
// picking one.
func TestPostureFlowsToTheDevice(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	ts := h.serve(t, freeUDPPort(t))

	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(ts.URL)
	joined, err := client.Join(ctx, id, h.netID.String(), "reporter", "lab-01", time.Now())
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	var authorized wire.MembershipResponse
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+joined.MembershipID+"/authorize",
		nil, &authorized); code != http.StatusOK {
		t.Fatalf("authorize: status %d", code)
	}

	// The agent report path identifies a host by overlay source address, which
	// only a real overlay listener provides. Drive the store directly with what
	// the handler would have written, so this asserts the recording rule rather
	// than re-testing HTTP plumbing the join tests above already cover.
	yes, no := true, false
	membershipID := uuid.MustParse(joined.MembershipID)
	if err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		d, err := tx.DeviceForHost(ctx, membershipID)
		if err != nil {
			return err
		}
		if err := tx.RecordDeviceFacts(ctx, d.ID, store.DeviceFacts{
			OS: "linux", OSVersion: "Fedora Linux 42", Kernel: "6.14.0", Arch: "amd64",
		}); err != nil {
			return err
		}
		return tx.RecordDevicePosture(ctx, d.ID, store.DevicePosture{
			DiskEncrypted: &yes, SecureBoot: &no,
			// FirewallEnabled deliberately absent: the probe could not tell.
			TPMPresent: &yes,
		})
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	var got wire.DeviceResponse
	if code := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/devices/"+joined.DeviceID, nil, &got); code != http.StatusOK {
		t.Fatalf("get device: status %d", code)
	}

	if got.Facts.OSVersion != "Fedora Linux 42" {
		t.Errorf("OSVersion = %q", got.Facts.OSVersion)
	}
	if got.Posture.DiskEncrypted == nil || !*got.Posture.DiskEncrypted {
		t.Errorf("DiskEncrypted = %v, want true", got.Posture.DiskEncrypted)
	}
	if got.Posture.SecureBoot == nil || *got.Posture.SecureBoot {
		t.Errorf("SecureBoot = %v, want false", got.Posture.SecureBoot)
	}
	// The signal the probe could not read must survive the round trip as
	// UNKNOWN. A JSON encoding that turned a nil *bool into false at any layer
	// would make a broken probe indistinguishable from a non-compliant machine.
	if got.Posture.FirewallEnabled != nil {
		t.Errorf("FirewallEnabled = %v, want unknown", *got.Posture.FirewallEnabled)
	}
	if got.PostureObservedAt == nil {
		t.Error("posture was recorded with no observation time; its age is what makes it evidence")
	}

	// And the machine's membership is reachable from the device, so "where is
	// this laptop" is one request.
	if len(got.Memberships) != 1 || got.Memberships[0].MembershipID != joined.MembershipID {
		t.Errorf("memberships = %+v", got.Memberships)
	}
}

// TestBlockedDeviceCannotJoinOrClaim.
//
// Blocking a device is the revocation mechanism for a device identity, and it is
// what lets that identity be long-lived. A block a machine can step around by
// joining again is not one.
func TestBlockedDeviceCannotJoinOrClaim(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	ts := h.serve(t, freeUDPPort(t))

	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(ts.URL)
	joined, err := client.Join(ctx, id, h.netID.String(), "doomed", "", time.Now())
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	var blocked wire.DeviceResponse
	if code := h.adminPost(t, ts.URL+"/v1/devices/"+joined.DeviceID+"/block",
		wire.BlockDeviceRequest{Reason: "stolen"}, &blocked); code != http.StatusOK {
		t.Fatalf("block: status %d", code)
	}
	if !blocked.Blocked {
		t.Fatal("block did not take")
	}

	// Authorizing a blocked device must be refused. This is the likeliest real
	// case: a machine reported stolen between asking to join and an operator
	// looking at the queue.
	var authorized wire.MembershipResponse
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+joined.MembershipID+"/authorize",
		nil, &authorized); code != http.StatusForbidden {
		t.Fatalf("authorizing a blocked device gave status %d, want 403", code)
	}

	// And it cannot re-join to get a fresh row.
	if _, err := client.Join(ctx, id, h.netID.String(), "doomed-again", "", time.Now()); err == nil {
		t.Fatal("a blocked device joined again")
	}
}

// TestExpiredCertificateRecoversByRejoining.
//
// This is the test that earns the deletion of `orbit agent recover`, and it is
// worth stating exactly what it replaces.
//
// The old recovery flow existed for one reason: the agent API listens only on
// the overlay, so a machine whose certificate expired could not reach the
// control plane to renew the certificate that would give it a working overlay.
// Breaking that circle took a challenge-response protocol, a proof of key
// possession, a recovery window, and a separate public endpoint — all to
// establish something the device key now establishes for free.
//
// A device identity is never issued and never expires. So a machine whose mesh
// certificate has died simply asks again: the join is idempotent and returns the
// membership it already has, and the claim is authenticated by a key no clock
// can invalidate. There is nothing left to recover FROM.
func TestExpiredCertificateRecoversByRejoining(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	ts := h.serve(t, freeUDPPort(t))

	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(ts.URL)

	joined, err := client.Join(ctx, id, h.netID.String(), "long-lived", "", time.Now())
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	var authorized wire.MembershipResponse
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+joined.MembershipID+"/authorize",
		nil, &authorized); code != http.StatusOK {
		t.Fatalf("authorize: status %d", code)
	}
	kp, err := agent.GenerateKeypair(h.curve)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Claim(ctx, id, joined.MembershipID, kp, "e2e", time.Now())
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	// Time passes; the certificate expires; the machine's overlay is dead and
	// the agent API is unreachable. It re-runs the same command it joined with.
	rejoined, err := client.Join(ctx, id, h.netID.String(), "a-different-name", "", time.Now())
	if err != nil {
		t.Fatalf("re-join after expiry: %v", err)
	}
	if rejoined.MembershipID != joined.MembershipID {
		t.Fatalf("re-joining created a new membership (%s) instead of returning the existing one (%s); "+
			"a machine recovering would lose its address and its policy",
			rejoined.MembershipID, joined.MembershipID)
	}
	// And the name it asked for did NOT override the one it holds. A recovering
	// machine must not be able to rename itself out from under a policy that
	// selects on the name.
	if rejoined.Name != "long-lived" {
		t.Errorf("re-joining renamed the membership to %q", rejoined.Name)
	}

	// A fresh mesh key, because the old one is as stale as the certificate.
	newKP, err := agent.GenerateKeypair(h.curve)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Claim(ctx, id, rejoined.MembershipID, newKP, "e2e", time.Now())
	if err != nil {
		t.Fatalf("re-claim after expiry: %v", err)
	}
	if second.Certificate == "" {
		t.Fatal("recovery produced no certificate")
	}
	if second.Certificate == first.Certificate {
		t.Error("recovery handed back the same certificate; it was not reissued")
	}
	// Same place in the network. Recovery that moved a machine's address would
	// break every peer's firewall rule that names it.
	if len(authorized.OverlayAddrs) == 0 || second.MembershipID != joined.MembershipID {
		t.Errorf("recovery did not return the machine to its own membership")
	}
}

// postJSON issues a raw, unauthenticated POST and surfaces the status.
//
// The join and claim endpoints take no bearer token — they authenticate a
// signature — so a test that has to send a DELIBERATELY MALFORMED body cannot
// go through agent.Client, which would refuse to build one. This is the escape
// hatch for exactly that: proving a forged signature is rejected requires
// sending a forgery.
func postJSON(ctx context.Context, url string, body, out any) error {
	b, err := jsonMarshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return &agent.APIError{Status: resp.StatusCode, Message: string(raw)}
	}
	return jsonUnmarshal(raw, out)
}

// TestCLIReserveThenJoin drives the two commands an operator and a machine
// actually run, as processes, against a live control plane.
//
// This is the path `orbit agent install` takes — it shells into `join` — and it
// is worth exercising as a subprocess rather than through the client library,
// because the failure it guards against is a wiring one: install used to call
// `enroll`, which cannot redeem a reservation at all. A code minted by
// `membership reserve` presented to the enrollment endpoint fails, because that
// endpoint expects a code bound to a membership that already exists.
func TestCLIReserveThenJoin(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	res := h.cli(t, ts, "membership", "reserve", "-name", "cli-joined", "-json")
	if res.code != 0 {
		t.Fatalf("reserve: exit %d\n%s", res.code, res.stderr)
	}
	var code wire.EnrollmentCodeResponse
	if err := jsonUnmarshal([]byte(res.stdout), &code); err != nil {
		t.Fatalf("decode reservation: %v\n%s", err, res.stdout)
	}
	if code.Code == "" {
		t.Fatal("reserve returned no code")
	}

	root := t.TempDir()
	dir := filepath.Join(root, "prod")
	// -wait 0 would stop before claiming; a reservation is auto-authorized, so
	// the machine goes straight through to a certificate with nobody watching.
	// That is the property unattended provisioning needs.
	join := h.cliEnv(t, nil, "agent", "join",
		"-url", ts.URL, "-network", h.netID.String(), "-code", code.Code,
		"-dir", dir, "-root", root, "-wait", "30s")
	if join.code != 0 {
		t.Fatalf("join: exit %d\n%s", join.code, join.stderr)
	}

	// The machine holds real files, and the device key sits at the ROOT — one
	// machine, one identity, however many networks it joins.
	for _, f := range []string{
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "host.crt"),
		filepath.Join(dir, "host.key"),
		filepath.Join(dir, "nebula.yml"),
		filepath.Join(root, "device.key"),
	} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}

	// And it took the reserved name, not one it chose.
	var list wire.MembershipListResponse
	h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/memberships?network_id="+h.netID.String(), nil, &list)
	var found bool
	for _, m := range list.Memberships {
		if m.Name == "cli-joined" {
			found = true
			if len(m.OverlayAddrs) == 0 {
				t.Error("the reserved membership has no address")
			}
		}
	}
	if !found {
		t.Error("no membership named cli-joined; the reservation was not redeemed under its own name")
	}
}

// TestInstallThenJoinPicksUpTheNetwork.
//
// The property that makes `install` a device-level command: the service starts
// before this machine belongs to anything, and each join is picked up without a
// restart.
//
// A restart would work, and is what the old install-per-network shape forced. It
// is the wrong answer for a machine already on other networks, because
// restarting to add the third overlay drops the first two — which is a real
// outage caused by a routine action.
func TestInstallThenJoinPicksUpTheNetwork(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	root := t.TempDir()

	// `run` with nothing joined must be a normal running state, not an error.
	// A freshly installed machine idles here until somebody joins it.
	idle := h.cliEnv(t, nil, "agent", "run", "-root", root, "-once")
	if idle.code == 0 {
		t.Fatal("`run -once` with no networks exited 0; a single pass with nothing to do " +
			"should say so rather than look like success")
	}
	if !strings.Contains(idle.stderr, "orbit join") {
		t.Errorf("the message does not say how to fix it:\n%s", idle.stderr)
	}

	// Join, exactly as install would.
	res := h.cli(t, ts, "membership", "reserve", "-name", "picked-up", "-json")
	if res.code != 0 {
		t.Fatalf("reserve: exit %d\n%s", res.code, res.stderr)
	}
	var code wire.EnrollmentCodeResponse
	if err := jsonUnmarshal([]byte(res.stdout), &code); err != nil {
		t.Fatalf("decode reservation: %v", err)
	}

	dir := filepath.Join(root, "prod")
	join := h.cliEnv(t, nil, "agent", "join",
		"-url", ts.URL, "-network", h.netID.String(), "-code", code.Code,
		"-dir", dir, "-root", root, "-wait", "30s")
	if join.code != 0 {
		t.Fatalf("join: exit %d\n%s", join.code, join.stderr)
	}

	// And now the SAME command that had nothing to do finds the network, with
	// no argument naming it — it was discovered under -root.
	after := h.cliEnv(t, nil, "agent", "run", "-root", root, "-once")
	if after.code != 0 {
		t.Fatalf("`run -once` after a join: exit %d\n%s", after.code, after.stderr)
	}
	if !strings.Contains(after.stderr, "prod") {
		t.Errorf("the agent did not report serving the joined network:\n%s", after.stderr)
	}
}

// TestJoinByNetworkID is the ergonomic half: a machine joins by the short,
// verifiable identifier rather than a uuid.
func TestJoinByNetworkID(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	ts := h.serve(t, freeUDPPort(t))

	if len(h.networkID) != ca.NetworkIDLen {
		t.Fatalf("bootstrap produced network id %q, want %d characters", h.networkID, ca.NetworkIDLen)
	}

	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(ts.URL)

	// Written the way an operator would read it off a screen: uppercase, with
	// grouping hyphens. Crockford base32 is case-insensitive by design and this
	// is why.
	pretty := strings.ToUpper(h.networkID[:4] + "-" + h.networkID[4:8] + "-" +
		h.networkID[8:12] + "-" + h.networkID[12:])
	joined, err := client.Join(ctx, id, pretty, "by-id", "", time.Now())
	if err != nil {
		t.Fatalf("join by network id: %v", err)
	}
	if joined.NetworkID != h.networkID {
		t.Errorf("response names %q, want %q", joined.NetworkID, h.networkID)
	}
}

// TestJoinRefusesAControlPlaneThatCannotProveItself.
//
// The whole reason a network ID exists. A uuid plus a URL cannot defend against
// being pointed at the wrong control plane: the machine joins, is issued a
// certificate by somebody else's CA, and is on somebody else's mesh.
//
// The impostor is a SERVER, not another Orbit deployment, because that is the
// actual threat — an attacker's endpoint answers whatever it likes, and will
// happily claim to be the network you asked for. An earlier version of this test
// stood up a second harness and proved nothing: both share one database, so the
// "impostor" resolved the operator's own network and correctly let the machine
// in.
//
// It is the strongest realistic impostor: it KNOWS the network ID, which is not
// a secret and is read off a wiki or a chat message. Only the proof separates it
// from the real control plane.
func TestJoinRefusesAControlPlaneThatCannotProveItself(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	ts := h.serve(t, freeUDPPort(t))

	// The attacker's own network identity. Everything it serves is internally
	// consistent — the key hashes to the ID it claims, the proof verifies under
	// that key — and none of it is the network the operator named.
	attackerPub, attackerPriv, err := ca.GenerateNetworkIdentity()
	if err != nil {
		t.Fatal(err)
	}
	attackerID, err := ca.NetworkIDFor(attackerPub)
	if err != nil {
		t.Fatal(err)
	}

	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req wire.JoinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pub, _ := base64.StdEncoding.DecodeString(req.PublicKey)
		proof, err := ca.SignNetworkProof(attackerPriv,
			device.JoinStatement(req.Network, req.Name, device.Fingerprint(pub),
				time.Unix(req.SignedAt, 0)))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wire.JoinResponse{
			MembershipID: uuid.NewString(),
			DeviceID:     uuid.NewString(),
			Name:         req.Name,
			State:        "created",
			NetworkID:    attackerID,
			NetworkKey:   base64.StdEncoding.EncodeToString(attackerPub),
			NetworkProof: base64.StdEncoding.EncodeToString(proof),
		})
	}))
	t.Cleanup(impostor.Close)

	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// The operator's own network ID, dialled at the wrong URL.
	_, err = agent.NewClient(impostor.URL).
		Join(ctx, id, h.networkID, "misdirected", "", time.Now())
	if err == nil {
		t.Fatal("a machine joined a control plane that does not hold the network's identity key")
	}
	if !errors.Is(err, ca.ErrNetworkIDMismatch) {
		t.Fatalf("error = %v, want ErrNetworkIDMismatch so the agent can say what is wrong", err)
	}

	// And the right URL still works, so the check is not simply refusing
	// everything — which is the way this kind of test usually passes for the
	// wrong reason.
	if _, err := agent.NewClient(ts.URL).
		Join(ctx, id, h.networkID, "correct", "", time.Now()); err != nil {
		t.Fatalf("the real control plane was refused: %v", err)
	}
}

// TestJoinRefusesAForgedProof.
//
// The impostor above fails on the ID. This one is subtler: a control plane that
// serves the RIGHT public key — anyone can copy it, it is public — but does not
// hold the private half. Without checking the signature the two are
// indistinguishable, which is why VerifyNetworkID alone is not enough.
func TestJoinRefusesAForgedProof(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// A response carrying the network's real ID and real public key, and a
	// proof signed by a key the impostor generated.
	_, impostorPriv, err := ca.GenerateNetworkIdentity()
	if err != nil {
		t.Fatal(err)
	}
	challenge := device.JoinStatement(h.networkID, "victim", id.Fingerprint(), now)
	forged, err := ca.SignNetworkProof(impostorPriv, challenge)
	if err != nil {
		t.Fatal(err)
	}

	var netPub []byte
	if err := h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		n, err := tx.GetNetwork(ctx, h.netID)
		if err != nil {
			return err
		}
		netPub = n.IdentityPublicKey
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	err = ca.VerifyNetworkProof(h.networkID, netPub, challenge, forged)
	if err == nil {
		t.Fatal("a control plane serving the right public key passed without holding it")
	}
	if !errors.Is(err, ca.ErrNetworkIDMismatch) {
		t.Errorf("error = %v, want ErrNetworkIDMismatch", err)
	}
}
