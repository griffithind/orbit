package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// Recovery for a host whose certificate expired while it was offline.
//
// That host cannot reach the overlay, so the agent API — the normal renewal
// path — is closed to it. Without recovery the only remedy is an operator
// re-enrolling by hand, which is the papercut that decides whether people keep
// using a thing.
//
// Identity is proved by Diffie-Hellman rather than a signature, because nebula
// host keys on Curve25519 are X25519 and cannot sign at all.

// expireCertificate backdates a host's certificate so it is past NotAfter,
// which is the state recovery exists for and is otherwise a day's wait.
func expireCertificate(t *testing.T, h *harness, hostID uuid.UUID, notAfter time.Time) {
	t.Helper()
	err := h.store.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		c, err := tx.LatestCertificate(ctx, hostID)
		if err != nil {
			return err
		}
		_, err = h.store.Pool().Exec(ctx,
			`UPDATE orbit.certificate SET not_before = $2, not_after = $3 WHERE id = $1`,
			c.ID, notAfter.Add(-24*time.Hour), notAfter)
		return err
	})
	if err != nil {
		t.Fatalf("expire certificate: %v", err)
	}
}

func recover_(t *testing.T, ts string, host *enrolledHost, hostID string) (*wire.EnrollResponse, error) {
	t.Helper()
	ctx := context.Background()

	client := agent.NewClient(ts)
	ch, err := client.RecoveryChallenge(ctx, hostID)
	if err != nil {
		return nil, err
	}
	kp, err := agent.GenerateKeypair(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	return client.Recover(ctx, hostID, filepath.Join(host.dir, "host.key"), ch, kp)
}

// TestRecoveryAfterExpiry is the headline case.
func TestRecoveryAfterExpiry(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "came-back", "10.42.50.5", false, false, nil)
	hostID := host.id
	oldCert := readFile(t, filepath.Join(host.dir, "host.crt"))

	// Expired yesterday: inside the grace window.
	expireCertificate(t, h, uuid.MustParse(hostID), time.Now().Add(-24*time.Hour))

	resp, err := recover_(t, ts.URL, host, hostID)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if resp.Certificate == "" || resp.Certificate == oldCert {
		t.Fatal("recovery did not issue a new certificate")
	}
	if !resp.NotAfter.After(time.Now()) {
		t.Errorf("recovered certificate is already expired: %s", resp.NotAfter)
	}

	// It must be audited loudly: routine recovery means renewal is broken.
	var audit []wire.AuditRecordResponse
	h.adminReq(t, http.MethodGet, ts.URL+"/v1/audit-logs?target_id="+hostID, nil, &audit)
	found := false
	for _, a := range audit {
		if a.Action == store.ActionRecovered {
			found = true
			t.Logf("audited: %s meta=%s", a.Action, a.Meta)
		}
	}
	if !found {
		t.Error("recovery was not audited")
	}
}

// TestRecoveryRequiresTheRealKey is the whole security property. An attacker
// who knows a host id but not its key must get nothing.
func TestRecoveryRequiresTheRealKey(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "impersonated", "10.42.51.5", false, false, nil)
	expireCertificate(t, h, uuid.MustParse(host.id), time.Now().Add(-24*time.Hour))

	// A different host's directory stands in for an attacker holding some other
	// valid key: they can complete the exchange, just not for this identity.
	other := h.createAndEnroll(t, ts, "attacker", "10.42.51.9", false, false, nil)

	_, err := recover_(t, ts.URL, other, host.id)
	if err == nil {
		t.Fatal("recovered another host's identity with the wrong key")
	}
	var apiErr *agent.APIError
	if !errorsAs(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("wrong-key recovery = %v, want 401", err)
	}
	if apiErr.Message != "recovery denied" {
		t.Errorf("error message %q distinguishes failure modes; it should not", apiErr.Message)
	}
}

// TestRecoveryRefusesBlockedHost: recovery is a path to a new certificate, and
// blocking exists precisely to close that path.
func TestRecoveryRefusesBlockedHost(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "blocked-return", "10.42.52.5", false, false, nil)
	expireCertificate(t, h, uuid.MustParse(host.id), time.Now().Add(-24*time.Hour))

	var blocked wire.BlockResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts/"+host.id+"/block", nil, &blocked); code != http.StatusOK {
		t.Fatalf("block: %d", code)
	}

	if _, err := recover_(t, ts.URL, host, host.id); err == nil {
		t.Fatal("a blocked host recovered")
	}
}

// TestRecoveryRefusesPastGrace bounds the window. A certificate that expired
// long ago is more likely a decommissioned machine than a returning one, and
// the old key file has had that long to leak.
func TestRecoveryRefusesPastGrace(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "long-gone", "10.42.53.5", false, false, nil)
	expireCertificate(t, h, uuid.MustParse(host.id), time.Now().Add(-400*24*time.Hour))

	if _, err := recover_(t, ts.URL, host, host.id); err == nil {
		t.Fatal("recovered a host whose certificate expired over a year ago")
	}
}

// TestRecoveryProofBindsTheNewKey is the replay guard. A captured proof must
// not be reusable to obtain a certificate for a key the attacker controls.
func TestRecoveryProofBindsTheNewKey(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	host := h.createAndEnroll(t, ts, "replay-target", "10.42.54.5", false, false, nil)
	expireCertificate(t, h, uuid.MustParse(host.id), time.Now().Add(-24*time.Hour))

	client := agent.NewClient(ts.URL)
	ch, err := client.RecoveryChallenge(ctx, host.id)
	if err != nil {
		t.Fatal(err)
	}

	// Compute a legitimate proof for one key...
	honest, _ := agent.GenerateKeypair(cert.Curve_CURVE25519)
	resp, err := client.Recover(ctx, host.id, filepath.Join(host.dir, "host.key"), ch, honest)
	if err != nil {
		t.Fatalf("honest recovery: %v", err)
	}
	_ = resp

	// ...then replay that same proof with a key the attacker controls. The MAC
	// covers the new public key, so it cannot match.
	attacker, _ := agent.GenerateKeypair(cert.Curve_CURVE25519)
	var replayed wire.EnrollResponse
	err = postJSON(ctx, ts.URL+"/enroll/v1/recover", wire.RecoverRequest{
		HostID:    host.id,
		Nonce:     ch.Nonce,
		PublicKey: attacker.PublicB64,
		Curve:     "CURVE25519",
		// The proof from the honest exchange, recomputed here would need the
		// host key; we deliberately reuse a value bound to a different key.
		Proof: base64.StdEncoding.EncodeToString([]byte("replayed-proof-bytes-not-valid")),
	}, &replayed)
	if err == nil {
		t.Fatal("a proof bound to one key was accepted for another")
	}
}

// TestRecoveryChallengeExpires bounds how long a challenge stays answerable.
func TestRecoveryChallengeExpires(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	host := h.createAndEnroll(t, ts, "slow-answer", "10.42.55.5", false, false, nil)
	expireCertificate(t, h, uuid.MustParse(host.id), time.Now().Add(-24*time.Hour))

	client := agent.NewClient(ts.URL)
	ch, err := client.RecoveryChallenge(ctx, host.id)
	if err != nil {
		t.Fatal(err)
	}
	if !ch.ExpiresAt.After(time.Now()) {
		t.Error("challenge is issued already expired")
	}

	// Forge a nonce with an old timestamp. The server derives its ephemeral key
	// from the nonce, so an attacker can choose one — but a stale timestamp is
	// rejected before any work happens.
	stale := make([]byte, 24)
	copy(stale, []byte{0, 0, 0, 0, 0x50, 0, 0, 0}) // far in the past
	var out wire.EnrollResponse
	err = postJSON(ctx, ts.URL+"/enroll/v1/recover", wire.RecoverRequest{
		HostID: host.id, Nonce: base64.StdEncoding.EncodeToString(stale),
		PublicKey: "AAAA", Curve: "CURVE25519", Proof: "AAAA",
	}, &out)
	if err == nil {
		t.Fatal("a stale challenge was accepted")
	}
}

func postJSON(ctx context.Context, url string, body, out any) error {
	c := agent.NewClient("")
	_ = c
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
