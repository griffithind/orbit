package agent

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/wire"
)

// Recovery for a host whose certificate expired while it was offline.
//
// Such a host cannot reach the overlay, so it cannot renew through the agent
// API. It falls back to the public endpoint and proves it is who it claims by
// demonstrating possession of the private key from its last certificate.
//
// The proof is a Diffie-Hellman exchange rather than a signature: nebula host
// keys on Curve25519 are X25519, key agreement only.

// RecoveryChallenge fetches the server's half of the exchange.
func (c *Client) RecoveryChallenge(ctx context.Context, hostID string) (*wire.RecoveryChallengeResponse, error) {
	url := fmt.Sprintf("%s/enroll/v1/recover/challenge?host_id=%s", c.BaseURL, hostID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out wire.RecoveryChallengeResponse
	if err := decodeResponse(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Recover answers a challenge and returns a fresh generation.
//
// keyPath is the host's existing private key — the one whose certificate
// expired. It never leaves the machine; only the shared secret derived from it
// is used, and only to compute a MAC.
func (c *Client) Recover(ctx context.Context, hostID, keyPath string, ch *wire.RecoveryChallengeResponse, newKey *Keypair) (*wire.EnrollResponse, error) {
	id, err := uuid.Parse(hostID)
	if err != nil {
		return nil, fmt.Errorf("host id: %w", err)
	}

	oldPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read existing key (recovery needs the key whose certificate expired): %w", err)
	}
	oldPriv, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(oldPEM)
	if err != nil {
		return nil, fmt.Errorf("parse existing key: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	serverPub, err := base64.StdEncoding.DecodeString(ch.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode server public key: %w", err)
	}
	newPub, err := base64.StdEncoding.DecodeString(newKey.PublicB64)
	if err != nil {
		return nil, err
	}

	shared, err := ca.SharedSecret(curve, oldPriv, serverPub)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}

	// Bind the NEW public key into the MAC. Without that binding a captured
	// proof could be replayed to obtain a certificate for a key the attacker
	// holds; with it, the MAC simply would not match.
	key, err := hkdf.Key(sha256.New, shared, nonce, "orbit-recovery-v1", 32)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(id[:])
	mac.Write(newPub)

	req := wire.RecoverRequest{
		HostID:    hostID,
		Nonce:     ch.Nonce,
		PublicKey: newKey.PublicB64,
		Curve:     newKey.Curve.String(),
		Proof:     base64.StdEncoding.EncodeToString(mac.Sum(nil)),
	}

	var resp wire.EnrollResponse
	if err := c.post(ctx, "/enroll/v1/recover", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
