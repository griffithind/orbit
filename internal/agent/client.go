package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/wire"
)

// Client talks to the control plane.
type Client struct {
	BaseURL string
	HTTP    *http.Client

	// escapeHost is the enrolled public endpoint whose connections bypass the
	// tunnel. Empty when this host has no exit node, which is almost all of
	// them. See escapehatch.go.
	escapeHost string
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		// Comfortably above the server's watch hold: a long poll that completes
		// normally must not look like a client timeout.
		HTTP: &http.Client{Timeout: 2 * time.Minute},
	}
}

// Keypair is a freshly generated host identity.
//
// The private half never leaves this struct's process. It is written to disk by
// the applier and is never sent to the control plane; there is no field for it
// in any wire type.
type Keypair struct {
	Curve      cert.Curve
	PublicB64  string
	PrivatePEM string
}

// GenerateKeypair creates a host static keypair.
//
// Generating on the host is not a convenience, it is the property that makes
// the control plane's compromise bounded: Orbit can mint a certificate for a
// public key, but it can never impersonate a host whose private key it has
// never seen.
func GenerateKeypair(curve cert.Curve) (*Keypair, error) {
	pub, priv, err := ca.GenerateHostKey(curve)
	if err != nil {
		return nil, err
	}
	return &Keypair{
		Curve:      curve,
		PublicB64:  base64.StdEncoding.EncodeToString(pub),
		PrivatePEM: string(cert.MarshalPrivateKeyToPEM(curve, priv)),
	}, nil
}

// Enroll redeems a credential and returns the host's first generation.
func (c *Client) Enroll(ctx context.Context, credential string, kp *Keypair, agentVersion string) (*wire.EnrollResponse, error) {
	req := wire.EnrollRequest{
		Credential:   credential,
		PublicKey:    kp.PublicB64,
		Curve:        kp.Curve.String(),
		AgentVersion: agentVersion,
	}
	var resp wire.EnrollResponse
	if err := c.post(ctx, "/enroll/v1/enroll", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// State polls for updates, telling the server what the agent has already
// applied so an unchanged response stays small.
func (c *Client) State(ctx context.Context, configEpoch, blockEpoch int64) (*wire.StateResponse, error) {
	url := fmt.Sprintf("%s/agent/v1/state?config_epoch=%d&blocklist_epoch=%d",
		c.BaseURL, configEpoch, blockEpoch)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	httpResp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	var resp wire.StateResponse
	if err := decodeResponse(httpResp, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Report tells the control plane what this host has applied.
//
// Called only after a successful apply. Reporting on fetch would make
// convergence measure downloads and hide the case where a configuration
// arrived but never took effect.
func (c *Client) Report(ctx context.Context, r wire.ReportRequest) error {
	return c.post(ctx, "/agent/v1/report", r, nil)
}

// Renew requests a fresh certificate for a new keypair.
func (c *Client) Renew(ctx context.Context, kp *Keypair) (*wire.EnrollResponse, error) {
	req := wire.RenewRequest{PublicKey: kp.PublicB64, Curve: kp.Curve.String()}
	var resp wire.EnrollResponse
	if err := c.post(ctx, "/agent/v1/renew", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, out)
}

// APIError carries a status code so callers can distinguish "retry" from
// "this will never work". A 401 on enrollment means the credential is spent;
// retrying is pointless and looks like an attack.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("control plane returned %d: %s", e.Status, e.Message)
}

// Retryable reports whether another attempt could succeed. 5xx and 429 are
// transient; 4xx means the request itself is wrong.
func (e *APIError) Retryable() bool {
	return e.Status >= 500 || e.Status == http.StatusTooManyRequests
}

func decodeResponse(resp *http.Response, out any) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		return err
	}

	if resp.StatusCode >= 300 {
		msg := string(bytes.TrimSpace(body))
		var e wire.Error
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}

	if out == nil || len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

// Watch long-polls for changes.
//
// It returns as soon as an epoch advances, or empty after the server's hold
// period. The agent treats a hold-period return as "nothing changed, reconnect"
// rather than an error: an idle watch completing is the normal case.
//
// The HTTP timeout must exceed the server's hold or every watch looks like a
// failure. NewClient's default is deliberately larger than DefaultWatchHold.
func (c *Client) Watch(ctx context.Context, configEpoch, blockEpoch int64, hold time.Duration) (*wire.StateResponse, error) {
	url := fmt.Sprintf("%s/agent/v1/watch?config_epoch=%d&blocklist_epoch=%d&hold=%s",
		c.BaseURL, configEpoch, blockEpoch, hold)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out wire.StateResponse
	if err := decodeResponse(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Join asks a control plane to admit this device to a network.
//
// The device key signs the request; nothing secret travels. What comes back is
// a membership id and a state, not a certificate — see Claim for the second
// half.
//
// code is a reservation code, empty when there is none. It used to be a second
// method wrapping this one with "", which production never called and only
// tests reached — two spellings of one request.
//
// A valid code auto-authorizes: the membership is created with the name,
// address and role the reservation named, instead of landing in a queue. That
// is what keeps unattended provisioning working — a machine can come up fully
// configured with nobody watching.
//
// The code is NOT part of the signed statement, and that is worth being explicit
// about. The signature proves who is asking; the code proves the asking was
// pre-authorized. They are independent claims, and binding them would mean a
// reservation could only ever be redeemed by a device chosen before the code was
// minted — which is the opposite of what a reservation is for.
func (c *Client) Join(ctx context.Context, id *device.Identity,
	network, name, hostname, code string, now time.Time) (*wire.JoinResponse, error) {

	sig, err := id.SignJoin(network, name, now)
	if err != nil {
		return nil, fmt.Errorf("sign join: %w", err)
	}
	req := wire.JoinRequest{
		Network:    network,
		Name:       name,
		PublicKey:  base64.StdEncoding.EncodeToString(id.PublicKey()),
		Hostname:   hostname,
		SignedAt:   now.Unix(),
		Signature:  base64.StdEncoding.EncodeToString(sig),
		Credential: code,
	}
	var resp wire.JoinResponse
	if err := c.post(ctx, "/enroll/v1/join", req, &resp); err != nil {
		return nil, err
	}

	// Verify that the control plane that answered is the one the network ID
	// names, BEFORE anything it said is acted on.
	//
	// This is the step that makes a network ID worth having. Without it a
	// machine pointed at a hostile URL joins, is issued a certificate by
	// somebody else's CA, and is on somebody else's mesh — and nothing in a
	// uuid, a slug, or a URL could have told it otherwise.
	//
	// The challenge is reconstructed rather than trusted: it is the statement
	// this client just signed, so a proof over anything else does not verify.
	if err := verifyNetwork(network, name, id.Fingerprint(), now, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// verifyNetwork checks a join response's proof of network identity.
//
// When the caller joined BY network ID, that ID is what must be satisfied — the
// one in the response is the control plane's own claim about itself and cannot
// be the thing it is checked against.
//
// When the caller joined by uuid or slug there is nothing to check against, so
// this verifies the response is at least internally consistent — the key hashes
// to the ID it claims, and the proof verifies under it — and the caller records
// the ID for next time. Trust on first use: weaker than an ID handed over out of
// band, much stronger than nothing.
func verifyNetwork(ref, name, fingerprint string, at time.Time, resp *wire.JoinResponse) error {
	key, err := base64.StdEncoding.DecodeString(resp.NetworkKey)
	if err != nil {
		return fmt.Errorf("control plane sent an unreadable network key: %w", err)
	}
	proof, err := base64.StdEncoding.DecodeString(resp.NetworkProof)
	if err != nil {
		return fmt.Errorf("control plane sent an unreadable network proof: %w", err)
	}

	expect := resp.NetworkID
	if _, err := ca.ParseNetworkID(ref); err == nil {
		expect = ref
	}

	challenge := device.JoinStatement(ref, name, fingerprint, at)
	if err := ca.VerifyNetworkProof(expect, key, challenge, proof); err != nil {
		return fmt.Errorf("refusing to join: %w", err)
	}
	return nil
}

// Claim collects the certificate an authorized membership entitles this device
// to, issued over a freshly generated mesh key.
//
// The 409 an unauthorized membership produces is a normal, expected answer here
// and not a failure — see ErrPendingAuthorization.
func (c *Client) Claim(ctx context.Context, id *device.Identity, membershipID string, kp *Keypair, agentVersion string, now time.Time) (*wire.EnrollResponse, error) {
	// Signed over the base64 exactly as it will be sent, so there is no
	// encoding step between what was signed and what is verified.
	sig, err := id.SignClaim(membershipID, kp.PublicB64, now)
	if err != nil {
		return nil, fmt.Errorf("sign claim: %w", err)
	}
	req := wire.ClaimRequest{
		MembershipID: membershipID,
		PublicKey:    kp.PublicB64,
		Curve:        kp.Curve.String(),
		AgentVersion: agentVersion,
		SignedAt:     now.Unix(),
		Signature:    base64.StdEncoding.EncodeToString(sig),
	}
	var resp wire.EnrollResponse
	if err := c.post(ctx, "/enroll/v1/claim", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// IsPendingAuthorization reports whether a Claim failed only because nobody has
// approved the membership yet.
//
// A predicate rather than a sentinel error because the signal arrives as an
// HTTP status from a server this client does not otherwise interpret, and the
// caller's response to it — keep waiting — is the one case where a non-2xx is
// not a problem.
func IsPendingAuthorization(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict
}
