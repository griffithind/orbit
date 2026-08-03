package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/wire"
)

// Client talks to the control plane.
type Client struct {
	BaseURL string
	HTTP    *http.Client
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

// KeypairFromPrivate reconstructs a Keypair from an existing private key.
//
// Used by --reuse-key renewal. The private half never changes and never leaves
// the host; only the derived public half is sent.
func KeypairFromPrivate(curve cert.Curve, priv []byte) (*Keypair, error) {
	pub, err := ca.PublicFromHostKey(curve, priv)
	if err != nil {
		return nil, err
	}
	return &Keypair{
		Curve:      curve,
		PublicB64:  base64.StdEncoding.EncodeToString(pub),
		PrivatePEM: string(cert.MarshalPrivateKeyToPEM(curve, priv)),
	}, nil
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
