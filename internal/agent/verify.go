package agent

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Verifier decides whether a freshly applied generation actually works.
//
// This runs after the reload and before the apply is considered successful. If
// it fails, the applier restores the previous generation. Without it, "apply"
// means "the files were written and a signal was sent", which is not the same
// as "the host is still on the mesh" — and the gap between those two is exactly
// where a fleet silently falls off.
type Verifier interface {
	Verify(ctx context.Context) error
	Describe() string
}

// NoopVerifier accepts everything.
//
// Correct when something else owns liveness (a test harness, or an operator
// watching a rollout by hand), and wrong as a production default: it turns the
// rollback machinery into dead code, because nothing ever reports failure.
type NoopVerifier struct{}

func (NoopVerifier) Verify(context.Context) error { return nil }
func (NoopVerifier) Describe() string             { return "none" }

// VerifierFunc adapts a function.
type VerifierFunc struct {
	Name string
	Fn   func(ctx context.Context) error
}

func (v VerifierFunc) Verify(ctx context.Context) error { return v.Fn(ctx) }
func (v VerifierFunc) Describe() string                 { return v.Name }

// ReachabilityVerifier confirms the control plane is reachable over the overlay.
//
// This is the strongest signal available to the agent without adding a
// dependency, because it is end to end: a successful request proves nebula
// loaded the new certificate, the handshake completed against a peer, the
// firewall permits the flow, and routing works. Checking that the process is
// alive, or that the config parses, proves none of those.
//
// It requires the agent endpoint to be an overlay address. When Orbit is not
// yet running on the overlay the agent has no such signal and should use
// NoopVerifier, accepting that rollback is then untested in production.
type ReachabilityVerifier struct {
	// URL is polled until it answers. Any 2xx, 4xx, or 5xx response counts as
	// reachable: the question is whether packets flow, not whether the endpoint
	// likes the request. Only a transport failure means "not reachable".
	URL string

	// Timeout bounds the whole verification.
	//
	// This must comfortably exceed a nebula handshake plus any hole punching.
	// Too short and a healthy renewal gets rolled back, which is worse than no
	// verification at all: it turns a working host into a flapping one.
	Timeout time.Duration

	// Interval between attempts.
	Interval time.Duration

	HTTP *http.Client
}

func NewReachabilityVerifier(url string) *ReachabilityVerifier {
	return &ReachabilityVerifier{
		URL:      url,
		Timeout:  60 * time.Second,
		Interval: 2 * time.Second,
		HTTP:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (v *ReachabilityVerifier) Describe() string {
	return "reachability of " + v.URL
}

func (v *ReachabilityVerifier) Verify(ctx context.Context) error {
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	interval := v.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	client := v.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastErr error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.URL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			// Any HTTP response at all means the overlay path works.
			return nil
		}
		lastErr = err

		select {
		case <-ctx.Done():
			return fmt.Errorf("control plane unreachable over the overlay after %s: %w", timeout, lastErr)
		case <-time.After(interval):
		}
	}
}
