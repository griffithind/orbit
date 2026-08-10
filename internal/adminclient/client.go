// Package adminclient is a typed client for Orbit's admin API.
//
// It lives here rather than inside cmd/orbit because it compiles against
// internal/wire, and that is the whole point of wire existing as its own
// package: a protocol change breaks this build rather than breaking an operator
// at a terminal. A client buried in a main package would still compile against
// wire, but nothing else could ever share it, and the next consumer — a UI, a
// terraform provider, an incident script — would start by copying it.
package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/griffithind/orbit/internal/wire"
)

// Client talks to one control plane with one credential.
type Client struct {
	// BaseURL is the admin surface's root, without a trailing /v1.
	BaseURL string

	// Token is the bearer credential. It is never logged and never placed in a
	// URL: a query string reaches proxy logs, and this one is equivalent to the
	// scopes it carries.
	Token string

	HTTP *http.Client
}

// New builds a client with a bounded timeout.
//
// A timeout rather than none, because "the control plane is down" and "your
// token is bad" are different diagnoses with different remedies, and a CLI that
// hangs forever reports neither.
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Result is a decoded response together with the exact bytes it came from.
//
// Raw exists so `orbit membership ls -json` can emit what the server sent, byte for
// byte, rather than a re-encoding of Value. The docs are still full of curl, so
// a pipeline that works against one has to work against the other — and a
// re-encode would differ in field order, in how timestamps and numbers are
// spelled, and, worst of all, would silently drop every field this build of the
// CLI does not yet know about.
type Result[T any] struct {
	Value T
	Raw   []byte
}

// APIError is a non-2xx response the server explained.
//
// Body is retained because several 409s carry the only actionable part of the
// answer in fields beside "error": which hosts are lagging, which hosts still
// carry a role. Discarding it would leave the CLI printing "conflict" and the
// operator back in curl.
type APIError struct {
	Status  int
	Message string
	Body    []byte
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return e.Message
}

// Lagging decodes the host list a 409 from CA activation carries. Nil for any
// other error body, so a caller can ask unconditionally.
//
// The shape is wire.LaggingHostsError, not a local struct: these two 409 bodies
// are the ones whose non-error field carries the entire remedy, and decoding
// them against an ad-hoc shape would let the server rename a field without
// breaking anything until an operator needed the answer.
func (e *APIError) Lagging() []wire.LaggingHost {
	var body wire.LaggingHostsError
	_ = json.Unmarshal(e.Body, &body)
	return body.Lagging
}

// BlockingHosts decodes the hosts a 409 from role deletion carries.
func (e *APIError) BlockingHosts() []wire.RoleHost {
	var body wire.RoleInUseError
	_ = json.Unmarshal(e.Body, &body)
	return body.Memberships
}

// MissingScope extracts the scope a 403 named.
//
// The server's message is "token lacks required scope: hosts:write". Parsing it
// is a small coupling, and the alternative is a CLI that can only repeat the
// sentence back — where naming the scope lets it print the exact `orbit token
// create` that would grant it, which is the difference between a message and a
// remedy. A parse failure degrades to "", and the caller falls back to the
// server's own words.
func (e *APIError) MissingScope() string {
	const prefix = "token lacks required scope: "
	if i := strings.Index(e.Message, prefix); i >= 0 {
		return strings.TrimSpace(e.Message[i+len(prefix):])
	}
	return ""
}

// UnreachableError is a transport failure: DNS, connection refused, TLS,
// timeout.
//
// A distinct type because it is a distinct diagnosis. "The control plane is
// down" and "your token was revoked" have no remedy in common, and a client
// that folds them into one error makes the operator try the wrong one first.
type UnreachableError struct {
	URL string
	Err error
}

func (e *UnreachableError) Error() string {
	return fmt.Sprintf("cannot reach %s: %v", e.URL, e.Err)
}

func (e *UnreachableError) Unwrap() error { return e.Err }

// do issues one request and returns the raw response body.
//
// out may be nil for endpoints that answer 204. Every caller gets the bytes back
// regardless, because -json prints them verbatim.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body, out any) ([]byte, error) {
	raw, _, err := c.doStatus(ctx, method, path, q, body, out)
	return raw, err
}

// doStatus is do, plus the status code.
//
// Separate because exactly one route needs the code on a success: PATCH
// /v1/roles/{id} answers 200 or 202, and 202 means the edit landed in
// configuration but not yet in any certificate. Inferring that from a body field
// instead would report what the CLI concluded rather than what the server said.
func (c *Client) doStatus(ctx context.Context, method, path string, q url.Values, body, out any) ([]byte, int, error) {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("encode request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		// Unwrap the *url.Error so the message is the cause rather than a
		// restatement of the method and URL we are about to print anyway.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return nil, 0, &UnreachableError{URL: c.BaseURL, Err: uerr.Err}
		}
		return nil, 0, &UnreachableError{URL: c.BaseURL, Err: err}
	}
	defer resp.Body.Close()

	// Bounded, like the server bounds request bodies. A listing is small; a
	// misconfigured URL that reaches something else entirely need not be read
	// into memory in full before it is rejected.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, resp.StatusCode, &UnreachableError{URL: c.BaseURL, Err: err}
	}

	if resp.StatusCode >= 300 {
		return raw, resp.StatusCode,
			&APIError{Status: resp.StatusCode, Message: errMessage(raw, resp.Status), Body: raw}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return raw, resp.StatusCode, fmt.Errorf("decode %s %s: %w", method, path, err)
		}
	}
	return raw, resp.StatusCode, nil
}

// errMessage pulls the error out of a wire.Error body, falling back to the
// status line for a response that is not one — a proxy's HTML, say, which is
// exactly the case where the status line is the only true thing available.
func errMessage(raw []byte, status string) string {
	var e wire.Error
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		return e.Error
	}
	if s := strings.TrimSpace(string(raw)); s != "" && len(s) < 512 {
		return s
	}
	return status
}

// get is the common shape: decode into T and hand back the bytes too.
func get[T any](ctx context.Context, c *Client, path string, q url.Values) (Result[T], error) {
	var v T
	raw, err := c.do(ctx, http.MethodGet, path, q, nil, &v)
	return Result[T]{Value: v, Raw: raw}, err
}

func send[T any](ctx context.Context, c *Client, method, path string, q url.Values, body any) (Result[T], error) {
	var v T
	raw, err := c.do(ctx, method, path, q, body, &v)
	return Result[T]{Value: v, Raw: raw}, err
}

// WhoAmI describes the calling credential.
//
// The CLI fetches JSON and renders it itself rather than asking for
// ?format=text. That renderer is a compatibility surface —
// scripts/check-break-glass.sh parses it with sed, on a machine that may not
// have jq — and a second consumer with its own layout wishes would be the thing
// that eventually breaks it.
func (c *Client) WhoAmI(ctx context.Context) (Result[wire.WhoAmIResponse], error) {
	return get[wire.WhoAmIResponse](ctx, c, "/v1/whoami", nil)
}

// Raw performs an arbitrary authenticated request against the admin API and
// returns the response body verbatim.
//
// The escape hatch behind `orbit api`, and the reason it exists is that a CLI
// which only exposes what someone remembered to wrap becomes a ceiling on the
// API. ZeroTier arrived at the same idea from the other end: any argument
// beginning with "/" is passed straight through.
//
// The body is returned unparsed. A caller that wanted a typed response would
// use the typed method; this one exists precisely for the routes that have none
// yet, and re-encoding would put this command's opinion between the server and
// jq.
func (c *Client) Raw(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	var payload any
	if len(body) > 0 {
		payload = json.RawMessage(body)
	}
	return c.doStatus(ctx, method, path, nil, payload, nil)
}
