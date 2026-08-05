package adminclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

// ListNetworks returns every network the credential can see. Unpaginated,
// because the server does not paginate it: a deployment's networks are counted
// in tens, not thousands.
func (c *Client) ListNetworks(ctx context.Context) (Result[[]wire.NetworkResponse], error) {
	return get[[]wire.NetworkResponse](ctx, c, "/v1/networks", nil)
}

// GetNetwork resolves one network by uuid or by name, in a single request.
//
// The server takes either, because network names are globally unique. Before
// this route existed every command that named a network listed all of them and
// filtered client-side — a cost paid on each invocation, and proportional to
// the number of networks rather than to the one being asked about.
func (c *Client) GetNetwork(ctx context.Context, ref string) (Result[wire.NetworkResponse], error) {
	return get[wire.NetworkResponse](ctx, c, "/v1/networks/"+url.PathEscape(ref), nil)
}

func (c *Client) ListRoles(ctx context.Context, networkID uuid.UUID) (Result[[]wire.RoleResponse], error) {
	q := url.Values{"network_id": {networkID.String()}}
	return get[[]wire.RoleResponse](ctx, c, "/v1/roles", q)
}

func (c *Client) GetRole(ctx context.Context, id uuid.UUID) (Result[wire.RoleResponse], error) {
	return get[wire.RoleResponse](ctx, c, "/v1/roles/"+id.String(), nil)
}

// RoleUpdateResult is wire.RoleUpdateResponse plus what only the status line
// says.
//
// Embedding rather than restating: the fields moved into internal/wire, so a
// rename on the server is now a build failure here instead of a silent
// regression. Accepted is the one thing the body genuinely does not carry.
type RoleUpdateResult struct {
	wire.RoleUpdateResponse

	// Accepted records that the server answered 202 rather than 200 — the
	// configuration half of a group change is live, the certificate half is
	// not. Read from the status line rather than inferred from GroupsChanged,
	// so the CLI reports what the server actually said.
	Accepted bool `json:"-"`
}

// UpdateRole edits a role. A group change answers 202 with a certificate-lag
// deadline; that is a success, not an error, and the caller must say so loudly.
func (c *Client) UpdateRole(ctx context.Context, id uuid.UUID, req wire.UpdateRoleRequest) (Result[RoleUpdateResult], error) {
	var v RoleUpdateResult
	raw, status, err := c.doStatus(ctx, http.MethodPatch, "/v1/roles/"+id.String(), nil, req, &v)
	v.Accepted = status == http.StatusAccepted
	return Result[RoleUpdateResult]{Value: v, Raw: raw}, err
}

// DeleteRole removes a role no host carries. A 409 names the carriers in its
// body; see APIError.BlockingHosts.
func (c *Client) DeleteRole(ctx context.Context, id uuid.UUID) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/roles/"+id.String(), nil, nil, nil)
	return err
}

func (c *Client) ListCAs(ctx context.Context, networkID uuid.UUID) (Result[[]wire.CAResponse], error) {
	q := url.Values{"network_id": {networkID.String()}}
	return get[[]wire.CAResponse](ctx, c, "/v1/cas", q)
}

// ActivateCA promotes a CA to signing. A 409 carries the lagging hosts; see
// APIError.Lagging.
func (c *Client) ActivateCA(ctx context.Context, id uuid.UUID, acknowledgeCutoff bool) (Result[wire.CAResponse], error) {
	// Always send a body, even the empty one. The server tolerates no body, but
	// a request that sometimes has one and sometimes not is a shape a proxy or a
	// future middleware can treat differently, and the override must never be
	// lost in transit.
	req := wire.ActivateCARequest{AcknowledgeCutoff: acknowledgeCutoff}
	return send[wire.CAResponse](ctx, c, http.MethodPost, "/v1/cas/"+id.String()+"/activate", nil, req)
}

func (c *Client) RetireCA(ctx context.Context, id uuid.UUID) (Result[wire.CAResponse], error) {
	return send[wire.CAResponse](ctx, c, http.MethodPost, "/v1/cas/"+id.String()+"/retire", nil, nil)
}

func (c *Client) ListTokens(ctx context.Context) (Result[[]wire.TokenResponse], error) {
	return get[[]wire.TokenResponse](ctx, c, "/v1/tokens", nil)
}

// CreateToken mints a credential. The plaintext is in the response and is not
// recoverable afterwards — only its SHA-256 is stored.
func (c *Client) CreateToken(ctx context.Context, req wire.CreateTokenRequest) (Result[wire.TokenResponse], error) {
	return send[wire.TokenResponse](ctx, c, http.MethodPost, "/v1/tokens", nil, req)
}

func (c *Client) RevokeToken(ctx context.Context, id uuid.UUID) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/tokens/"+id.String(), nil, nil, nil)
	return err
}

// ListSessions returns the browser sessions that can reach the control plane
// right now. Live only — a session that expired, was signed out, or went idle
// is absent rather than listed as dead.
func (c *Client) ListSessions(ctx context.Context) (Result[[]wire.SessionResponse], error) {
	return get[[]wire.SessionResponse](ctx, c, "/v1/sessions", nil)
}

// RevokeSession ends one browser session. The token it references keeps
// working; RevokeToken is the larger act.
func (c *Client) RevokeSession(ctx context.Context, id uuid.UUID) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/sessions/"+id.String(), nil, nil, nil)
	return err
}

// AuditFilter mirrors the query parameters GET /v1/audit-logs accepts.
type AuditFilter struct {
	Action     string
	TargetType string
	TargetID   string
	Since      time.Time
	Until      time.Time
	Limit      int
}

func (f AuditFilter) values() url.Values {
	q := url.Values{}
	if f.Action != "" {
		q.Set("action", f.Action)
	}
	if f.TargetType != "" {
		q.Set("target_type", f.TargetType)
	}
	if f.TargetID != "" {
		q.Set("target_id", f.TargetID)
	}
	if !f.Since.IsZero() {
		q.Set("since", f.Since.Format(time.RFC3339))
	}
	if !f.Until.IsZero() {
		q.Set("until", f.Until.Format(time.RFC3339))
	}
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	return q
}

func (c *Client) ListAudit(ctx context.Context, f AuditFilter) (Result[[]wire.AuditRecordResponse], error) {
	return get[[]wire.AuditRecordResponse](ctx, c, "/v1/audit-logs", f.values())
}

// CreateCA mints a new certificate authority for a network.
//
// The CA is created but NOT signing: it has to be distributed to every host before
// anything is signed by it, which is what `orbit ca activate` does once they have it.
// That two-step is the whole of rotation, and it is why this returns a CA nobody is using
// yet rather than one that has already taken over.
func (c *Client) CreateCA(ctx context.Context, networkID uuid.UUID, req wire.CreateCARequest) (Result[wire.CAResponse], error) {
	q := url.Values{"network_id": {networkID.String()}}
	return send[wire.CAResponse](ctx, c, http.MethodPost, "/v1/cas", q, req)
}
