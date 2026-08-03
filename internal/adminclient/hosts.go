package adminclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

// HostFilter mirrors the query parameters GET /v1/hosts accepts.
//
// Typed, and every field is passed through. The server refuses a parameter it
// cannot parse rather than dropping it, because a dropped filter returns the
// whole fleet as the answer to a narrow question; a client that quietly failed
// to send one would reintroduce exactly that failure on the other side of the
// wire.
type HostFilter struct {
	NetworkID uuid.UUID

	State        string
	Tag          string
	RoleID       *uuid.UUID
	NameContains string
	Behind       bool

	Limit  int
	Cursor string

	// Count asks for total_count. Off by default: it is a second aggregate
	// query over the same filter, and most listings do not need it.
	Count bool
}

func (f HostFilter) values() url.Values {
	q := url.Values{}
	q.Set("network_id", f.NetworkID.String())
	if f.State != "" {
		q.Set("state", f.State)
	}
	if f.Tag != "" {
		q.Set("tag", f.Tag)
	}
	if f.RoleID != nil {
		q.Set("role_id", f.RoleID.String())
	}
	if f.NameContains != "" {
		q.Set("name_contains", f.NameContains)
	}
	if f.Behind {
		q.Set("behind", "true")
	}
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	if f.Cursor != "" {
		q.Set("cursor", f.Cursor)
	}
	if f.Count {
		q.Set("count", "true")
	}
	return q
}

// ListHosts returns one page of the fleet.
func (c *Client) ListHosts(ctx context.Context, f HostFilter) (Result[wire.HostListResponse], error) {
	return get[wire.HostListResponse](ctx, c, "/v1/hosts", f.values())
}

// GetHost returns one host with its active certificates.
func (c *Client) GetHost(ctx context.Context, id uuid.UUID) (Result[wire.HostResponse], error) {
	return get[wire.HostResponse](ctx, c, "/v1/hosts/"+id.String(), nil)
}

// CertFilter mirrors the query parameters GET /v1/hosts/{id}/certificates
// accepts.
type CertFilter struct {
	State  string
	Limit  int
	Cursor string
}

func (f CertFilter) values() url.Values {
	q := url.Values{}
	if f.State != "" {
		q.Set("state", f.State)
	}
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	if f.Cursor != "" {
		q.Set("cursor", f.Cursor)
	}
	return q
}

// HostCertificates returns one page of a host's certificate history.
func (c *Client) HostCertificates(ctx context.Context, id uuid.UUID, f CertFilter) (Result[wire.CertificateListResponse], error) {
	return get[wire.CertificateListResponse](ctx, c, "/v1/hosts/"+id.String()+"/certificates", f.values())
}

func (c *Client) CreateHost(ctx context.Context, req wire.CreateHostRequest) (Result[wire.HostResponse], error) {
	return send[wire.HostResponse](ctx, c, http.MethodPost, "/v1/hosts", nil, req)
}

func (c *Client) UpdateHost(ctx context.Context, id uuid.UUID, req wire.UpdateHostRequest) (Result[wire.HostResponse], error) {
	return send[wire.HostResponse](ctx, c, http.MethodPatch, "/v1/hosts/"+id.String(), nil, req)
}

// DeleteHost decommissions a host: it revokes the certificates and releases the
// name and address. Returns the blocklist epoch the revocation landed in, which
// is what `orbit converge` can then be watched against.
func (c *Client) DeleteHost(ctx context.Context, id uuid.UUID, reason string) (Result[wire.BlockResponse], error) {
	q := url.Values{}
	if reason != "" {
		q.Set("reason", reason)
	}
	return send[wire.BlockResponse](ctx, c, http.MethodDelete, "/v1/hosts/"+id.String(), q, nil)
}

func (c *Client) BlockHost(ctx context.Context, id uuid.UUID) (Result[wire.BlockResponse], error) {
	return send[wire.BlockResponse](ctx, c, http.MethodPost, "/v1/hosts/"+id.String()+"/block", nil, nil)
}

func (c *Client) UnblockHost(ctx context.Context, id uuid.UUID) (Result[wire.BlockResponse], error) {
	return send[wire.BlockResponse](ctx, c, http.MethodPost, "/v1/hosts/"+id.String()+"/unblock", nil, nil)
}

// EnrollmentCode mints a single-use enrollment credential. The plaintext is in
// the response and nowhere else, ever.
func (c *Client) EnrollmentCode(ctx context.Context, id uuid.UUID) (Result[wire.EnrollmentCodeResponse], error) {
	return send[wire.EnrollmentCodeResponse](ctx, c, http.MethodPost, "/v1/hosts/"+id.String()+"/enrollment-code", nil, nil)
}

// Convergence reports how much of a network has applied the current epochs.
func (c *Client) Convergence(ctx context.Context, networkID uuid.UUID) (Result[wire.ConvergenceResponse], error) {
	return get[wire.ConvergenceResponse](ctx, c, "/v1/networks/"+networkID.String()+"/convergence", nil)
}
