package adminclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/griffithind/orbit/internal/wire"
)

// The network policy document.
//
// ref is a network uuid or slug, the same pair GetNetwork takes and for the same
// reason: both are immutable, so automation holding either survives a rename.
//
// The request body of PutPolicy and CheckPolicy is the DOCUMENT ITSELF, with no
// envelope — see the note above wire.PolicyResponse. do() marshals whatever it is
// given, and json.Marshal of a json.RawMessage emits those bytes (compacted),
// which is exactly the raw body the server reads. That does mean a document that
// is not valid JSON fails at the marshal step with an encoding error rather than
// with the server's lint; every caller here validates locally first, which is
// what makes that unreachable in practice and a better error when it is not.

// GetPolicy reads a network's current policy document.
//
// A 404 means one of two things and the server's message distinguishes them: the
// network does not exist, or it exists and has never had a document — which is
// the state of every network that has not opted in.
func (c *Client) GetPolicy(ctx context.Context, ref string) (Result[wire.PolicyResponse], error) {
	return get[wire.PolicyResponse](ctx, c, "/v1/networks/"+url.PathEscape(ref)+"/policy", nil)
}

// PutPolicy replaces the document wholesale.
//
// Wholesale, never merged, for the reason UpdateRole's firewall field is:
// merging makes "remove this entry" inexpressible, and an entry an operator
// believes they deleted is the worst possible outcome for a firewall.
//
// The response reports `changed`, which is false when the document was
// semantically what was already stored. That is not a failure — it is the
// property that makes re-running a reconcile loop free rather than a fleet-wide
// re-render.
func (c *Client) PutPolicy(ctx context.Context, ref string, document []byte) (Result[wire.PolicyUpdateResponse], error) {
	return send[wire.PolicyUpdateResponse](ctx, c, http.MethodPut,
		"/v1/networks/"+url.PathEscape(ref)+"/policy", nil, json.RawMessage(document))
}

// CheckPolicy validates a document without storing it.
//
// host is optional and is a host name or uuid. Supplying one turns this from
// "is this well-formed" into "what would web-01 actually get", which is the
// question an operator has — the response then carries the compiled rule set and
// the selector inputs it was resolved against.
func (c *Client) CheckPolicy(ctx context.Context, ref string, document []byte, host string) (Result[wire.PolicyCheckResponse], error) {
	var q url.Values
	if host != "" {
		q = url.Values{"host": {host}}
	}
	return send[wire.PolicyCheckResponse](ctx, c, http.MethodPost,
		"/v1/networks/"+url.PathEscape(ref)+"/policy/check", q, json.RawMessage(document))
}

// SetFirewallSource switches a network between per-role rules and the policy
// document.
//
// acknowledge is the typed gate. The server refuses an unacknowledged switch on a
// network with live hosts with a 409 carrying wire.FirewallSourceChangeError; see
// APIError.FirewallSourceChange for the body, which holds the part that matters
// — how many hosts have their entire rule set replaced.
//
// This needs policy:write IN ADDITION to networks:write. A token that can rename
// a network deliberately cannot replace the firewall on every host in it.
func (c *Client) SetFirewallSource(ctx context.Context, ref, source string, acknowledge bool) (Result[wire.NetworkUpdateResponse], error) {
	req := wire.UpdateNetworkRequest{
		FirewallSource:            &source,
		AcknowledgeFirewallChange: acknowledge,
	}
	return send[wire.NetworkUpdateResponse](ctx, c, http.MethodPatch,
		"/v1/networks/"+url.PathEscape(ref), nil, req)
}

// FirewallSourceChange decodes the body a 409 from a firewall-source switch
// carries. Zero value for any other error body, so a caller can ask
// unconditionally — the same shape as Lagging and BlockingHosts.
func (e *APIError) FirewallSourceChange() wire.FirewallSourceChangeError {
	var body wire.FirewallSourceChangeError
	_ = json.Unmarshal(e.Body, &body)
	return body
}
