package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/policy"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The network policy document endpoints.
//
//	GET  /v1/networks/{ref}/policy         read it
//	PUT  /v1/networks/{ref}/policy         replace it wholesale
//	POST /v1/networks/{ref}/policy/check   validate it without storing
//
// The switch that decides whether the document is in force at all lives on
// PATCH /v1/networks/{ref}; see handleUpdateNetwork.
//
// THE BODY OF PUT AND POST IS THE DOCUMENT, raw, with no envelope — see the note
// above PolicyResponse in internal/wire. That is why these three do not use
// decode(): it takes a struct and sets DisallowUnknownFields, and there is no
// struct here. readDocument does the same job for a raw body, including the same
// size cap, and then hands the bytes to policy.Validate, whose entire contract is
// to be strict and to name the fault.
//
// NO ?format=text ON THE READ, deliberately, and it was considered. The two
// routes that have one are a compatibility surface —
// scripts/check-break-glass.sh parses renderWhoAmI with sed, from cron, on a
// machine that may have neither jq nor a working overlay, and internal/api/
// convergence.go says so. A third text renderer would be a layout nobody scripts
// against and a second place to keep in sync with the JSON every time a field is
// added. `orbit policy show` renders this for a human, on the client, which is
// what cmd/orbit/output.go says the CLI does with every other response.

// store.NetworkPolicy is the enroll.PolicySource a deployment wires in, and this
// asserts it stays one.
//
// The assertion lives here rather than in either package because it cannot live
// in either: enroll imports store, so store cannot import enroll to state its own
// conformance. This package already imports both, and the alternative to a
// compile-time check is prose in two files that nothing enforces.
//
// It matters because the seam is otherwise invisible. cmd/orbitd assigns this to
// enroll.Config.Policy; if it is not assigned, a policy document is stored,
// switchable, reported as in force by every endpoint here — and rendered by
// nothing. There is no error anywhere in that. A signature drift would produce
// the same silence, so it is made a build failure instead.
var _ enroll.PolicySource = store.NetworkPolicy

// maxPolicyBytes caps a submitted document.
//
// The same 1 MiB decode() applies to every other body. A policy document is
// kilobytes — it is a set of rules, not a data set — and an unbounded read on any
// endpoint is a free denial of service even behind a token, because the read
// happens before the scope check has finished mattering.
const maxPolicyBytes = 1 << 20

// readDocument reads a raw policy document from the request body and validates
// it.
//
// Validation is policy.Validate, and the error goes back verbatim: that function
// exists to name the fault, and rewording it here would replace "outbound rule 3:
// port \"htpp\" is not a port or \"any\"" with something an operator cannot act
// on. Nebula ignores keys it does not recognise, which is why the parse is strict
// rather than lenient — the same argument nebulacfg.ValidateFirewall makes for
// per-role rules.
func readDocument(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPolicyBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read the policy document: "+err.Error())
		return nil, false
	}
	if len(raw) == 0 {
		// Named as the parameter it is, with the consequence. An empty body here
		// is not "clear the policy": there is no way to un-set one, because a
		// network in policy mode with no document renders an empty rule set and
		// nebula's firewall is default-deny.
		writeErr(w, http.StatusBadRequest,
			"the request body must be the policy document; it was empty. "+
				"There is no way to remove a policy document — switch the network's "+
				"firewall_source back to \"role\" instead")
		return nil, false
	}
	if err := policy.Validate(raw); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	return raw, true
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	var out wire.PolicyResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		net, err := s.resolveNetwork(ctx, tx, r)
		if err != nil {
			return err
		}
		p, err := tx.GetPolicy(ctx, net.ID)
		if err != nil {
			return err
		}
		out = policyResponse(net, p)
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNoPolicy) {
			// 404 with the network named, not with the generic "network not
			// found" the shared mapper would produce. The two failures have
			// opposite remedies: a bad reference is a typo, and this is a real
			// network that has simply never had a document — which is the state
			// of every network that has not opted in, and the message has to say
			// so or an operator concludes their network is missing.
			writeErr(w, http.StatusNotFound,
				"this network has no policy document; PUT one to create the first version")
			return
		}
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handlePutPolicy replaces the document wholesale.
//
// WHOLESALE, never merged, for the reason UpdateRoleRequest.Firewall replaces:
// merging makes "remove this entry" inexpressible, and an entry an operator
// believes they deleted is the worst possible outcome for a firewall. A PUT is
// also the honest verb for it — the resource is one document, and this is the
// document.
//
// The epoch advances only when the document actually changed, and the comparison
// happens in Postgres against a jsonb column, so a re-send with different key
// order or indentation is correctly nothing. store.PutPolicy explains the
// mechanism; the reason is the one SetHostRoles and UpdateRole both state, and it
// is stronger here than for either: this document governs every host in the
// network, so a no-op PUT that bumped would make the safest thing an operator
// can do — re-run a reconcile loop — the single most expensive.
//
// 200 whether or not anything changed, with `changed` in the body. Not 202: the
// change is fully in force once agents poll, because a policy is compiled into
// configuration and carries nothing in a certificate. That is the entire point of
// the policy document, and it is exactly why a group edit answers 202 and this
// does not.
func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())

	raw, ok := readDocument(w, r)
	if !ok {
		return
	}

	var (
		net    *store.Network
		change *store.PolicyChange
	)
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		net, err = s.resolveNetwork(ctx, tx, r)
		if err != nil {
			return err
		}

		change, err = tx.PutPolicy(ctx, net.ID, raw, id.Display)
		if err != nil {
			return err
		}
		if !change.Changed {
			return nil
		}
		// The network struct was read before the epoch moved, so refresh the one
		// field this response reports from it. Re-reading the whole row would
		// cost a query to learn one number PutPolicy already returned.
		net.ConfigEpoch = change.Policy.ConfigEpoch

		e := id.Audit(store.ActionPolicyUpdated, "network", net.ID.String())
		meta, merr := json.Marshal(map[string]any{
			"slug":              net.Slug,
			"version_before":    change.PreviousVersion,
			"version_after":     change.Policy.Version,
			"config_epoch":      change.Policy.ConfigEpoch,
			"firewall_source":   net.FirewallSource,
			"in_force_on_apply": net.FirewallSource == store.FirewallSourcePolicy,
		})
		if merr != nil {
			return fmt.Errorf("encode policy update audit metadata: %w", merr)
		}
		e.Meta = meta
		return tx.AppendAudit(ctx, e)
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}

	resp := wire.PolicyUpdateResponse{
		PolicyResponse:  policyResponse(net, &change.Policy),
		Changed:         change.Changed,
		PreviousVersion: change.PreviousVersion,
		Detail:          policyDetail(net, change),
	}
	// Said on the server's own log as well as in the body, because this is the
	// case an operator most often walks away from believing they are done: the
	// document is stored, the request succeeded, and nothing is enforcing it.
	if change.Changed && net.FirewallSource != store.FirewallSourcePolicy {
		s.log.Warn("policy document written to a network that does not use it",
			"network", net.Slug, "version", change.Policy.Version,
			"firewallSource", net.FirewallSource)
	}
	writeJSON(w, http.StatusOK, resp)
}

// policyDetail says what happens next, in words.
func policyDetail(net *store.Network, change *store.PolicyChange) string {
	switch {
	case !change.Changed:
		return "the submitted document is the one already stored, compared as JSON rather than " +
			"as text, so nothing was written and no agent was woken"
	case net.FirewallSource != store.FirewallSourcePolicy:
		return fmt.Sprintf(
			"version %d stored, and it is NOT in force: network %s still draws its firewall from "+
				"per-role rules. Switch it with PATCH /v1/networks/%s {\"firewall_source\":\"policy\"}",
			change.Policy.Version, net.Slug, net.Slug)
	default:
		return fmt.Sprintf(
			"version %d is in force at config epoch %d; every host in %s re-renders its firewall "+
				"on its next poll, with no certificate reissued",
			change.Policy.Version, change.Policy.ConfigEpoch, net.Slug)
	}
}

// handleCheckPolicy validates a document without storing it.
//
// This endpoint matters more than its size suggests. A policy edit is fleet-wide
// and an operator cannot see its effect before applying it — there is no staging
// network and no dry run anywhere else in this API — so this is the only place a
// typo is found before it reaches four hundred hosts. It is what `orbit policy
// check` runs, and what a CI job should run against a policy file in review.
//
// ?host=<name|uuid> scopes the check to one host and answers the question people
// actually have, which is not "is this document well-formed" but "will web-01
// still reach the database". It reports two things, and both are needed.
//
// The compiled rule set: exactly what the renderer would produce for that host,
// from the same policy.Compiler with the same fleet and the same management
// floor, so this is a dry run rather than an approximation.
//
// And the inputs the selectors were resolved against — the host's addresses,
// tags, role and groups. Those are what is actually wrong most of the time: a
// rule is far more often narrow because the host is not tagged the way its author
// assumed than because the rule is malformed. A rule set with no inputs beside it
// tells an operator that web-01 got two rules without telling them why it did not
// get the third.
//
// Compiled against the fleet AS IT IS NOW. A host enrolled after this check
// changes the answer, which is inherent to compiling selectors to addresses and
// is the same freshness every other read on this API has.
func (s *Server) handleCheckPolicy(w http.ResponseWriter, r *http.Request) {
	raw, ok := readDocument(w, r)
	if !ok {
		return
	}
	// Parsed as well as validated. Validate is the lint; the Document is what the
	// compiler is handed, and holding one is proof it is well-formed.
	doc, err := policy.Parse(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "policy document did not parse: "+err.Error())
		return
	}

	hostRef := r.URL.Query().Get("host")

	var out wire.PolicyCheckResponse
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		net, err := s.resolveNetwork(ctx, tx, r)
		if err != nil {
			return err
		}
		out = wire.PolicyCheckResponse{
			Valid:          true,
			NetworkID:      net.ID.String(),
			NetworkSlug:    net.Slug,
			FirewallSource: net.FirewallSource,
			// A network with no document yet: everything is a change, and
			// CurrentVersion stays 0 rather than being reported as a version that
			// does not exist.
			WouldChange: true,
		}

		switch current, err := tx.GetPolicy(ctx, net.ID); {
		case err == nil:
			out.CurrentVersion = current.Version
			// The same semantic comparison the write path makes, and made the same
			// way — by Postgres, over jsonb — so "would this change anything" and
			// "did this change anything" can never disagree.
			same, err := tx.PolicyMatches(ctx, net.ID, raw)
			if err != nil {
				return err
			}
			out.WouldChange = !same
		case errors.Is(err, store.ErrNoPolicy):
			// Fine, and already reflected above.
		default:
			return err
		}

		if hostRef == "" {
			return nil
		}
		host, err := resolveCheckHost(ctx, tx, net.ID, hostRef)
		if err != nil {
			return err
		}
		out.Host = host

		// The dry run. Same compiler, same fleet, same management floor as the
		// render path — a preview built from anything else is a preview of a
		// system that does not exist.
		fleet, err := tx.PolicyFleet(ctx, net.ID)
		if err != nil {
			return err
		}
		c := policy.Compiler{
			Fleet:      policy.Snapshot{Members: fleet, CIDRs: net.CIDRs},
			Management: s.managementFloor(ctx, tx, net.ID),
		}
		rs, cerr := c.Host(doc, host.ID)
		if cerr != nil {
			// A document that validates and then fails to compile is the failure
			// this endpoint exists to catch: a selector naming a host that was
			// deleted passes every syntactic check and takes the whole network's
			// render down when it is applied. It is the caller's document, so 400,
			// with the compiler's own words.
			return fmt.Errorf("%w: %s", errPolicyWouldNotCompile, cerr.Error())
		}
		out.Compiled = &wire.PolicyRuleset{
			Inbound:  ruleResponses(rs.Inbound),
			Outbound: ruleResponses(rs.Outbound),
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errPolicyCheckHostNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, errPolicyWouldNotCompile) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

var errPolicyWouldNotCompile = errors.New("policy document does not compile against this network")

// managementFloor is the control-plane reachability a compiled policy may not
// remove.
//
// Read here so the preview matches what the renderer emits. Without it a dry run
// would show two fewer rules than the host will actually get, and the two it
// omits are the ones that keep the agent API reachable — so the preview would be
// wrong in exactly the place an operator is looking when they are worried about
// locking themselves out.
//
// A failure is not fatal, matching enroll.managementEndpoints: a preview missing
// its floor is worse than one that has it and better than no answer at all.
func (s *Server) managementFloor(ctx context.Context, tx *store.Tx, networkID uuid.UUID) []policy.Endpoint {
	live, err := tx.LiveControlPlanes(ctx, networkID, time.Now().Add(-enroll.DefaultControlPlaneStaleAfter))
	if err != nil {
		s.log.Warn("could not list control planes for the policy check management floor",
			"network", networkID, "error", err)
		return nil
	}
	out := make([]policy.Endpoint, 0, len(live))
	for _, cp := range live {
		out = append(out, policy.Endpoint{Addr: cp.Addr, Port: cp.AgentPort})
	}
	return out
}

func ruleResponses(rules []policy.Rule) []wire.PolicyRule {
	out := make([]wire.PolicyRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, wire.PolicyRule{
			Proto: r.Proto, Port: r.Port, CIDR: r.CIDR, LocalCIDR: r.LocalCIDR,
		})
	}
	return out
}

var errPolicyCheckHostNotFound = errors.New("no such host in this network")

// resolveCheckHost reads the host a check was scoped to, by uuid or by name.
//
// By name as well as by uuid because the operator asking "will web-01 still reach
// the database" has the name, and making them look up a uuid first is the friction
// that stops the check from being run at all. Names are unique within a network
// (orbit.host UNIQUE (network_id, name)), so the lookup is unambiguous — which is
// not true across networks, and is why this takes a network id.
func resolveCheckHost(ctx context.Context, tx *store.Tx, networkID uuid.UUID, ref string) (*wire.PolicyCheckHost, error) {
	var (
		host *store.Host
		err  error
	)
	if hostID, perr := uuid.Parse(ref); perr == nil {
		host, err = tx.GetHost(ctx, hostID)
		if err == nil && host.NetworkID != networkID {
			// A real host, in a different network. Reported as absent rather than
			// as a mismatch, for the reason notFoundOr conflates absent and
			// forbidden: a lookup that distinguishes them confirms the existence
			// of something the caller was not shown.
			return nil, fmt.Errorf("%w: %s", errPolicyCheckHostNotFound, ref)
		}
	} else {
		host, err = tx.GetHostByName(ctx, networkID, ref)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", errPolicyCheckHostNotFound, ref)
		}
		return nil, err
	}

	out := &wire.PolicyCheckHost{
		ID: host.ID.String(), Name: host.Name, Tags: host.Tags,
		State: host.State, RoleName: host.RoleName,
	}
	for _, a := range host.Addrs {
		out.OverlayAddrs = append(out.OverlayAddrs, a.String())
	}
	if host.RoleID != nil {
		role, err := tx.GetRole(ctx, *host.RoleID)
		if err != nil {
			return nil, err
		}
		out.Groups = role.Groups
	}
	return out, nil
}

func policyResponse(net *store.Network, p *store.Policy) wire.PolicyResponse {
	return wire.PolicyResponse{
		NetworkID:      net.ID.String(),
		NetworkSlug:    net.Slug,
		Version:        p.Version,
		Document:       json.RawMessage(p.Document),
		ConfigEpoch:    p.ConfigEpoch,
		Author:         p.Author,
		CreatedAt:      p.CreatedAt,
		FirewallSource: net.FirewallSource,
	}
}
