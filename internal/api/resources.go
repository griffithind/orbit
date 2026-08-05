package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	// The agent package is imported for its renewal policy, not to run an
	// agent. When a role's groups change, the control plane has to say when
	// every host will have a certificate carrying the new set, and the only
	// honest source for that is the schedule the agent will actually follow.
	// Restating the formula here instead would let the two drift silently, and
	// the number would then be wrong in the direction that matters.
	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// ResourceRoutes registers the network, role, CA, token, and audit endpoints.
//
// Split from AdminRoutes so the host-lifecycle surface stays readable, but they
// mount on the same listener and use the same scoped tokens.
func (s *Server) ResourceRoutes(mux *http.ServeMux) { register(mux, s.resourceRoutes()) }

func (s *Server) resourceRoutes() []route {
	a := func(pattern, scope string, h http.HandlerFunc) route {
		return route{pattern: pattern, surface: surfaceAdmin, scope: scope, h: s.admin(scope, h)}
	}
	return []route{
		a("POST /v1/networks", "networks:write", s.handleCreateNetwork),
		a("GET /v1/networks", "networks:read", s.handleListNetworks),
		a("PATCH /v1/networks/{ref}", "networks:write", s.handleUpdateNetwork),
		// The CIDR to remove is a query parameter, not a path segment: a CIDR
		// contains a slash, and an encoded slash in a path is a long-standing
		// source of proxy-specific 404s.
		a("POST /v1/networks/{ref}/cidrs", "networks:write", s.handleAddNetworkCIDR),
		a("DELETE /v1/networks/{ref}/cidrs", "networks:write", s.handleRemoveNetworkCIDR),
		// {ref} is a uuid OR a name. Network names are globally unique, which
		// hosts' and roles' are not, so this is the one resource where a name
		// is an unambiguous identifier — and it removes a full listing from
		// every client that knows a network by the name its operator uses.
		a("GET /v1/networks/{ref}", "networks:read", s.handleGetNetwork),

		// The network policy document. {ref} is a uuid or a slug, resolved by the
		// same rule GET /v1/networks/{ref} uses.
		//
		// policy:read and policy:write rather than networks:*: this document is
		// the firewall for every host in the network, and a token trusted to
		// read network metadata should not reach it — the same reasoning that
		// puts the trust bundle behind cas:read. routes.go's knownScopes carries
		// the longer version.
		a("GET /v1/networks/{ref}/policy", "policy:read", s.handleGetPolicy),
		// PUT, not PATCH, and it replaces wholesale rather than merging, for the
		// reason UpdateRoleRequest.Firewall does: merging makes "remove this
		// entry" inexpressible, and an entry an operator believes they deleted is
		// the worst possible outcome for a firewall.
		a("PUT /v1/networks/{ref}/policy", "policy:write", s.handlePutPolicy),
		// Validate without storing. policy:write rather than policy:read, because
		// what it accepts is a document the caller is proposing to install — the
		// scope should match the operation being rehearsed, not the fact that
		// nothing was written this time.
		a("POST /v1/networks/{ref}/policy/check", "policy:write", s.handleCheckPolicy),
		// The bidirectional reachability answer. policy:read, not policy:write:
		// it stores nothing and proposes nothing, it reads what is already in
		// force — which is what makes it usable from an on-call token.
		a("GET /v1/networks/{ref}/reachability", "policy:read", s.handleReachability),

		a("POST /v1/roles", "roles:write", s.handleCreateRole),
		a("GET /v1/roles", "roles:read", s.handleListRoles),
		a("GET /v1/roles/{id}", "roles:read", s.handleGetRole),
		a("PATCH /v1/roles/{id}", "roles:write", s.handleUpdateRole),
		a("DELETE /v1/roles/{id}", "roles:write", s.handleDeleteRole),

		a("POST /v1/cas", "cas:write", s.handleCreateCA),
		a("GET /v1/cas", "cas:read", s.handleListCAs),
		a("POST /v1/cas/{id}/activate", "cas:write", s.handleActivateCA),
		a("POST /v1/cas/{id}/retire", "cas:write", s.handleRetireCA),

		a("POST /v1/tokens", "tokens:write", s.handleCreateToken),
		a("GET /v1/tokens", "tokens:read", s.handleListTokens),
		a("DELETE /v1/tokens/{id}", "tokens:write", s.handleRevokeToken),

		// Browser sessions are a derived credential: a session references a
		// token and holds nothing of its own, so revoking the token already
		// ends every session it opened. These scopes are the token's for that
		// reason — anyone who can do the larger thing can do the smaller one,
		// and a sessions:* pair would only be a second place to get it wrong.
		a("GET /v1/sessions", "tokens:read", s.handleListSessions),
		a("DELETE /v1/sessions/{id}", "tokens:write", s.handleRevokeSession),

		a("GET /v1/audit-logs", "audit:read", s.handleListAudit),

		// Operational reads. Four questions an operator asks during an incident,
		// each backed by a store method that already existed and was reachable
		// from nowhere — so the answers lived in psql.
		//
		// networks:read. The live blocklist is network state, in the same sense
		// convergence is, and it carries nothing a mesh member does not already
		// hold: these exact fingerprints are rendered into every host's
		// configuration on this network.
		a("GET /v1/networks/{id}/blocklist", "networks:read", s.handleBlocklist),
		// cas:read, not networks:read. This hands back CA certificates, and a
		// token trusted to read network metadata should not reach certificate
		// material through a different path — the same reasoning that keeps
		// GET /v1/cas behind cas:read.
		a("GET /v1/networks/{id}/trust-bundle", "cas:read", s.handleTrustBundle),
		// hosts:read, for the reason GET /v1/memberships/{id}/certificates uses it:
		// the response names hosts and certificates but carries no PEM and no
		// key material.
		a("GET /v1/networks/{id}/certificates/expiring", "memberships:read", s.handleExpiringCertificates),
		a("GET /v1/networks/{id}/replicas", "networks:read", s.handleReplicas),

		// No scope, and the only route allowed one. routes.go documents why,
		// and routes_test.go refuses any other scopeless admin route.
		a("GET /v1/whoami", "", s.handleWhoAmI),
	}
}

//------------------------------------------------------------------------------
// Operational reads
//------------------------------------------------------------------------------

// handleBlocklist lists what is revoked and currently being distributed.
//
// The only view of the blocklist there is. Blocking a host reports an epoch and
// nothing else, the host listing shows a state rather than a fingerprint, and
// DeleteHost removes the host row while deliberately leaving its blocklist
// entries behind — so the fingerprints belonging to decommissioned machines are
// invisible through every other endpoint, and those are the ones nobody can
// reconstruct from memory at 3am.
//
// Entries whose certificate has already expired are absent, because they are
// absent from what hosts are given: nebula rejects an expired certificate
// before it consults the blocklist, so distributing the fingerprint buys
// nothing. This endpoint answers "what is in force", not "what has ever been
// revoked" — the audit log answers that one.
func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	networkID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var out []wire.BlocklistEntryResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		// Resolve the network first purely so a mistyped id is a 404. Without
		// it an unknown network returns an empty blocklist, which reads as
		// "nothing is revoked" — the single most dangerous wrong answer this
		// endpoint could give.
		if _, err := tx.GetNetwork(ctx, networkID); err != nil {
			return err
		}

		// Fingerprints only, which is all store.LiveBlocklist returns: it exists
		// to build the agent configuration, where a fingerprint is the entire
		// payload. The reason, the epoch that introduced the entry, the expiry,
		// and the best-effort host name are columns of orbit.blocklist_entry
		// that no store method surfaces, so they are absent here rather than
		// invented. See the note in the handover: this wants a
		// LiveBlocklistEntries returning the row with a LEFT JOIN for the name.
		fps, err := tx.LiveBlocklist(ctx, networkID, time.Now())
		if err != nil {
			return err
		}
		out = make([]wire.BlocklistEntryResponse, 0, len(fps))
		for _, fp := range fps {
			out = append(out, wire.BlocklistEntryResponse{Fingerprint: fp})
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}

	// Text, for the same reason convergence has it: this is read at a terminal
	// during a revocation, and requiring jq to answer "did it land" is a tax
	// paid at the worst moment.
	if wantsPlainText(r) {
		writePlain(w, http.StatusOK, renderBlocklist(networkID.String(), out))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleTrustBundle re-exports every CA a host on this network must trust.
//
// It exists because caResponse includes the PEM only when called from the
// create handler, so a CA certificate is fetchable exactly once — and the moment
// it is wanted again is a rotation that has gone wrong, long after that response
// scrolled out of a terminal. Recovering it otherwise means psql or the signing
// host's disk.
//
// Same rule as the bundle agents receive: everything except retired. A retired
// CA is one hosts have stopped trusting, and including it here would describe a
// trust set that no host on the network actually has.
func (s *Server) handleTrustBundle(w http.ResponseWriter, r *http.Request) {
	networkID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var out wire.TrustBundleResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.GetNetwork(ctx, networkID); err != nil {
			return err
		}

		pem, err := tx.TrustBundlePEM(ctx, networkID)
		if err != nil {
			return err
		}
		cas, err := tx.ListCAs(ctx, networkID)
		if err != nil {
			return err
		}

		out = wire.TrustBundleResponse{NetworkID: networkID.String(), PEM: pem}
		for i := range cas {
			if cas[i].State == store.CARetired {
				continue
			}
			// Live certificate counts, for the reason GET /v1/cas carries them:
			// a retiring CA can be retired once this reaches zero, and that is
			// the number that says a rotation is finished. Bounded by the number
			// of CAs on a network, which is two or three even mid-rotation.
			n, err := tx.ActiveCertificateCount(ctx, cas[i].ID)
			if err != nil {
				return err
			}
			// With the PEM. Withholding the per-CA copy would protect nothing —
			// the concatenated bundle above already contains every one of them —
			// while forcing a reader who wants just the new CA to split the
			// bundle and match it back by fingerprint by hand.
			out.CAs = append(out.CAs, caResponse(&cas[i], true, n))
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}

	// CAs is newest first, as it is everywhere else; PEM is oldest first, as
	// hosts receive it. They are not positionally aligned and nothing should
	// index one by the other — match on fingerprint.
	writeJSON(w, http.StatusOK, out)
}

// expiringDefaultLimit and expiringMaxLimit bound the certificate scan.
//
// A cap rather than a cursor, because this list is a work queue and not a
// history: a network with a thousand overdue certificates has one problem, not
// a thousand, and paging through them changes no decision. The number is
// returned honestly — a response holding exactly limit rows may be truncated,
// and the text rendering says so.
const (
	expiringDefaultLimit = 100
	expiringMaxLimit     = 500
)

// handleExpiringCertificates names the certificates approaching expiry.
//
// The metrics endpoint reports how many; this reports which, and that is the
// whole difference. orbit_certificates_expiring_soon rising says renewal is
// failing somewhere, and an operator cannot act on a count.
//
// The signal is RenewAt, not NotAfter. Every host is supposed to renew at the
// midpoint of its certificate's lifetime, so a RenewAt already in the past means
// renewal has failed at least once for that host, while it still holds a
// perfectly valid certificate — hours of warning that NotAfter does not give,
// because by the time NotAfter is close the host is about to fall off the mesh.
//
// ?window shifts the horizon forward: the default of zero asks "which hosts
// should have renewed by now", and 24h asks "which will be due within a day",
// which is the shape of a report run from cron.
func (s *Server) handleExpiringCertificates(w http.ResponseWriter, r *http.Request) {
	networkID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	q := r.URL.Query()

	window, ok := expiringWindowParam(w, q)
	if !ok {
		return
	}
	limit, ok := expiringLimitParam(w, q)
	if !ok {
		return
	}

	var out []wire.ExpiringCertificateResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.GetNetwork(ctx, networkID); err != nil {
			return err
		}

		// Shifting "now" forward is what turns "already due" into "due within
		// window": the store's predicate is now >= the midpoint, so a horizon
		// in the future selects everything that will have crossed it by then.
		certs, err := tx.CertificatesDueForRenewal(ctx, networkID, time.Now().Add(window), limit)
		if err != nil {
			return err
		}

		out = make([]wire.ExpiringCertificateResponse, 0, len(certs))
		for _, c := range certs {
			e := wire.ExpiringCertificateResponse{
				MembershipID: c.MembershipID.String(),
				Fingerprint:  c.Fingerprint,
				NotAfter:     c.NotAfter.Format(time.RFC3339),
				RenewAt:      c.RenewAt().Format(time.RFC3339),
			}

			// One lookup per certificate. Acceptable only because limit bounds
			// it: a name and a last-seen are the two things that make this list
			// actionable, and a host id alone sends the reader back to another
			// endpoint for every row. The right fix is for the store query to
			// return them — it already joins orbit.membership to filter on state.
			host, err := tx.GetHost(ctx, c.MembershipID)
			if err != nil {
				return err
			}
			e.MembershipName = host.Name
			if host.LastSeenAt != nil {
				e.LastSeenAt = host.LastSeenAt.Format(time.RFC3339)
			}
			out = append(out, e)
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}

	if wantsPlainText(r) {
		writePlain(w, http.StatusOK, renderExpiring(out, window, limit, time.Now()))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// expiringWindowParam parses ?window, defaulting to zero: due now.
func expiringWindowParam(w http.ResponseWriter, q url.Values) (time.Duration, bool) {
	v := q.Get("window")
	if v == "" {
		return 0, true
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		writeErr(w, http.StatusBadRequest,
			"window must be a duration, e.g. \"24h\"; omit it to list certificates already due")
		return 0, false
	}
	if d < 0 {
		// Refused rather than quietly reinterpreted. A negative window would
		// narrow to "overdue by at least this long", which is a different
		// question with a different answer, and guessing which one was meant is
		// how a reader concludes a fleet is healthy.
		writeErr(w, http.StatusBadRequest,
			"window cannot be negative: it extends the horizon forward from now. "+
				"Omit it to list certificates that are already due")
		return 0, false
	}
	return d, true
}

// expiringLimitParam parses ?limit.
func expiringLimitParam(w http.ResponseWriter, q url.Values) (int, bool) {
	v := q.Get("limit")
	if v == "" {
		return expiringDefaultLimit, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
		return 0, false
	}
	if n > expiringMaxLimit {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(
			"limit must be %d or fewer; this list is a work queue, and a network with "+
				"more overdue certificates than that has one problem rather than %d",
			expiringMaxLimit, n))
		return 0, false
	}
	return n, true
}

// handleReplicas lists the control planes currently serving this network.
//
// Answers "who is actually up", which nothing else does. A replica appears here
// by heartbeating (store.RegisterControlPlane) and disappears by going quiet, so
// this is measured rather than configured — the same list, built the same way
// from the same staleness bound, that agents are handed as
// EnrollResponse.AgentEndpoints. Reusing enroll.DefaultControlPlaneStaleAfter
// rather than picking a number here is the point: an operator asking which
// replicas are live must get the answer the fleet is acting on, not a second
// opinion that disagrees at the margin.
func (s *Server) handleReplicas(w http.ResponseWriter, r *http.Request) {
	networkID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var out []wire.ControlPlaneResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.GetNetwork(ctx, networkID); err != nil {
			return err
		}

		live, err := tx.LiveControlPlanes(ctx, networkID,
			time.Now().Add(-enroll.DefaultControlPlaneStaleAfter))
		if err != nil {
			return err
		}
		out = make([]wire.ControlPlaneResponse, 0, len(live))
		for _, cp := range live {
			out = append(out, wire.ControlPlaneResponse{
				MembershipID: cp.MembershipID.String(),
				Addr:         cp.Addr.String(),
				AgentPort:    cp.AgentPort,
				LastSeenAt:   cp.LastSeenAt.Format(time.RFC3339),
			})
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// renderBlocklist formats the live blocklist for a terminal.
//
// An empty list is stated in words rather than left as blank output, because
// "nothing is revoked on this network" and "the command produced no output" are
// the same thing on a terminal and mean opposite things during an incident.
func renderBlocklist(networkID string, entries []wire.BlocklistEntryResponse) string {
	var b strings.Builder
	fmt.Fprintf(&b, "network  %s\n", networkID)

	if len(entries) == 0 {
		b.WriteString("\nnothing is revoked on this network\n")
		return b.String()
	}

	fmt.Fprintf(&b, "revoked  %d fingerprint(s) distributed to every host\n\n", len(entries))
	for _, e := range entries {
		fmt.Fprintf(&b, "  %s", e.Fingerprint)
		if e.MembershipName != "" {
			fmt.Fprintf(&b, "  %s", e.MembershipName)
		}
		b.WriteString("\n")
	}

	// Say what the list does not cover. An entry drops off here the moment its
	// certificate expires, which is correct — nebula rejects an expired
	// certificate before consulting the blocklist — but a reader who does not
	// know that will read a shrinking list as revocations being undone.
	b.WriteString("\nentries disappear once the revoked certificate expires; " +
		"the audit log holds the full history\n")
	return b.String()
}

// renderExpiring formats the renewal backlog for a terminal.
func renderExpiring(certs []wire.ExpiringCertificateResponse, window time.Duration, limit int, now time.Time) string {
	var b strings.Builder

	horizon := "now"
	if window > 0 {
		horizon = "within " + window.String()
	}
	fmt.Fprintf(&b, "due %s\n", horizon)

	if len(certs) == 0 {
		b.WriteString("\nevery certificate on this network is renewing on schedule\n")
		return b.String()
	}

	fmt.Fprintf(&b, "\n%d certificate(s):\n", len(certs))
	fmt.Fprintf(&b, "  %-28s %-14s %-22s %s\n", "HOST", "RENEW", "EXPIRES", "LAST SEEN")

	overdue := 0
	for _, c := range certs {
		renew := c.RenewAt
		if at, err := time.Parse(time.RFC3339, c.RenewAt); err == nil {
			if at.Before(now) {
				overdue++
				renew = ago(now.Sub(at)) + " ago"
			} else {
				renew = "in " + now.Sub(at).Abs().Round(time.Minute).String()
			}
		}
		// "never" rather than a blank column: a host that has never reported has
		// a different problem from one that reported an hour ago, and an empty
		// cell reads as a rendering glitch.
		seen := "never"
		if c.LastSeenAt != "" {
			if at, err := time.Parse(time.RFC3339, c.LastSeenAt); err == nil {
				seen = ago(now.Sub(at)) + " ago"
			}
		}
		fmt.Fprintf(&b, "  %-28s %-14s %-22s %s\n",
			truncate(c.MembershipName, 28), renew, c.NotAfter, seen)
	}

	if overdue > 0 {
		// The consequence, not just the count. A host past its renewal point is
		// one whose agent is already failing to renew, and it loses the mesh at
		// NotAfter unless something changes before then.
		fmt.Fprintf(&b, "\n%d host(s) are past their renewal point: their agents have already "+
			"failed to renew at least once, and each falls off the mesh at its expiry\n", overdue)
	}
	if len(certs) == limit {
		fmt.Fprintf(&b, "\nexactly %d rows, the current limit — there may be more; "+
			"raise it with ?limit= (max %d)\n", limit, expiringMaxLimit)
	}
	return b.String()
}

// ago renders a duration for a terminal, rounded to something a human reads at
// a glance rather than to the second.
func ago(d time.Duration) string {
	if d >= time.Hour {
		return d.Round(time.Minute).String()
	}
	return d.Round(time.Second).String()
}

// handleWhoAmI reports which credential is being used, and never its value.
//
// Two callers. An operator with several tokens in several shells, and the
// break-glass check in deployment.md 5 — which needs to distinguish "this token
// still authenticates" from "this token still holds the scopes it was minted
// with". A plain 200 from any other endpoint conflates those, because a token
// that lost its scopes returns 403 while a revoked one returns 401.
func (s *Server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())

	resp := wire.WhoAmIResponse{
		Kind: id.Kind, ID: id.Subject, Name: id.Display,
		Scopes:   id.Scopes,
		Unscoped: id.HasScope("*"),
	}
	if id.ExpiresAt != nil {
		resp.ExpiresAt = id.ExpiresAt.Format(time.RFC3339)
		days := int(time.Until(*id.ExpiresAt).Hours() / 24)
		resp.ExpiresInDays = &days
	}

	if wantsPlainText(r) {
		writePlain(w, http.StatusOK, renderWhoAmI(&resp))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())

	var req wire.CreateNetworkRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || len(req.CIDRs) == 0 {
		writeErr(w, http.StatusBadRequest, "name and at least one cidr are required")
		return
	}

	cidrs := make([]netip.Prefix, 0, len(req.CIDRs))
	for _, c := range req.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("cidr %q: %v", c, err))
			return
		}
		cidrs = append(cidrs, p)
	}

	ttl := 24 * time.Hour
	if req.CertTTL != "" {
		d, err := time.ParseDuration(req.CertTTL)
		if err != nil || d <= 0 {
			writeErr(w, http.StatusBadRequest, "cert_ttl must be a positive duration, e.g. \"24h\"")
			return
		}
		ttl = d
	}

	// The network's identity key, and the ID that commits to it.
	//
	// Generated here and sealed inside the same transaction as the network row
	// below: a key stored by a transaction that then rolled back would be
	// ciphertext nothing references, and a network stored without its key would
	// be a network nothing can join.
	if s.cfg.SealNetworkIdentity == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"this server cannot create a network: every network needs an identity key, "+
				"and this server has no key vault to put one in")
		return
	}
	identityPub, identityPriv, err := ca.GenerateNetworkIdentity()
	if err != nil {
		s.log.Error("could not generate a network identity key", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not create the network")
		return
	}

	net := store.Network{
		Name:              req.Name,
		CIDRs:             cidrs,
		CertTTL:           ttl,
		Curve:             cert.Curve_CURVE25519.String(),
		CertVer:           2,
		IdentityPublicKey: identityPub,
	}
	if req.Curve != "" {
		if req.Curve != "CURVE25519" && req.Curve != "P256" {
			writeErr(w, http.StatusBadRequest, "curve must be CURVE25519 or P256")
			return
		}
		net.Curve = req.Curve
	}
	if req.CertVersion != 0 {
		if req.CertVersion != 1 && req.CertVersion != 2 {
			writeErr(w, http.StatusBadRequest, "cert_version must be 1 or 2")
			return
		}
		net.CertVer = int16(req.CertVersion)
	}

	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		ref, err := s.cfg.SealNetworkIdentity(ctx, tx, ca.MarshalNetworkIdentityPEM(identityPriv))
		if err != nil {
			return err
		}
		net.IdentitySignerRef = ref
		if err := tx.CreateNetwork(ctx, &net); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionNetworkCreated, "network", net.ID.String()))
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusCreated, networkResponse(&net))
}

// handleGetNetwork resolves one network by uuid or by name.
//
// Both, in one route, because a caller usually has whichever of the two a human
// gave it and should not have to care which. The database refuses a network
// name shaped like a uuid (migration 0005), so trying uuid.Parse first cannot
// shadow a name.
func (s *Server) handleGetNetwork(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if ref == "" {
		writeErr(w, http.StatusBadRequest, "a network id or name is required")
		return
	}

	var out wire.NetworkResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var (
			net *store.Network
			err error
		)
		if id, perr := uuid.Parse(ref); perr == nil {
			net, err = tx.GetNetwork(ctx, id)
		} else {
			// By slug, not by name. A network is addressed by id or slug and by
			// nothing else, both immutable — resolving a mutable string is how a
			// rename silently retargets a script at a different network.
			net, err = tx.GetNetworkBySlug(ctx, ref)
		}
		if err != nil {
			return err
		}
		out = networkResponse(net)
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	var out []wire.NetworkResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		nets, err := tx.ListNetworks(ctx)
		if err != nil {
			return err
		}
		out = make([]wire.NetworkResponse, 0, len(nets))
		for i := range nets {
			out = append(out, networkResponse(&nets[i]))
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())

	var req wire.CreateRoleRequest
	if !decode(w, r, &req) {
		return
	}
	networkID, err := uuid.Parse(req.NetworkID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid network_id")
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}

	// Validate before storing. Nebula ignores keys it does not recognise, so a
	// typo'd rule silently becomes a different rule; rejecting it here is the
	// difference between an error message and a quiet change in posture across
	// every host carrying this role.
	if err := nebulacfg.ValidateFirewall(req.Firewall); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	role := store.Role{
		NetworkID:     networkID,
		Name:          req.Name,
		Groups:        req.Groups,
		FirewallRules: req.Firewall,
	}
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		if err := checkFirewallSource(ctx, tx, networkID, len(req.Firewall) > 0); err != nil {
			return err
		}
		if err := checkGroupsAgainstCA(ctx, tx, networkID, role.Groups); err != nil {
			return err
		}
		if err := tx.CreateRole(ctx, &role); err != nil {
			return err
		}
		// A role changes what every host carrying it may do, so it advances the
		// config epoch and every affected agent picks it up on the next push.
		if _, err := tx.BumpEpoch(ctx, networkID, store.EpochConfig); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionRoleCreated, "role", role.ID.String()))
	})
	if err != nil {
		if errors.Is(err, ca.ErrGroupNotInCA) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, errRoleFirewallNotInForce) {
			// 409, not 400. The request is well-formed and would be accepted on
			// this same network tomorrow; what refuses it is the network's
			// current posture, which is the distinction CA activation's 409 draws
			// too.
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusCreated, roleResponse(&role))
}

// checkGroupsAgainstCA refuses groups the signing CA will not certify.
//
// Groups must be a subset of the active CA's, or issuance fails later with a
// constraint error that names the certificate rather than the role. Check while
// the operator is still looking at the role — and on every path that can write
// groups, since a role created legally and then edited illegally fails just as
// confusingly.
func checkGroupsAgainstCA(ctx context.Context, tx *store.Tx, networkID uuid.UUID, groups []string) error {
	if len(groups) == 0 {
		return nil
	}
	caRow, err := tx.GetActiveCA(ctx, networkID)
	if err != nil {
		return err
	}
	caCert, _, perr := cert.UnmarshalCertificateFromPEM([]byte(caRow.CertPEM))
	if perr != nil {
		return fmt.Errorf("parse active CA: %w", perr)
	}
	// An unconstrained CA permits anything. The API refuses to create one
	// (handleCreateCA), but one may predate that rule.
	allowed := caCert.Groups()
	if len(allowed) == 0 {
		return nil
	}
	for _, g := range groups {
		if !containsStr(allowed, g) {
			return fmt.Errorf("%w: group %q is not permitted by CA %q (allows %v)",
				ca.ErrGroupNotInCA, g, caRow.Name, allowed)
		}
	}
	return nil
}

// errRoleFirewallNotInForce is returned when a role's firewall rules are written
// to a network that draws its firewall from the policy document.
var errRoleFirewallNotInForce = errors.New("this network's firewall comes from its policy document")

// checkFirewallSource refuses per-role firewall rules on a network in policy
// mode.
//
// A REFUSAL RATHER THAN A WARNING, and that is the whole point. In policy mode
// nothing renders role.firewall_rules, so accepting the write would store rules
// that take effect nowhere, report 200, advance the epoch, and leave an operator
// certain they have opened a port. "A rule an operator believes they added that
// does nothing" is the exact dual of the failure that makes UpdateRoleRequest
// replace rather than merge, and it deserves the same treatment.
//
// Only when firewall rules are actually supplied. Roles are NOT obsolete in
// policy mode — they still carry `groups`, groups still go into the signed
// certificate, and the CA still constrains them — so creating or editing a role
// without touching its firewall stays entirely legal.
//
// The rules already stored on a role are left alone, here and everywhere else: a
// switch is meant to be reversible, and destroying the configuration being
// switched away from makes it not.
func checkFirewallSource(ctx context.Context, tx *store.Tx, networkID uuid.UUID, writesFirewall bool) error {
	if !writesFirewall {
		return nil
	}
	net, err := tx.GetNetwork(ctx, networkID)
	if err != nil {
		return err
	}
	if net.FirewallSource != store.FirewallSourcePolicy {
		return nil
	}
	return fmt.Errorf("%w: network %s draws its firewall from the policy document, "+
		"so rules written here would be stored and enforced nowhere. "+
		"Edit the policy document (PUT /v1/networks/%s/policy), or switch the network back "+
		"to firewall_source \"role\" first",
		errRoleFirewallNotInForce, net.Slug, net.Slug)
}

func (s *Server) handleGetRole(w http.ResponseWriter, r *http.Request) {
	roleID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var role *store.Role
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		role, err = tx.GetRole(ctx, roleID)
		return err
	})
	if err != nil {
		s.notFoundOr(w, err, "role")
		return
	}
	writeJSON(w, http.StatusOK, roleResponse(role))
}

// handleUpdateRole edits a role in place.
//
// Sibling of handleCreateRole, and runs the same two checks for the same
// reasons: firewall rules are validated strictly because nebula silently
// ignores keys it does not recognise, and groups are checked against the
// signing CA because otherwise issuance fails later with a certificate error
// that names nothing an operator can act on.
//
// Two things are specific to editing.
//
// The epoch advances only when something actually changed. store.UpdateRole
// decides that, comparing firewall_rules as jsonb so a re-send with different
// key order is correctly nothing. A no-op PATCH must not wake every agent on
// the network to re-render a fragment identical to the one it is already
// running, or re-running a reconcile loop becomes fleet-wide work.
//
// And a change to `groups` is reported differently from a change to anything
// else, because it costs something entirely different. Firewall rules are
// configuration: they reach every host on the next poll and converge in
// seconds. Groups are embedded in the signed certificate, so every host
// carrying this role keeps the old set until it renews — at the midpoint of
// its own certificate's lifetime, hours away on a day-long certificate, and
// nothing here can pull that forward (see the note on RenewAfter below).
//
// So a group change answers 202 rather than 200, with the number of hosts still
// holding stale certificates and the instant the last of them renews, and it is
// audited under its own action. 202 is not decoration: "accepted, processing
// not complete" is literally the state of the system, and it is the one signal
// a caller that checks the status code and ignores the body cannot miss. The
// alternative shapes were considered and are worse with the request type as it
// stands — refusing group edits outright leaves them with no supported path at
// all, and the create-a-second-role workaround has exactly the same
// certificate lag, since reassigning a host's role does not reissue anything
// either.
func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	roleID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var req wire.UpdateRoleRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Name == nil && req.Groups == nil && req.Firewall == nil {
		writeErr(w, http.StatusBadRequest,
			"no fields supplied; set name, groups, or firewall")
		return
	}
	if req.Name != nil && *req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name cannot be empty")
		return
	}
	if req.Firewall != nil {
		if err := nebulacfg.ValidateFirewall(*req.Firewall); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	upd := store.RoleUpdate{Name: req.Name, Groups: req.Groups}
	if req.Firewall != nil {
		raw := []byte(*req.Firewall)
		upd.Firewall = &raw
	}

	var (
		change *store.RoleChange
		lag    certificateLag
	)
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		role, err := tx.GetRole(ctx, roleID)
		if err != nil {
			return err
		}
		if err := checkFirewallSource(ctx, tx, role.NetworkID, req.Firewall != nil); err != nil {
			return err
		}
		if req.Groups != nil {
			if err := checkGroupsAgainstCA(ctx, tx, role.NetworkID, *req.Groups); err != nil {
				return err
			}
		}

		change, err = tx.UpdateRole(ctx, roleID, upd)
		if err != nil {
			return err
		}
		if !change.Changed {
			return nil
		}

		if change.GroupsChanged {
			hosts, err := tx.RoleHosts(ctx, roleID)
			if err != nil {
				return err
			}
			lag = certificateLagFor(hosts, time.Now())
		}

		// The role changed what every host carrying it may do, so it advances
		// the config epoch and every affected agent picks it up on the next
		// push — the firewall part of it, at least.
		if _, err := tx.BumpEpoch(ctx, role.NetworkID, store.EpochConfig); err != nil {
			return err
		}

		// A group change is audited under its own action rather than as one
		// more role.updated, for the same reason ca.force_activated is not
		// ca.activated: it is the entry an incident review needs to find with a
		// WHERE clause, and the one that explains why a host was still trusted
		// hours after policy said it should not be.
		e := id.Audit(store.ActionRoleUpdated, "role", roleID.String())
		if change.GroupsChanged {
			e.Action = store.ActionRoleGroupsChanged
			meta, merr := json.Marshal(map[string]any{
				"groups_before":              change.Before.Groups,
				"groups_after":               change.After.Groups,
				"hosts_awaiting_certificate": lag.Memberships,
				"certificates_converge_by":   lag.formatted(),
			})
			if merr != nil {
				return fmt.Errorf("encode role update audit metadata: %w", merr)
			}
			e.Meta = meta
		}
		return tx.AppendAudit(ctx, e)
	})
	if err != nil {
		if errors.Is(err, ca.ErrGroupNotInCA) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, errRoleFirewallNotInForce) {
			// 409, not 400. The request is well-formed and would be accepted on
			// this same network tomorrow; what refuses it is the network's
			// current posture, which is the distinction CA activation's 409 draws
			// too.
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		s.notFoundOr(w, err, "role")
		return
	}

	resp := wire.RoleUpdateResponse{
		RoleResponse: roleResponse(&change.After),
		Changed:      change.Changed,
	}
	if !change.GroupsChanged {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	s.log.Warn("role groups changed; hosts keep the old groups until they renew",
		"role", roleID, "hosts", lag.Memberships, "convergeBy", lag.formatted())

	resp.GroupsChanged = true
	resp.MembershipsAwaitingCertificate = lag.Memberships
	resp.CertificatesConvergeBy = lag.formatted()
	resp.Detail = lag.detail()
	writeJSON(w, http.StatusAccepted, resp)
}

// certificateLag is how far behind a role's hosts are after a group change.
type certificateLag struct {
	// Memberships is how many are still presenting a certificate with the old
	// groups. Memberships that have never enrolled are excluded: they have no stale
	// certificate, and will be issued the new groups the first time they ask.
	Memberships int

	// ConvergeBy is when the last of them renews. Zero when Memberships is zero.
	ConvergeBy time.Time
}

// certificateLagFor computes when a group change will actually be in force.
//
// Not an estimate. Each agent's renewal instant is the midpoint of its
// certificate's lifetime offset by a jitter derived from a SHA-256 of its host
// id — deterministic, not random (agent.RenewalPolicy.RenewAt explains why), so
// the same policy the agent will apply, applied here to the certificate rows we
// already hold, yields the exact instant. The default policy is what
// the agent runs; a fleet running a custom one will differ, which is the one
// assumption in this number.
//
// It is a ceiling in the sense that matters: an agent may renew EARLIER, if the
// control plane pulls it forward or the maintenance sweep gets there first, but
// nothing schedules it later.
func certificateLagFor(hosts []store.RoleHost, now time.Time) certificateLag {
	policy := agent.DefaultRenewalPolicy()

	var lag certificateLag
	for _, h := range hosts {
		if h.CertNotAfter.IsZero() {
			continue // never enrolled; nothing stale to replace
		}
		if h.State != store.MembershipEnrolled && h.State != store.MembershipActive {
			continue // suspended or deleted; not renewing, and not on the mesh
		}
		lag.Memberships++

		at := policy.RenewAt(h.CertNotBefore, h.CertNotAfter, h.ID.String())
		if at.Before(now) {
			at = now // already due; it converges as soon as the agent polls
		}
		if at.After(lag.ConvergeBy) {
			lag.ConvergeBy = at
		}
	}
	return lag
}

func (l certificateLag) formatted() string {
	if l.ConvergeBy.IsZero() {
		return ""
	}
	return l.ConvergeBy.UTC().Format(time.RFC3339)
}

func (l certificateLag) detail() string {
	if l.Memberships == 0 {
		return "firewall and configuration changes are live; no host currently holds a certificate for this role"
	}
	return fmt.Sprintf(
		"firewall and configuration changes are live, but groups are carried in the signed certificate: "+
			"%d host(s) keep the previous groups until they renew, the last by %s. "+
			"Revoke a host's certificate to force it sooner",
		l.Memberships, l.formatted())
}

// handleDeleteRole removes a role no host carries.
//
// It exists rather than not because the database makes the dangerous case
// impossible: host.role_id is ON DELETE RESTRICT, so a role in use cannot be
// deleted however this endpoint is called. What the endpoint adds is the
// answer to the only question an operator has when it is refused — which hosts
// — because a bare 409 leaves them scanning a host list by hand, and because
// the raw database error would surface through mapErr as a 404 claiming the
// role does not exist.
func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	roleID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var carriers []store.RoleHost
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.GetRole(ctx, roleID); err != nil {
			return err
		}
		var err error
		carriers, err = tx.RoleHosts(ctx, roleID)
		if err != nil {
			return err
		}
		if err := tx.DeleteRole(ctx, roleID); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionRoleDeleted, "role", roleID.String()))
	})
	if err != nil {
		if errors.Is(err, store.ErrRoleInUse) {
			hosts := make([]wire.RoleHost, 0, len(carriers))
			for _, h := range carriers {
				hosts = append(hosts, wire.RoleHost{ID: h.ID.String(), Name: h.Name})
			}
			// 409, not 400: the request is well-formed, the system is not in a
			// state that permits it. The carriers are in the body because
			// "still in use" without naming who is not actionable — which is
			// also why this is a declared type rather than an inline map. It is
			// the useful half of the answer, and a client cannot decode a shape
			// nothing declares.
			writeJSON(w, http.StatusConflict, wire.RoleInUseError{
				Error: "role is still assigned to hosts; reassign them first. " +
					"Deleting it would change the firewall on every one of them at once",
				Memberships: hosts,
			})
			return
		}
		s.notFoundOr(w, err, "role")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	networkID, err := uuid.Parse(r.URL.Query().Get("network_id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "network_id query parameter is required")
		return
	}

	var out []wire.RoleResponse
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		roles, err := tx.ListRoles(ctx, networkID)
		if err != nil {
			return err
		}
		out = make([]wire.RoleResponse, 0, len(roles))
		for i := range roles {
			out = append(out, roleResponse(&roles[i]))
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateCA(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())

	var req wire.CreateCARequest
	if !decode(w, r, &req) {
		return
	}
	networkID, err := uuid.Parse(req.NetworkID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid network_id")
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	// Nebula has no intermediate CAs, so a CA's constraints are the only thing
	// bounding what a compromised signing path can mint. An unconstrained CA is
	// a mesh-wide backdoor and the API will not create one.
	if len(req.Networks) == 0 {
		writeErr(w, http.StatusBadRequest,
			"networks is required: an unconstrained CA can mint any identity in the mesh")
		return
	}

	days := req.Days
	if days <= 0 {
		days = 90
	}
	networks := make([]netip.Prefix, 0, len(req.Networks))
	for _, n := range req.Networks {
		p, perr := netip.ParsePrefix(n)
		if perr != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("networks %q: %v", n, perr))
			return
		}
		networks = append(networks, p)
	}

	if s.cfg.SealCAKey == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"this server has no key vault, so it cannot create a certificate authority")
		return
	}

	// The key is GENERATED HERE, not supplied.
	//
	// This endpoint used to take a `signer_ref`, which meant an operator placed
	// a key file somewhere and passed its path — the caller chose the custody,
	// and rotation had a manual step that could be got wrong silently. Now the
	// control plane makes the keypair and seals it in the vault, so a rotation
	// is one API call and the key never exists outside it.
	//
	// The curve comes from the network, not the request: nebula refuses a
	// certificate whose curve differs from its signer's, so a CA on the wrong
	// curve is one that can never sign for its own network.
	var net *store.Network
	if err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		net, err = tx.GetNetwork(ctx, networkID)
		return err
	}); err != nil {
		s.notFoundOr(w, err, "network")
		return
	}
	curve, err := ca.ParseCurve(net.Curve)
	if err != nil {
		s.log.Error("network has an unparseable curve", "network", networkID, "curve", net.Curve)
		writeErr(w, http.StatusInternalServerError, "could not create certificate authority")
		return
	}
	caPub, caPriv, err := ca.GenerateCAKey(curve)
	if err != nil {
		s.log.Error("generate CA key failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not create certificate authority")
		return
	}
	signer := ca.NewMemorySigner(curve, caPub, caPriv)
	defer signer.Close()

	now := time.Now()
	caCert, err := ca.CreateCA(r.Context(), signer, ca.CAParams{
		Name:      req.Name,
		Networks:  networks,
		Groups:    req.Groups,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.AddDate(0, 0, days),
	})
	if err != nil {
		s.log.Error("create CA failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not create certificate authority")
		return
	}
	pem, _ := caCert.MarshalPEM()
	fingerprint, _ := caCert.Fingerprint()

	row := store.CA{
		NetworkID: networkID, Name: req.Name, Fingerprint: fingerprint,
		CertPEM: string(pem), Curve: signer.Curve().String(),
		NotBefore: caCert.NotBefore(), NotAfter: caCert.NotAfter(),
	}
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		// Sealed in the same transaction as the row that references it: a key
		// stored by a transaction that rolled back is ciphertext nothing points
		// at, and a CA row without its key is one that can never sign.
		ref, err := s.cfg.SealCAKey(ctx, tx, networkID,
			cert.MarshalSigningPrivateKeyToPEM(curve, caPriv))
		if err != nil {
			return err
		}
		row.SignerRef = ref
		if err := tx.CreateCA(ctx, &row); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionCACreated, "ca", row.ID.String()))
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}

	// Created pending, not active. A CA must be published into every host's
	// trust bundle and converged before it starts signing, or promoting it
	// partitions off every host that has not caught up.
	writeJSON(w, http.StatusCreated, caResponse(&row, true, 0))
}

func (s *Server) handleListCAs(w http.ResponseWriter, r *http.Request) {
	networkID, err := uuid.Parse(r.URL.Query().Get("network_id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "network_id query parameter is required")
		return
	}

	var out []wire.CAResponse
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		cas, err := tx.ListCAs(ctx, networkID)
		if err != nil {
			return err
		}
		out = make([]wire.CAResponse, 0, len(cas))
		for i := range cas {
			// Usage per CA is what tells an operator a rotation is finished:
			// a retiring CA with zero live certificates can be retired.
			n, err := tx.ActiveCertificateCount(ctx, cas[i].ID)
			if err != nil {
				return err
			}
			out = append(out, caResponse(&cas[i], false, n))
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleActivateCA promotes a CA to signing.
//
// Gated on convergence. A CA reaches every trust bundle as soon as it is
// created (pending), so by the time an operator promotes it every host should
// already trust it. Promoting before that is what partitions a fleet: the
// straggler does not trust the new CA, and its next certificate will be signed
// by it.
//
// The gate is here rather than in the store so the emergency path can override
// it. After a signing-key compromise, cutting off unconverged hosts is the
// lesser harm — but it must be deliberate, and it is audited as a different
// action.
func (s *Server) handleActivateCA(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	caID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	// An empty body is the common case: activation with no override.
	var req wire.ActivateCARequest
	if r.ContentLength > 0 {
		if !decode(w, r, &req) {
			return
		}
	}

	var (
		row     *store.CA
		lagging []wire.LaggingHost
	)
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		row, err = tx.GetCA(ctx, caID)
		if err != nil {
			return err
		}
		if row.State == store.CAActive {
			return nil // idempotent
		}

		conv, err := tx.Convergence(ctx, row.NetworkID, 20)
		if err != nil {
			return err
		}
		if conv.ConfigApplied < conv.MembershipsTotal && !req.AcknowledgeCutoff {
			for _, l := range conv.Lagging {
				lagging = append(lagging, wire.LaggingHost{
					MembershipID: l.MembershipID.String(), Name: l.Name,
					AppliedConfigEpoch:    l.AppliedConfigEpoch,
					AppliedBlocklistEpoch: l.AppliedBlocklistEpoch,
					LastSeenAt:            l.LastSeenAt,
				})
			}
			return errNotConverged
		}

		if err := tx.ActivateCA(ctx, row.NetworkID, caID); err != nil {
			return err
		}

		action := store.ActionCAActivated
		meta := []byte(`{}`)
		if conv.ConfigApplied < conv.MembershipsTotal {
			action = store.ActionCAForceActivated
			meta = []byte(fmt.Sprintf(`{"hosts_cut_off":%d,"hosts_total":%d}`,
				conv.MembershipsTotal-conv.ConfigApplied, conv.MembershipsTotal))
			s.log.Warn("CA activated before convergence; unconverged hosts are cut off",
				"ca", caID, "network", row.NetworkID,
				"cutOff", conv.MembershipsTotal-conv.ConfigApplied, "total", conv.MembershipsTotal)
		}
		e := id.Audit(action, "ca", caID.String())
		e.Meta = meta
		return tx.AppendAudit(ctx, e)
	})
	if err != nil {
		if errors.Is(err, errNotConverged) {
			// 409, not 400: the request is well-formed, the system is not ready.
			// The lagging hosts are in the body because "not converged" without
			// naming who is not actionable.
			writeJSON(w, http.StatusConflict, wire.LaggingHostsError{
				Error: "hosts have not yet applied this CA; promoting now would cut them off. " +
					"Retry once they converge, or resend with acknowledge_cutoff to proceed anyway",
				Lagging: lagging,
			})
			return
		}
		s.notFoundOr(w, err, "certificate authority")
		return
	}

	row.State = store.CAActive
	writeJSON(w, http.StatusOK, caResponse(row, false, 0))
}

var errNotConverged = errors.New("network has not converged on this CA")

// handleRetireCA completes a rotation by dropping a CA from distribution.
func (s *Server) handleRetireCA(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	caID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var row *store.CA
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		row, err = tx.GetCA(ctx, caID)
		if err != nil {
			return err
		}
		if err := tx.RetireCA(ctx, caID); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionCARetired, "ca", caID.String()))
	})
	if err != nil {
		if errors.Is(err, store.ErrCAInUse) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		s.notFoundOr(w, err, "certificate authority")
		return
	}

	row.State = store.CARetired
	writeJSON(w, http.StatusOK, caResponse(row, false, 0))
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())

	var req wire.CreateTokenRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || len(req.Scopes) == 0 {
		writeErr(w, http.StatusBadRequest, "name and at least one scope are required")
		return
	}

	plaintext, hash, err := store.NewAPIToken()
	if err != nil {
		s.log.Error("token generation failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	var expiresAt *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresInDays)
		expiresAt = &t
	}

	var tokenID uuid.UUID
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		tokenID, err = tx.CreateAPIToken(ctx, req.Name, hash, req.Scopes, expiresAt)
		if err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionTokenCreated, "token", tokenID.String()))
	})
	if err != nil {
		s.notFoundOr(w, err, "token")
		return
	}

	resp := wire.TokenResponse{
		ID: tokenID.String(), Token: plaintext, Name: req.Name, Scopes: req.Scopes,
	}
	if expiresAt != nil {
		resp.ExpiresAt = expiresAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	var out []wire.TokenResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		toks, err := tx.ListAPITokens(ctx)
		if err != nil {
			return err
		}
		out = make([]wire.TokenResponse, 0, len(toks))
		for _, t := range toks {
			// No Token field. The plaintext existed only in the response that
			// created it and is not recoverable from here — which is the point
			// of storing a hash.
			out = append(out, wire.TokenResponse{
				ID: t.ID.String(), Name: t.Name, Scopes: t.Scopes,
				CreatedAt:  t.CreatedAt.Format(time.RFC3339),
				ExpiresAt:  formatTime(t.ExpiresAt),
				LastUsedAt: formatTime(t.LastUsedAt),
				RevokedAt:  formatTime(t.RevokedAt),
			})
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "tokens")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRevokeToken makes a token unusable from the next request onward.
//
// Revoking the token that authorized this request is allowed. It is what
// rotating a credential looks like from the last step's point of view, and
// refusing it would mean the most privileged token is the one you cannot
// retire. The audit entry records the actor, so a self-revocation is legible
// afterwards.
func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	tokenID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		if err := tx.RevokeAPIToken(ctx, tokenID); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionTokenRevoked, "token", tokenID.String()))
	})
	if err != nil {
		// ErrNotFound also covers an already-revoked token, deliberately: see
		// store.RevokeAPIToken.
		s.notFoundOr(w, err, "token")
		return
	}

	if tokenID == id.TokenID {
		s.log.Warn("token revoked itself; this request was its last", "token", tokenID)
	} else {
		s.log.Info("api token revoked", "token", tokenID, "by", id.TokenID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListSessions lists the browser sessions that are usable right now.
//
// The console has the same list. It is here too because the operator whose
// laptop is missing reaches for a terminal, and because "is anything signed in
// with this credential" is a question about a token, which is an API object.
//
// Live only, by exactly the rule that authenticates a cookie — see
// store.ListUISessions. The empty currentCookie is not an omission: this
// request arrived with a bearer token, so none of these sessions is the
// caller's, and marking one would be a lie.
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	var out []wire.SessionResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		sessions, err := tx.ListUISessions(ctx, "")
		if err != nil {
			return err
		}
		out = make([]wire.SessionResponse, 0, len(sessions))
		for _, sess := range sessions {
			resp := wire.SessionResponse{
				ID: sess.ID.String(), TokenID: sess.TokenID.String(),
				TokenName: sess.TokenName, ReadOnly: sess.ReadOnly,
				CreatedAt:  sess.CreatedAt,
				ExpiresAt:  sess.ExpiresAt,
				LastSeenAt: sess.LastSeenAt,
				UserAgent:  sess.UserAgent,
			}
			if sess.CreatedIP != nil {
				resp.CreatedIP = sess.CreatedIP.String()
			}
			out = append(out, resp)
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "sessions")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRevokeSession ends one browser session and leaves its token alone.
//
// That is the whole reason this exists next to DELETE /v1/tokens/{id}. Revoking
// the token is the larger act and takes the operator's shell and their CI with
// it; closing one forgotten browser should not cost that, or it does not get
// done.
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	sessionID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		return tx.RevokeUISessionByID(ctx, sessionID, *id)
	})
	if err != nil {
		// Already-revoked is ErrNotFound, deliberately: see
		// store.RevokeUISessionByID.
		s.notFoundOr(w, err, "session")
		return
	}

	s.log.Info("browser session revoked", "session", sessionID, "by", id.Subject)
	w.WriteHeader(http.StatusNoContent)
}

// formatTime renders an optional timestamp, or "" when it is unset, so the
// omitempty tags on TokenResponse mean what they look like they mean.
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// handleListAudit serves the trail, narrowed by every filter the store
// implements.
//
// A parameter the API accepts and drops is worse than one it does not offer at
// all: the caller reads a full, unfiltered page as the answer to the question
// they asked. "Nothing happened in that hour" is the wrong thing to conclude
// during an incident, so an unparseable bound is a 400 that names it rather
// than a silently wider window.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{
		Action:     q.Get("action"),
		TargetType: q.Get("target_type"),
		TargetID:   q.Get("target_id"),
	}

	var ok bool
	if f.Since, ok = auditTimeParam(w, q, "since"); !ok {
		return
	}
	if f.Until, ok = auditTimeParam(w, q, "until"); !ok {
		return
	}
	// An inverted window matches nothing, which reads exactly like a quiet
	// period. Say which way round it is instead.
	if !f.Since.IsZero() && !f.Until.IsZero() && f.Until.Before(f.Since) {
		writeErr(w, http.StatusBadRequest, "until is before since, so no entry can match")
		return
	}
	if f.Limit, ok = auditLimitParam(w, q); !ok {
		return
	}

	var out []wire.AuditRecordResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		recs, err := tx.ListAudit(ctx, f)
		if err != nil {
			return err
		}
		out = make([]wire.AuditRecordResponse, 0, len(recs))
		for _, rec := range recs {
			a := wire.AuditRecordResponse{
				ID: rec.ID, At: rec.At, ActorType: rec.ActorType, ActorID: rec.ActorID,
				ActorDisplay: rec.ActorDisplay,
				Action:       rec.Action, TargetType: rec.TargetType, TargetID: rec.TargetID,
				Meta: rec.Meta,
			}
			if rec.SourceIP != nil {
				a.SourceIP = rec.SourceIP.String()
			}
			out = append(out, a)
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "audit log")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// auditLimitMax is the ceiling store.ListAudit enforces. Past it the store does
// not clamp to the ceiling, it drops back to the default page — so asking for
// more than this returns fewer rows than asking for nothing, with nothing in
// the response to say why. The API refuses rather than answer a question it was
// not asked.
const auditLimitMax = 1000

// auditTimeParam parses an optional RFC3339 bound, writing a 400 and returning
// false if it is present and unparseable.
func auditTimeParam(w http.ResponseWriter, q url.Values, name string) (time.Time, bool) {
	v := q.Get(name)
	if v == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(
			"%s must be an RFC3339 timestamp, e.g. \"2026-01-02T15:04:05Z\"", name))
		return time.Time{}, false
	}
	return t, true
}

// auditLimitParam parses an optional row cap. Zero means "the store's default".
func auditLimitParam(w http.ResponseWriter, q url.Values) (int, bool) {
	v := q.Get("limit")
	if v == "" {
		return 0, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
		return 0, false
	}
	if n > auditLimitMax {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(
			"limit must be %d or fewer; a larger value returns the default page, not more",
			auditLimitMax))
		return 0, false
	}
	return n, true
}

//------------------------------------------------------------------------------

// networkResponse is the ONLY renderer for a network, and must stay so. Two
// renderers for one type is precisely the drift internal/wire exists to
// prevent: a field added to one is silently absent from half the API.
func networkResponse(n *store.Network) wire.NetworkResponse {
	cidrs := make([]string, 0, len(n.CIDRs))
	for _, c := range n.CIDRs {
		cidrs = append(cidrs, c.String())
	}
	out := wire.NetworkResponse{
		NetworkID: n.NetworkID,
		ID:        n.ID.String(), Slug: n.Slug, Name: n.Name, CIDRs: cidrs,
		Curve: n.Curve, CertVersion: int(n.CertVer), CertTTL: n.CertTTL.String(),
		ConfigMode:     n.ConfigMode,
		FirewallSource: n.FirewallSource,
		ConfigEpoch:    n.ConfigEpoch, BlocklistEpoch: n.BlocklistEpoch,
	}
	if n.ListenPort != nil {
		out.ListenPort = *n.ListenPort
	}
	return out
}

func roleResponse(r *store.Role) wire.RoleResponse {
	return wire.RoleResponse{
		ID: r.ID.String(), NetworkID: r.NetworkID.String(), Name: r.Name,
		Groups: r.Groups, Firewall: r.FirewallRules,
	}
}

func caResponse(c *store.CA, includePEM bool, activeCerts int) wire.CAResponse {
	out := wire.CAResponse{
		ID: c.ID.String(), NetworkID: c.NetworkID.String(), Name: c.Name,
		Fingerprint: c.Fingerprint, State: c.State,
		NotBefore: c.NotBefore.Format(time.RFC3339),
		NotAfter:  c.NotAfter.Format(time.RFC3339),

		ActiveCertificates: activeCerts,
	}
	if includePEM {
		out.CertPEM = c.CertPEM
	}
	return out
}

func containsStr(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
