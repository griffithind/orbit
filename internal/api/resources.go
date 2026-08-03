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
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// ResourceRoutes registers the network, role, CA, token, and audit endpoints.
//
// Split from AdminRoutes so the host-lifecycle surface stays readable, but they
// mount on the same listener and use the same scoped tokens.
func (s *Server) ResourceRoutes(mux *http.ServeMux) {
	mux.Handle("POST /v1/networks", s.admin("networks:write", s.handleCreateNetwork))
	mux.Handle("GET /v1/networks", s.admin("networks:read", s.handleListNetworks))

	mux.Handle("POST /v1/roles", s.admin("roles:write", s.handleCreateRole))
	mux.Handle("GET /v1/roles", s.admin("roles:read", s.handleListRoles))
	mux.Handle("GET /v1/roles/{id}", s.admin("roles:read", s.handleGetRole))
	mux.Handle("PATCH /v1/roles/{id}", s.admin("roles:write", s.handleUpdateRole))
	mux.Handle("DELETE /v1/roles/{id}", s.admin("roles:write", s.handleDeleteRole))

	mux.Handle("POST /v1/cas", s.admin("cas:write", s.handleCreateCA))
	mux.Handle("GET /v1/cas", s.admin("cas:read", s.handleListCAs))
	mux.Handle("POST /v1/cas/{id}/activate", s.admin("cas:write", s.handleActivateCA))
	mux.Handle("POST /v1/cas/{id}/retire", s.admin("cas:write", s.handleRetireCA))

	mux.Handle("POST /v1/tokens", s.admin("tokens:write", s.handleCreateToken))
	mux.Handle("GET /v1/tokens", s.admin("tokens:read", s.handleListTokens))
	mux.Handle("DELETE /v1/tokens/{id}", s.admin("tokens:write", s.handleRevokeToken))

	mux.Handle("GET /v1/audit-logs", s.admin("audit:read", s.handleListAudit))

	// No scope. Describing the caller to itself reveals nothing the caller does
	// not already hold, and gating it would make the one request a credential
	// with unknown scopes can usefully make the one it might be refused.
	mux.Handle("GET /v1/whoami", s.admin("", s.handleWhoAmI))
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

	net := store.Network{
		Name:    req.Name,
		CIDRs:   cidrs,
		CertTTL: ttl,
		Curve:   cert.Curve_CURVE25519.String(),
		CertVer: 2,
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

	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
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

// roleUpdateResponse is the edited role plus what the edit is going to cost.
//
// The extra fields exist because a role edit has two wildly different prices
// depending on which field was touched, and a response that looked identical
// either way would let an operator believe a policy change had landed when it
// had not. See handleUpdateRole.
type roleUpdateResponse struct {
	wire.RoleResponse

	// Changed is false when the request restated what was already stored. The
	// role is returned unmodified and no epoch was bumped.
	Changed bool `json:"changed"`

	// GroupsChanged marks the edit that outlives this request.
	GroupsChanged bool `json:"groups_changed,omitempty"`

	// HostsAwaitingCertificate is how many hosts are still presenting a
	// certificate carrying the old groups.
	HostsAwaitingCertificate int `json:"hosts_awaiting_certificate,omitempty"`

	// CertificatesConvergeBy is when the last of them will have renewed.
	// Computed from the live certificate rows and the agent's renewal policy,
	// which is deterministic per host, so it is a deadline rather than a guess.
	CertificatesConvergeBy string `json:"certificates_converge_by,omitempty"`

	// Detail says in words what the two numbers above mean, for the operator
	// reading a terminal rather than parsing JSON.
	Detail string `json:"detail,omitempty"`
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
				"hosts_awaiting_certificate": lag.Hosts,
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
		s.notFoundOr(w, err, "role")
		return
	}

	resp := roleUpdateResponse{
		RoleResponse: roleResponse(&change.After),
		Changed:      change.Changed,
	}
	if !change.GroupsChanged {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	s.log.Warn("role groups changed; hosts keep the old groups until they renew",
		"role", roleID, "hosts", lag.Hosts, "convergeBy", lag.formatted())

	resp.GroupsChanged = true
	resp.HostsAwaitingCertificate = lag.Hosts
	resp.CertificatesConvergeBy = lag.formatted()
	resp.Detail = lag.detail()
	writeJSON(w, http.StatusAccepted, resp)
}

// certificateLag is how far behind a role's hosts are after a group change.
type certificateLag struct {
	// Hosts is how many are still presenting a certificate with the old
	// groups. Hosts that have never enrolled are excluded: they have no stale
	// certificate, and will be issued the new groups the first time they ask.
	Hosts int

	// ConvergeBy is when the last of them renews. Zero when Hosts is zero.
	ConvergeBy time.Time
}

// certificateLagFor computes when a group change will actually be in force.
//
// Not an estimate. Each agent's renewal instant is the midpoint of its
// certificate's lifetime offset by a jitter derived from a SHA-256 of its host
// id — deterministic, not random (agent.RenewalPolicy.RenewAt explains why), so
// the same policy the agent will apply, applied here to the certificate rows we
// already hold, yields the exact instant. The default policy is what
// orbit-agent runs; a fleet running a custom one will differ, which is the one
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
		if h.State != store.HostEnrolled && h.State != store.HostActive {
			continue // suspended or deleted; not renewing, and not on the mesh
		}
		lag.Hosts++

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
	if l.Hosts == 0 {
		return "firewall and configuration changes are live; no host currently holds a certificate for this role"
	}
	return fmt.Sprintf(
		"firewall and configuration changes are live, but groups are carried in the signed certificate: "+
			"%d host(s) keep the previous groups until they renew, the last by %s. "+
			"Revoke a host's certificate to force it sooner",
		l.Hosts, l.formatted())
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
			names := make([]string, 0, len(carriers))
			for _, h := range carriers {
				names = append(names, h.Name)
			}
			// 409, not 400: the request is well-formed, the system is not in a
			// state that permits it. The carriers are in the body because
			// "still in use" without naming who is not actionable.
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": "role is still assigned to hosts; reassign them first. " +
					"Deleting it would change the firewall on every one of them at once",
				"hosts": names,
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
	if req.Name == "" || req.SignerRef == "" {
		writeErr(w, http.StatusBadRequest, "name and signer_ref are required")
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

	if s.cfg.SignerFactory == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"this server is not configured to create certificate authorities")
		return
	}
	signer, err := s.cfg.SignerFactory(r.Context(), req.SignerRef)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("signer_ref: %v", err))
		return
	}
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
		CertPEM: string(pem), SignerRef: req.SignerRef, Curve: signer.Curve().String(),
		NotBefore: caCert.NotBefore(), NotAfter: caCert.NotAfter(),
	}
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
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
		if conv.ConfigApplied < conv.HostsTotal && !req.AcknowledgeCutoff {
			for _, l := range conv.Lagging {
				lagging = append(lagging, wire.LaggingHost{
					HostID: l.HostID.String(), Name: l.Name,
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
		if conv.ConfigApplied < conv.HostsTotal {
			action = store.ActionCAForceActivated
			meta = []byte(fmt.Sprintf(`{"hosts_cut_off":%d,"hosts_total":%d}`,
				conv.HostsTotal-conv.ConfigApplied, conv.HostsTotal))
			s.log.Warn("CA activated before convergence; unconverged hosts are cut off",
				"ca", caID, "network", row.NetworkID,
				"cutOff", conv.HostsTotal-conv.ConfigApplied, "total", conv.HostsTotal)
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
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": "hosts have not yet applied this CA; promoting now would cut them off. " +
					"Retry once they converge, or resend with acknowledge_cutoff to proceed anyway",
				"lagging": lagging,
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

func networkResponse(n *store.Network) wire.NetworkResponse {
	cidrs := make([]string, 0, len(n.CIDRs))
	for _, c := range n.CIDRs {
		cidrs = append(cidrs, c.String())
	}
	return wire.NetworkResponse{
		ID: n.ID.String(), Name: n.Name, CIDRs: cidrs,
		Curve: n.Curve, CertVersion: int(n.CertVer), CertTTL: n.CertTTL.String(),
		ConfigEpoch: n.ConfigEpoch, BlocklistEpoch: n.BlocklistEpoch,
	}
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
