package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

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

	mux.Handle("POST /v1/cas", s.admin("cas:write", s.handleCreateCA))
	mux.Handle("GET /v1/cas", s.admin("cas:read", s.handleListCAs))
	mux.Handle("POST /v1/cas/{id}/activate", s.admin("cas:write", s.handleActivateCA))
	mux.Handle("POST /v1/cas/{id}/retire", s.admin("cas:write", s.handleRetireCA))

	mux.Handle("POST /v1/tokens", s.admin("tokens:write", s.handleCreateToken))
	mux.Handle("GET /v1/audit-logs", s.admin("audit:read", s.handleListAudit))
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
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "token", ActorID: id.TokenID.String(),
			Action: store.ActionNetworkCreated, TargetType: "network", TargetID: net.ID.String(),
		})
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
		// Groups must be a subset of the signing CA's, or issuance fails later
		// with a constraint error that names the certificate rather than the
		// role. Check now, while the operator is looking at the role.
		if len(role.Groups) > 0 {
			caRow, err := tx.GetActiveCA(ctx, networkID)
			if err != nil {
				return err
			}
			caCert, _, perr := cert.UnmarshalCertificateFromPEM([]byte(caRow.CertPEM))
			if perr != nil {
				return fmt.Errorf("parse active CA: %w", perr)
			}
			if allowed := caCert.Groups(); len(allowed) > 0 {
				for _, g := range role.Groups {
					if !containsStr(allowed, g) {
						return fmt.Errorf("%w: group %q is not permitted by CA %q (allows %v)",
							ca.ErrGroupNotInCA, g, caRow.Name, allowed)
					}
				}
			}
		}
		if err := tx.CreateRole(ctx, &role); err != nil {
			return err
		}
		// A role changes what every host carrying it may do, so it advances the
		// config epoch and every affected agent picks it up on the next push.
		if _, err := tx.BumpEpoch(ctx, networkID, store.EpochConfig); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "token", ActorID: id.TokenID.String(),
			Action: "role.created", TargetType: "role", TargetID: role.ID.String(),
		})
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
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "token", ActorID: id.TokenID.String(),
			Action: store.ActionCACreated, TargetType: "ca", TargetID: row.ID.String(),
		})
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
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "token", ActorID: id.TokenID.String(),
			Action: action, TargetType: "ca", TargetID: caID.String(), Meta: meta,
		})
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
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "token", ActorID: id.TokenID.String(),
			Action: store.ActionCARetired, TargetType: "ca", TargetID: caID.String(),
		})
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
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "token", ActorID: id.TokenID.String(),
			Action: "token.created", TargetType: "token", TargetID: tokenID.String(),
		})
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

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	f := store.AuditFilter{
		Action:     r.URL.Query().Get("action"),
		TargetType: r.URL.Query().Get("target_type"),
		TargetID:   r.URL.Query().Get("target_id"),
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
				Action: rec.Action, TargetType: rec.TargetType, TargetID: rec.TargetID,
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
