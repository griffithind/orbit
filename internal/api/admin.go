package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// identityKey carries the authenticated identity through the request.
type identityKey struct{}

func identityFrom(ctx context.Context) *store.Identity {
	id, _ := ctx.Value(identityKey{}).(*store.Identity)
	return id
}

// admin wraps a handler with bearer-token authentication and a scope check.
//
// Authentication establishes identity; the scope check is separate and explicit
// per route, so adding a route without deciding its scope is a compile-time
// omission rather than an accidentally-public endpoint.
//
// Only API tokens authenticate here today. A second credential type — an OIDC
// bearer JWT — would branch on the token's prefix (store.APITokenPrefix) and
// produce the same store.Identity, leaving every handler, scope check, and
// audit entry below untouched. That is why nothing downstream of this function
// knows what a token is.
func (s *Server) admin(scope string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		id, err := s.store.AuthenticateToken(r.Context(), hashToken(token))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Unknown, revoked, and expired all produce
				// the same response for the same reason as enrollment: a
				// distinguishable failure is a probing oracle.
				writeErr(w, http.StatusUnauthorized, "invalid token")
				return
			}
			s.log.Error("token authentication failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}

		if !id.HasScope(scope) {
			writeErr(w, http.StatusForbidden, "token lacks required scope: "+scope)
			return
		}

		s.store.TouchToken(r.Context(), id.TokenID)
		h(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	})
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	rest, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	return rest, rest != ""
}

func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid "+name)
		return uuid.Nil, false
	}
	return id, true
}

// notFoundOr maps a store error to a response. A row the caller may not see is
// reported as 404 rather than 403, so a failed lookup never confirms that
// something exists.
func (s *Server) notFoundOr(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, what+" not found")
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "already exists")
	case errors.Is(err, enroll.ErrHostBlocked):
		writeErr(w, http.StatusForbidden, "host is blocked")
	case errors.Is(err, store.ErrNoActived):
		writeErr(w, http.StatusServiceUnavailable, "network has no active certificate authority")
	default:
		s.log.Error("admin request failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())

	var req wire.CreateHostRequest
	if !decode(w, r, &req) {
		return
	}

	networkID, err := uuid.Parse(req.NetworkID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid network_id")
		return
	}
	addr, err := netip.ParseAddr(req.OverlayAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid overlay_addr")
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}

	var roleID *uuid.UUID
	if req.RoleID != "" {
		rid, err := uuid.Parse(req.RoleID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid role_id")
			return
		}
		roleID = &rid
	}

	var host store.Host
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		net, err := tx.GetNetwork(ctx, networkID)
		if err != nil {
			return err
		}
		// Catch an out-of-range address here rather than at issuance. The
		// database would accept it, and the failure would then surface much
		// later as a certificate the CA refuses to sign.
		if !net.ContainsAddr(addr) {
			return errOutOfRange
		}

		host = store.Host{
			NetworkID:    networkID,
			Name:         req.Name,
			RoleID:       roleID,
			Addrs:        []netip.Addr{addr},
			Tags:         req.Tags,
			IsLighthouse: req.IsLighthouse,
			IsRelay:      req.IsRelay,
			StaticAddrs:  req.StaticAddrs,
		}
		if err := tx.CreateHost(ctx, &host); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionHostCreated, "host", host.ID.String()))
	})
	if err != nil {
		if errors.Is(err, errOutOfRange) {
			writeErr(w, http.StatusBadRequest, "overlay_addr is not within the network")
			return
		}
		s.notFoundOr(w, err, "network")
		return
	}

	writeJSON(w, http.StatusCreated, hostResponse(&host))
}

var errOutOfRange = errors.New("overlay address is not within the network")

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	networkID, err := uuid.Parse(r.URL.Query().Get("network_id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "network_id query parameter is required")
		return
	}

	var out []wire.HostResponse
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		hosts, err := tx.ListHosts(ctx, networkID)
		if err != nil {
			return err
		}
		out = make([]wire.HostResponse, 0, len(hosts))
		for i := range hosts {
			out = append(out, hostResponse(&hosts[i]))
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleUpdateHost changes a host's roles and metadata.
//
// Role changes advance the config epoch, so every host learns about a new
// lighthouse or relay on its next poll — including the control plane, which
// refreshes its own configuration the same way. That is what makes moving the
// lighthouse role a normal operation rather than a restart.
func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	hostID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var req wire.UpdateHostRequest
	if !decode(w, r, &req) {
		return
	}

	var host *store.Host
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		host, err = tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}

		lighthouse, relay := host.IsLighthouse, host.IsRelay
		static := host.StaticAddrs
		if req.IsLighthouse != nil {
			lighthouse = *req.IsLighthouse
		}
		if req.IsRelay != nil {
			relay = *req.IsRelay
		}
		if req.StaticAddrs != nil {
			static = *req.StaticAddrs
		}

		// A lighthouse nobody can reach is worse than none: every host keeps
		// dialling it. Refuse rather than publish an address list that cannot
		// work.
		if lighthouse && len(static) == 0 {
			return errLighthouseNeedsAddr
		}

		if err := tx.SetHostRoles(ctx, hostID, lighthouse, relay, static); err != nil {
			return err
		}
		if req.RoleID != nil || req.Tags != nil {
			if err := tx.UpdateHostMeta(ctx, hostID, req.RoleID, req.Tags); err != nil {
				return err
			}
		}

		host, err = tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionHostUpdated, "host", hostID.String()))
	})
	if err != nil {
		if errors.Is(err, errLighthouseNeedsAddr) {
			writeErr(w, http.StatusBadRequest,
				"a lighthouse needs static_addrs; without a reachable address every host would keep trying it")
			return
		}
		s.notFoundOr(w, err, "host")
		return
	}
	writeJSON(w, http.StatusOK, hostResponse(host))
}

var errLighthouseNeedsAddr = errors.New("lighthouse requires static_addrs")

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	hostID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var host *store.Host
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		host, err = tx.GetHost(ctx, hostID)
		return err
	})
	if err != nil {
		s.notFoundOr(w, err, "host")
		return
	}
	writeJSON(w, http.StatusOK, hostResponse(host))
}

func (s *Server) handleCreateEnrollCode(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	hostID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	resp, err := s.enroll.CreateCode(r.Context(), hostID, 0, *id)
	if err != nil {
		s.notFoundOr(w, err, "host")
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleBlockHost(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	hostID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var epoch int64
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		epoch, err = tx.BlockHost(ctx, hostID, "blocked via admin API")
		if err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionHostBlocked, "host", hostID.String()))
	})
	if err != nil {
		s.notFoundOr(w, err, "host")
		return
	}
	writeJSON(w, http.StatusOK, wire.BlockResponse{BlocklistEpoch: epoch})
}

func (s *Server) handleUnblockHost(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	hostID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var epoch int64
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		epoch, err = tx.UnblockHost(ctx, hostID)
		if err != nil {
			return err
		}
		return tx.AppendAudit(ctx, id.Audit(store.ActionHostUnblocked, "host", hostID.String()))
	})
	if err != nil {
		s.notFoundOr(w, err, "host")
		return
	}
	writeJSON(w, http.StatusOK, wire.BlockResponse{BlocklistEpoch: epoch})
}

// handleDeleteHost decommissions a host: revoke, then remove.
//
// Distinct from block, which is reversible and keeps the record. This releases
// the name and the overlay address for reuse and cannot be undone, so the
// certificates have to be revoked on the way out — see store.DeleteHost for why
// the ordering carries the whole guarantee.
//
// Returns the blocklist epoch, like block does, because the caller's next
// question is the same one: has the fleet seen this yet.
func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	hostID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "deleted via admin API"
	}

	var (
		epoch int64
		name  string
	)
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		// Read the name before the row goes, so the audit entry says which host
		// this was. A uuid alone is useless to whoever reads the log later.
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		name = host.Name

		epoch, err = tx.DeleteHost(ctx, hostID, reason)
		if err != nil {
			return err
		}
		e := id.Audit(store.ActionHostDeleted, "host", hostID.String())
		e.Meta = []byte(fmt.Sprintf(`{"name":%q,"reason":%q}`, name, reason))
		return tx.AppendAudit(ctx, e)
	})
	if err != nil {
		s.notFoundOr(w, err, "host")
		return
	}

	s.log.Info("host deleted and its certificates revoked",
		"host", hostID, "name", name, "by", id.TokenID)
	writeJSON(w, http.StatusOK, wire.BlockResponse{BlocklistEpoch: epoch})
}

func (s *Server) handleConvergence(w http.ResponseWriter, r *http.Request) {
	networkID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var resp wire.ConvergenceResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		c, err := tx.Convergence(ctx, networkID, 100)
		if err != nil {
			return err
		}
		resp = wire.ConvergenceResponse{
			ConfigEpoch:    c.ConfigEpoch,
			BlocklistEpoch: c.BlocklistEpoch,
			HostsTotal:     c.HostsTotal,
			ConfigApplied:  c.ConfigApplied,
			BlockApplied:   c.BlockApplied,
		}
		for _, l := range c.Lagging {
			resp.Lagging = append(resp.Lagging, wire.LaggingHost{
				HostID:                l.HostID.String(),
				Name:                  l.Name,
				AppliedConfigEpoch:    l.AppliedConfigEpoch,
				AppliedBlocklistEpoch: l.AppliedBlocklistEpoch,
				LastSeenAt:            l.LastSeenAt,
			})
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}

	// Content negotiation rather than a separate endpoint. Convergence is the
	// number an operator checks before a CA rotation and while watching a
	// revocation land, which happens at a terminal far more often than in a
	// browser; making that require jq is a small tax paid constantly.
	if wantsPlainText(r) {
		writePlain(w, http.StatusOK, renderConvergence(&resp))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// wantsPlainText reports whether the caller asked for human-readable output.
func wantsPlainText(r *http.Request) bool {
	if r.URL.Query().Get("format") == "text" {
		return true
	}
	accept := r.Header.Get("Accept")
	// Only when text is asked for explicitly. A browser sends a wildcard and
	// would otherwise get text where a script expects JSON.
	return strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json")
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func hostResponse(h *store.Host) wire.HostResponse {
	addrs := make([]string, 0, len(h.Addrs))
	for _, a := range h.Addrs {
		addrs = append(addrs, a.String())
	}
	return wire.HostResponse{
		ID:                    h.ID.String(),
		Name:                  h.Name,
		NetworkID:             h.NetworkID.String(),
		OverlayAddrs:          addrs,
		State:                 h.State,
		Tags:                  h.Tags,
		IsLighthouse:          h.IsLighthouse,
		IsRelay:               h.IsRelay,
		AppliedConfigEpoch:    h.AppliedConfigEpoch,
		AppliedBlocklistEpoch: h.AppliedBlocklistEpoch,
		LastSeenAt:            h.LastSeenAt,
	}
}
