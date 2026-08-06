package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// Routes: prefixes a gateway offers that are not in the overlay.
//
// Scoped under a membership because that is what a route belongs to. The
// alternative — a flat /v1/routes taking a membership in the body — would allow
// a request whose URL and body disagree, and there is no useful answer to that.
//
// Nothing here checks the CA's constraint. It cannot usefully: the check
// belongs at signing time, in internal/ca, where the key is. A route the CA
// will not permit is accepted here and fails at the gateway's next enrollment
// with a message naming the CA — which is a legible failure in the right place,
// rather than this layer duplicating a rule it would eventually disagree with.

// handleListNetworkRoutes lists every route in a network.
//
// The listing that was missing. Routes were reachable only through
// /v1/memberships/{id}/routes, so seeing what a network routes meant already knowing which
// membership to ask — and the answer to "what does this fleet route" was assembled by
// hand, or not at all. NetworkRoutes has always existed; it is what config rendering
// reads, so this exposes the same view every host is already configured from.
func (s *Server) handleListNetworkRoutes(w http.ResponseWriter, r *http.Request) {
	networkID, err := uuid.Parse(r.URL.Query().Get("network_id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "network_id query parameter is required")
		return
	}

	var out wire.RouteListResponse
	out.Routes = []wire.RouteResponse{}
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		rs, err := tx.NetworkRoutes(ctx, networkID)
		if err != nil {
			return err
		}
		for _, rt := range rs {
			out.Routes = append(out.Routes, routeResponse(rt, rt.MembershipName))
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	membershipID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var out wire.RouteListResponse
	out.Routes = []wire.RouteResponse{}
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		m, err := tx.GetHost(ctx, membershipID)
		if err != nil {
			return err
		}
		rs, err := tx.MembershipRoutes(ctx, membershipID)
		if err != nil {
			return err
		}
		for _, rt := range rs {
			out.Routes = append(out.Routes, routeResponse(rt, m.Name))
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "membership")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	membershipID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req wire.CreateRouteRequest
	if !decode(w, r, &req) {
		return
	}

	prefix, err := netip.ParsePrefix(req.Prefix)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "prefix is not a CIDR: "+err.Error())
		return
	}
	// Refused rather than masked. An operator who wrote 192.168.88.5/24 meant a
	// host and got a network; silently correcting it would route a prefix they
	// did not ask for, which is worse than the error.
	if prefix.Addr() != prefix.Masked().Addr() {
		writeErr(w, http.StatusBadRequest, "prefix "+req.Prefix+
			" has bits set below the prefix length; write "+prefix.Masked().String())
		return
	}
	if req.Weight < 0 {
		writeErr(w, http.StatusBadRequest, "weight cannot be negative")
		return
	}

	install := true
	if req.Install != nil {
		install = *req.Install
	}

	var out wire.RouteResponse
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		m, err := tx.GetHost(ctx, membershipID)
		if err != nil {
			return err
		}
		rt := store.Route{
			NetworkID: m.NetworkID, MembershipID: m.ID,
			Prefix: prefix, Weight: req.Weight,
			Masquerade: req.Masquerade, Install: install,
		}
		if req.MTU != 0 {
			rt.MTU = &req.MTU
		}
		if err := tx.CreateRoute(ctx, &rt); err != nil {
			return err
		}
		// The address other machines will route through, so the response says
		// what was actually created rather than making the caller look it up.
		// Empty only when the gateway has no address yet, which is what a
		// half-enrolled membership looks like.
		if len(m.Addrs) > 0 {
			rt.GatewayAddr = m.Addrs[0]
		}
		out = routeResponse(rt, m.Name)
		return tx.AppendAudit(ctx, identityFrom(ctx).
			Audit(store.ActionRouteAdded, "membership", m.ID.String()))
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict,
				"this membership already offers "+prefix.String())
			return
		}
		s.notFoundOr(w, err, "membership")
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	routeID, ok := pathUUID(w, r, "routeId")
	if !ok {
		return
	}
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		if err := tx.DeleteRoute(ctx, routeID); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, identityFrom(ctx).
			Audit(store.ActionRouteRemoved, "route", routeID.String()))
	})
	if err != nil {
		s.notFoundOr(w, err, "route")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func routeResponse(r store.Route, membershipName string) wire.RouteResponse {
	out := wire.RouteResponse{
		ID: r.ID.String(), NetworkID: r.NetworkID.String(),
		MembershipID: r.MembershipID.String(), MembershipName: membershipName,
		Prefix: r.Prefix.String(), Weight: r.Weight,
		Masquerade: r.Masquerade, Install: r.Install,
	}
	if r.MTU != nil {
		out.MTU = *r.MTU
	}
	if r.GatewayAddr.IsValid() {
		out.GatewayAddr = r.GatewayAddr.String()
	}
	return out
}

// Exit nodes: a default route, chosen rather than imposed.
//
// The choice is a control-plane call, not a file on the machine, and that is
// deliberate. The agent runs only what the control plane signed
// (config-integrity.md 7a), so a locally-injected default route is the one
// thing that model exists to prevent. `orbit exit-node use` is a REQUEST: it
// patches the membership, bumps the epoch, and the route arrives in the next
// signed configuration. Local command, central authority.

func (s *Server) handleListExitNodes(w http.ResponseWriter, r *http.Request) {
	membershipID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	out := wire.ExitNodeListResponse{Available: []wire.RouteResponse{}}
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		m, err := tx.GetHost(ctx, membershipID)
		if err != nil {
			return err
		}
		avail, err := tx.DefaultRoutes(ctx, m.NetworkID)
		if err != nil {
			return err
		}
		for _, rt := range avail {
			out.Available = append(out.Available, routeResponse(rt, ""))
		}
		cur, err := tx.ExitRoute(ctx, membershipID)
		if err != nil {
			return err
		}
		if cur != nil {
			out.CurrentRouteID = cur.ID.String()
		}
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "membership")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	membershipID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req wire.SetExitNodeRequest
	if !decode(w, r, &req) {
		return
	}

	var routeID *uuid.UUID
	if req.RouteID != "" {
		id, err := uuid.Parse(req.RouteID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "route_id must be a uuid")
			return
		}
		routeID = &id
	}

	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		if err := tx.SetExitRoute(ctx, membershipID, routeID); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, identityFrom(ctx).
			Audit(store.ActionExitNodeSet, "membership", membershipID.String()))
	})
	if err != nil {
		if errors.Is(err, store.ErrInvalid) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.notFoundOr(w, err, "membership or route")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
