package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The join surface.
//
// Two public endpoints and two admin ones, for the flow in
// docs/design-device-identity.md §3: a device asks, an operator says yes, the
// device collects. The first and third are public and unauthenticated for the
// same reason enrollment is — a machine with no certificate has no overlay, and
// the overlay is the only place the agent API listens.
//
// "Unauthenticated" is the wrong word for what they actually are, and it is
// worth being precise because it changes how they should be read. Both are
// gated on a signature over a canonical statement: the join proves possession
// of the key it presents, and the claim proves possession of the key already
// recorded for the membership. Neither accepts a bearer secret because neither
// needs one.

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req wire.JoinRequest
	if !decodeAgent(w, r, &req) {
		return
	}

	resp, err := s.enroll.Join(r.Context(), req, s.clientAddr(r))
	if err != nil {
		switch {
		case errors.Is(err, device.ErrStaleJoin):
			// 400 rather than 401: nothing is wrong with the credential, the
			// machine's clock is wrong, and the message says by how much.
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, enroll.ErrJoinSignature):
			writeErr(w, http.StatusUnauthorized, "join signature is not valid")
		case errors.Is(err, enroll.ErrJoinName),
			errors.Is(err, enroll.ErrLighthouseNeedsAddr),
			errors.Is(err, store.ErrBadPublicAddr):
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, enroll.ErrNameTaken):
			writeErr(w, http.StatusConflict, err.Error())
		case errors.Is(err, enroll.ErrInvalidCredential):
			// One message for unknown, spent and expired, as enrollment does.
			// Telling a caller which one it was hands an attacker a way to
			// probe for live reservations.
			writeErr(w, http.StatusUnauthorized, "invalid or expired reservation code")
		case errors.Is(err, enroll.ErrReservationForAnotherNetwork):
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrAddressExhausted), errors.Is(err, store.ErrConflict):
			// Address exhaustion reaches here rather than the reserve call,
			// because a reservation holds a NAME and does not allocate. The
			// message names the prefix that ran out, which is the one thing an
			// operator needs and cannot get from a status code.
			writeErr(w, http.StatusConflict, err.Error())
		case errors.Is(err, store.ErrDeviceBlocked):
			writeErr(w, http.StatusForbidden, "device is blocked")
		case errors.Is(err, store.ErrNotFound):
			// The network. Deliberately the same shape as any other 404 and not
			// distinguished from a network that exists but is empty: this
			// endpoint takes no credential, and an enumerable network list is
			// not something to hand out for free.
			writeErr(w, http.StatusNotFound, "no such network")
		default:
			s.log.Error("join failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "join failed")
		}
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	var req wire.ClaimRequest
	if !decodeAgent(w, r, &req) {
		return
	}

	resp, err := s.enroll.Claim(r.Context(), req, s.clientAddr(r))
	if err != nil {
		switch {
		case errors.Is(err, enroll.ErrNotAuthorized):
			// 409, and this is the status an agent loops on. Not 403, which
			// means "and it will not change"; not 404, which would send
			// somebody looking for a lost row. The normal case on this endpoint
			// is a machine polling while a human has not looked yet, and the
			// response has to say "keep waiting" clearly enough that no agent
			// author mistakes it for a failure.
			writeErr(w, http.StatusConflict,
				"membership has not been authorized yet; an operator must approve it")
		case errors.Is(err, device.ErrStaleJoin):
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, enroll.ErrJoinSignature):
			writeErr(w, http.StatusUnauthorized, "claim signature is not valid")
		case errors.Is(err, store.ErrDeviceBlocked):
			writeErr(w, http.StatusForbidden, "device is blocked")
		case errors.Is(err, enroll.ErrHostBlocked):
			writeErr(w, http.StatusForbidden, "membership is suspended")
		case errors.Is(err, enroll.ErrInvalidPublicKey), errors.Is(err, enroll.ErrCurveMismatch):
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrNotFound):
			writeErr(w, http.StatusNotFound, "no such membership")
		case errors.Is(err, store.ErrNoActived):
			s.log.Error("claim failed: network has no active CA", "error", err)
			writeErr(w, http.StatusServiceUnavailable, "network has no active certificate authority")
		case errors.Is(err, ca.ErrOutsideCAValidity):
			s.log.Error("claim failed: the active CA cannot issue", "error", err)
			writeErr(w, http.StatusServiceUnavailable,
				"the network's certificate authority cannot issue: "+err.Error())
		default:
			s.log.Error("claim failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "claim failed")
		}
		return
	}
	s.cfg.Metrics.CertificateIssued("claim")
	writeJSON(w, http.StatusOK, resp)
}

//------------------------------------------------------------------------------
// Admin: the pending queue
//------------------------------------------------------------------------------

func (s *Server) handleListPending(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnroll(w) {
		return
	}
	var net *store.Network
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		net, err = s.resolveNetwork(ctx, tx, r)
		return err
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}

	pending, err := s.enroll.PendingJoins(r.Context(), net.ID)
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}

	out := make([]wire.PendingJoin, 0, len(pending))
	for _, m := range pending {
		p := wire.PendingJoin{
			MembershipID: m.ID.String(),
			Name:         m.Name,
			RequestedAt:  m.CreatedAt,
		}
		if m.DeviceID != nil {
			p.DeviceID = m.DeviceID.String()
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, wire.PendingJoinList{Pending: out})
}

func (s *Server) handleAuthorizeMembership(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnroll(w) {
		return
	}
	id := identityFrom(r.Context())
	membershipID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var req wire.AuthorizeRequest
	// A body is optional: authorizing with no role is the common case, and
	// requiring "{}" would make the simple call the awkward one.
	if r.ContentLength > 0 && !decodeAgent(w, r, &req) {
		return
	}

	var roleID *uuid.UUID
	if req.RoleID != "" {
		parsed, err := uuid.Parse(req.RoleID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "role_id is not a uuid")
			return
		}
		roleID = &parsed
	}

	m, net, err := s.enroll.Authorize(r.Context(), membershipID, roleID, *id)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotPending):
			writeErr(w, http.StatusConflict, err.Error())
		case errors.Is(err, store.ErrDeviceBlocked):
			// The case this check exists for: a machine reported stolen between
			// asking to join and an operator looking at the queue.
			writeErr(w, http.StatusForbidden,
				"the device that joined is blocked; unblock it first if this is intended")
		default:
			s.notFoundOr(w, err, "membership")
		}
		return
	}
	writeJSON(w, http.StatusOK, membershipResponse(m, net))
}

// handleReserve holds a place in a network for a machine that has not arrived.
func (s *Server) handleReserve(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnroll(w) {
		return
	}
	id := identityFrom(r.Context())

	var req wire.ReserveRequest
	if !decodeAgent(w, r, &req) {
		return
	}

	res := store.Reservation{
		Name:          req.Name,
		IsLighthouse:  req.IsLighthouse,
		IsRelay:       req.IsRelay,
		PublicAddrs:   req.PublicAddrs,
		AdvertisePort: req.AdvertisePort,
	}
	if req.AdvertisePort != nil && (*req.AdvertisePort < 1 || *req.AdvertisePort > 65535) {
		writeErr(w, http.StatusBadRequest, "advertise_port must be between 1 and 65535")
		return
	}
	if req.OverlayAddr != "" {
		addr, err := netip.ParseAddr(req.OverlayAddr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "overlay_addr is not an IP address")
			return
		}
		res.Addr = addr
	}
	if req.RoleID != "" {
		roleID, err := uuid.Parse(req.RoleID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "role_id must be a uuid, not a role name")
			return
		}
		res.RoleID = &roleID
	}

	out, err := s.enroll.Reserve(r.Context(), r.PathValue("ref"), res,
		time.Duration(req.TTLSeconds)*time.Second, *id)
	if err != nil {
		switch {
		case errors.Is(err, enroll.ErrReservedNameTaken):
			writeErr(w, http.StatusConflict, err.Error())
		case errors.Is(err, enroll.ErrJoinName),
			errors.Is(err, enroll.ErrLighthouseNeedsAddr),
			errors.Is(err, store.ErrBadPublicAddr):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			s.notFoundOr(w, err, "network")
		}
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// requireEnroll refuses politely when this server has no enrollment service.
//
// Several admin routes mint or redeem credentials and reach through s.enroll to
// do it. A server built without one — internal/api's own tests, and any
// deployment that mounts only the admin surface — would otherwise dereference
// nil and take the process down, turning a configuration gap into a crash on
// whichever request happened to arrive first.
//
// 503 rather than 404: the route exists, and this deployment cannot serve it.
func (s *Server) requireEnroll(w http.ResponseWriter) bool {
	if s.enroll == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"this server has no enrollment service configured, so it cannot issue credentials")
		return false
	}
	return true
}
