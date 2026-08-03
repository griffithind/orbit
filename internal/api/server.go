// Package api serves Orbit's three HTTP surfaces.
//
// They are separate because they have different threat models and different
// exposure requirements, and conflating them is how a management API ends up
// on the public internet:
//
//	/enroll/v1  public, unauthenticated except for the enrollment credential
//	/agent/v1   overlay only, identity derived from the source address
//	/v1         admin, scoped bearer tokens
//
// Mount them on separate listeners in production. Handler() returns one mux for
// development convenience, and says so.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// AgentListener describes the nebula network a given agent listener serves.
//
// This is required for the agent API and cannot be inferred. Two networks may
// use the same prefix, so a source address of 10.42.0.7 is ambiguous on its
// own; the network must come from which listener the request physically arrived
// on. Orbit therefore runs one agent listener per network.
type AgentListener struct {
	NetworkID uuid.UUID
}

type Config struct {
	// Agent is nil when this server has no overlay listener, which is the case
	// during early bring-up. The agent routes then refuse with a clear message
	// rather than falling back to a weaker identity check.
	Agent *AgentListener

	// TrustForwardedFor makes the server read the client address from
	// X-Forwarded-For. Only enable behind a proxy that overwrites the header;
	// on a directly-exposed listener it lets any client claim any address.
	TrustForwardedFor bool

	// Notifier powers /agent/v1/watch. Nil disables push, and agents fall back
	// to polling: correct but an order of magnitude slower to converge, so the
	// server says so at startup rather than degrading quietly.
	Notifier *notify.Notifier

	// MaxWatchers caps concurrent long-poll connections per network. Zero means
	// unlimited, which is wrong for a shared deployment.
	MaxWatchers int

	// SignerFactory resolves a CA signer reference. Nil disables CA creation
	// through the API, which is a reasonable posture for a deployment that
	// provisions certificate authorities out of band.
	SignerFactory ca.SignerFactory

	// EnrollLimit bounds the public enrollment endpoint. The zero value is
	// filled in with DefaultLimiterConfig; set Disabled to turn it off, which
	// leaves a public, unauthenticated, cryptographically expensive endpoint
	// unbounded.
	EnrollLimit LimiterConfig

	// DisableEnrollLimit removes rate limiting entirely. For tests and for
	// deployments that limit at a proxy instead.
	DisableEnrollLimit bool
}

type Server struct {
	store   *store.Store
	enroll  *enroll.Service
	cfg     Config
	log     *slog.Logger
	limiter *Limiter
}

func New(st *store.Store, es *enroll.Service, cfg Config, log *slog.Logger) *Server {
	s := &Server{store: st, enroll: es, cfg: cfg, log: log}
	if !cfg.DisableEnrollLimit {
		s.limiter = NewLimiter(cfg.EnrollLimit)
	}
	return s
}

// Handler returns every route on one mux.
//
// Convenient for development and for tests. In production, build three
// listeners and mount EnrollRoutes, AgentRoutes, and AdminRoutes separately so
// that network-level exposure matches each surface's threat model.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.EnrollRoutes(mux)
	s.AgentRoutes(mux)
	s.AdminRoutes(mux)
	return logging(s.log, mux)
}

func (s *Server) EnrollRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /enroll/v1/enroll", s.limitEnroll(s.handleEnroll))

	// Recovery lives on the public surface for the same reason enrollment does:
	// a host whose certificate expired cannot reach the overlay, which is the
	// only place the agent API listens.
	mux.HandleFunc("GET /enroll/v1/recover/challenge", s.limitEnroll(s.handleRecoveryChallenge))
	mux.HandleFunc("POST /enroll/v1/recover", s.limitEnroll(s.handleRecover))
}

func (s *Server) AgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /agent/v1/state", s.handleAgentState)
	mux.HandleFunc("GET /agent/v1/watch", s.handleAgentWatch)
	mux.HandleFunc("POST /agent/v1/report", s.handleAgentReport)
	mux.HandleFunc("POST /agent/v1/renew", s.handleAgentRenew)
}

func (s *Server) AdminRoutes(mux *http.ServeMux) {
	mux.Handle("POST /v1/hosts", s.admin("hosts:create", s.handleCreateHost))
	mux.Handle("GET /v1/hosts", s.admin("hosts:read", s.handleListHosts))
	mux.Handle("GET /v1/hosts/{id}", s.admin("hosts:read", s.handleGetHost))
	mux.Handle("PATCH /v1/hosts/{id}", s.admin("hosts:write", s.handleUpdateHost))
	mux.Handle("POST /v1/hosts/{id}/enrollment-code", s.admin("hosts:enroll", s.handleCreateEnrollCode))
	mux.Handle("POST /v1/hosts/{id}/block", s.admin("hosts:block", s.handleBlockHost))
	mux.Handle("POST /v1/hosts/{id}/unblock", s.admin("hosts:block", s.handleUnblockHost))
	mux.Handle("GET /v1/networks/{id}/convergence", s.admin("networks:read", s.handleConvergence))
	s.ResourceRoutes(mux)
}

//------------------------------------------------------------------------------
// Enroll surface
//------------------------------------------------------------------------------

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req wire.EnrollRequest
	if !decode(w, r, &req) {
		return
	}

	resp, err := s.enroll.Enroll(r.Context(), req, s.clientAddr(r))
	if err != nil {
		switch {
		case errors.Is(err, enroll.ErrInvalidCredential):
			// One message for unknown, already-used, and expired. Telling a
			// caller which one it was hands an attacker a way to probe for
			// live credentials.
			writeErr(w, http.StatusUnauthorized, "invalid or expired enrollment credential")
		case errors.Is(err, enroll.ErrHostBlocked):
			writeErr(w, http.StatusForbidden, "host is blocked")
		case errors.Is(err, enroll.ErrInvalidPublicKey), errors.Is(err, enroll.ErrCurveMismatch):
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrNoActived):
			// The operator's problem, not the agent's, and worth shouting about.
			s.log.Error("enrollment failed: network has no active CA", "error", err)
			writeErr(w, http.StatusServiceUnavailable, "network has no active certificate authority")
		default:
			s.log.Error("enrollment failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "enrollment failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

//------------------------------------------------------------------------------
// Agent surface
//------------------------------------------------------------------------------

// agentIdentity resolves the calling host from the request's source address.
//
// The address is trustworthy only because nebula's firewall verifies on every
// packet that a peer's certificate actually contains its source address
// (firewall.go Drop). That guarantee exists only for traffic arriving over the
// overlay, which is why this refuses to run without a configured overlay
// listener rather than degrading to something weaker.
func (s *Server) agentIdentity(w http.ResponseWriter, r *http.Request) (*store.AgentIdentity, bool) {
	if s.cfg.Agent == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"agent API is not available: this server has no overlay listener configured")
		return nil, false
	}

	addr := s.clientAddr(r)
	if !addr.IsValid() {
		writeErr(w, http.StatusBadRequest, "could not determine source address")
		return nil, false
	}

	id, err := s.store.ResolveAgentHost(r.Context(), s.cfg.Agent.NetworkID, addr)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusUnauthorized, "unknown host")
			return nil, false
		}
		s.log.Error("resolving agent host failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	if id.State == store.HostSuspended {
		writeErr(w, http.StatusForbidden, "host is blocked")
		return nil, false
	}
	return id, true
}

func (s *Server) handleAgentState(w http.ResponseWriter, r *http.Request) {
	id, ok := s.agentIdentity(w, r)
	if !ok {
		return
	}

	knownConfig, _ := strconv.ParseInt(r.URL.Query().Get("config_epoch"), 10, 64)
	knownBlock, _ := strconv.ParseInt(r.URL.Query().Get("blocklist_epoch"), 10, 64)

	resp, err := s.enroll.State(r.Context(), id.HostID, knownConfig, knownBlock)
	if err != nil {
		s.log.Error("agent state failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAgentReport(w http.ResponseWriter, r *http.Request) {
	id, ok := s.agentIdentity(w, r)
	if !ok {
		return
	}

	var req wire.ReportRequest
	if !decode(w, r, &req) {
		return
	}

	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		return tx.RecordAgentReport(ctx, id.HostID, store.AgentReport{
			ConfigEpoch:    req.ConfigEpoch,
			BlocklistEpoch: req.BlocklistEpoch,
			NebulaVersion:  req.NebulaVersion,
			AgentVersion:   req.AgentVersion,
		})
	})
	if err != nil {
		s.log.Error("agent report failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAgentRenew(w http.ResponseWriter, r *http.Request) {
	id, ok := s.agentIdentity(w, r)
	if !ok {
		return
	}

	var req wire.RenewRequest
	if !decode(w, r, &req) {
		return
	}

	resp, err := s.enroll.Renew(r.Context(), id.HostID, req)
	if err != nil {
		if errors.Is(err, enroll.ErrInvalidPublicKey) || errors.Is(err, enroll.ErrCurveMismatch) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.log.Error("renewal failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "renewal failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

// clientAddr extracts the caller's IP.
func (s *Server) clientAddr(r *http.Request) netip.Addr {
	if s.cfg.TrustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
				return a.Unmap()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	// Cap the body. These are all small documents and an unbounded read on an
	// unauthenticated endpoint is a free denial of service.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, wire.Error{Error: msg})
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// constantTimeEqual is used where a comparison result could otherwise leak
// timing information about a secret.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Debug("request",
			"method", r.Method, "path", r.URL.Path,
			"status", rec.status, "durationMs", time.Since(start).Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// handleRecoveryChallenge starts the proof-of-possession exchange.
//
// Rate limited with the same budget as enrollment: it is public, unauthenticated,
// and does elliptic-curve work per request.
func (s *Server) handleRecoveryChallenge(w http.ResponseWriter, r *http.Request) {
	hostID, err := uuid.Parse(r.URL.Query().Get("host_id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "host_id is required")
		return
	}

	resp, err := s.enroll.Challenge(r.Context(), hostID)
	if err != nil {
		s.recoveryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request) {
	var req wire.RecoverRequest
	if !decode(w, r, &req) {
		return
	}

	resp, err := s.enroll.Recover(r.Context(), req, s.clientAddr(r))
	if err != nil {
		s.recoveryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// recoveryError maps recovery failures to responses.
//
// A bad proof, an unknown host, and an ineligible host all return 401 with one
// message. Distinguishing them would let a caller enumerate host ids and learn
// which are recoverable, which is reconnaissance for exactly the attack this
// endpoint has to withstand.
func (s *Server) recoveryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enroll.ErrChallengeExpired):
		// Safe to distinguish: the caller already knows how old its challenge
		// is, and telling it to retry avoids a confusing loop.
		writeErr(w, http.StatusUnauthorized, "recovery challenge has expired; request a new one")
	case errors.Is(err, enroll.ErrBadProof),
		errors.Is(err, enroll.ErrRecoveryUnavailable),
		errors.Is(err, enroll.ErrHostBlocked),
		errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusUnauthorized, "recovery denied")
	case errors.Is(err, enroll.ErrInvalidPublicKey), errors.Is(err, enroll.ErrCurveMismatch):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		s.log.Error("recovery failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "recovery failed")
	}
}
