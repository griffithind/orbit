// Package api serves Orbit's HTTP surfaces.
//
// Three of them are separate because they have different threat models and
// different exposure requirements, and conflating them is how a management API
// ends up on the public internet:
//
//	/enroll/v1  public, unauthenticated except for the enrollment credential
//	/agent/v1   overlay only, identity derived from the source address
//	/v1         admin, scoped bearer tokens
//
// Mount them on separate listeners in production. Handler() returns one mux for
// development convenience, and says so.
//
// A fourth, /healthz and /readyz, is unauthenticated on purpose and is mounted
// alongside whichever of the above a given listener serves. See HealthRoutes.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/metrics"
	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/version"
	"github.com/griffithind/orbit/internal/wire"
)

// Version is the build, from internal/version so every binary reports the same
// string. See that package for why it is not declared here.
var Version = version.Version

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

	// Metrics counts events. Nil is safe and every call becomes a no-op, so
	// tests and metric-less deployments need no branching at the call sites.
	Metrics *metrics.Metrics

	// SealNetworkIdentity stores a new network's identity key and returns the
	// signer ref naming it. Nil refuses POST /v1/networks.
	//
	// A function rather than a *vault.Vault, for the reason SignerFactory and
	// PolicySource are functions: internal/api would otherwise import the vault,
	// and every test of this package would need a database and a KEK to
	// construct a server.
	//
	// It takes the caller's transaction because the key and the network row are
	// one fact. A key sealed by a transaction that then rolled back is
	// ciphertext nothing references; a network without its key is a network
	// nothing can join.
	SealNetworkIdentity func(ctx context.Context, tx *store.Tx, plaintext []byte) (string, error)

	// SealCAKey does the same for a CA signing key created by POST /v1/cas.
	// Nil refuses that endpoint.
	//
	// Separate from SealNetworkIdentity because the two are different kinds of
	// secret and the kind is authenticated into the ciphertext — one function
	// taking a kind would let a caller pass the wrong one, which is exactly the
	// substitution the binding exists to prevent.
	SealCAKey func(ctx context.Context, tx *store.Tx, networkID uuid.UUID, plaintext []byte) (string, error)
}

type Server struct {
	store   *store.Store
	enroll  *enroll.Service
	cfg     Config
	log     *slog.Logger
	limiter *Limiter

	// health is the last probe result, replaced wholesale rather than mutated
	// so /healthz can read it without ever taking a lock. healthProbe serializes
	// the probes themselves; see probeHealth.
	health      atomic.Pointer[healthSnapshot]
	healthProbe sync.Mutex
}

func New(st *store.Store, es *enroll.Service, cfg Config, log *slog.Logger) *Server {
	s := &Server{store: st, enroll: es, cfg: cfg, log: log}
	if !cfg.DisableEnrollLimit {
		s.limiter = NewLimiter(cfg.EnrollLimit)
	}

	// Seed the health snapshot rather than leaving it nil, so a /healthz that
	// arrives before any readiness probe answers something true instead of
	// "database: false" on a process that has never had a problem.
	//
	// A non-nil store means store.Open completed, and Open pings before it
	// returns — so Postgres was reachable a few milliseconds ago. The zero
	// timestamp marks it as stale, so the first readiness probe replaces it with
	// a measurement rather than trusting this indefinitely.
	s.health.Store(&healthSnapshot{database: st != nil, push: s.pushUp()})
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
	s.HealthRoutes(mux)
	// The same wrapping production gets, so development and tests exercise the
	// middleware rather than a path that only exists here.
	return Observe(s.log, mux)
}

func (s *Server) EnrollRoutes(mux *http.ServeMux) { register(mux, s.enrollRoutes()) }
func (s *Server) AgentRoutes(mux *http.ServeMux)  { register(mux, s.agentRoutes()) }
func (s *Server) AdminRoutes(mux *http.ServeMux)  { register(mux, s.adminRoutes()) }

// HealthRoutes mounts /healthz and /readyz.
//
// Separate from the other three registrations, and called in addition to them,
// because health is the one thing a listener needs regardless of what else it
// serves. Two listeners want it, for different reasons:
//
//   - The public listener, because that is where a load balancer, a reverse
//     proxy, and a systemd or Kubernetes probe actually look. Without this the
//     only unauthenticated request on that port is a POST to /enroll/v1, so a
//     proxy's health signal is a TCP connect — which stays green straight
//     through a total database outage.
//   - Each overlay listener, because it is a different socket with a different
//     way to fail. A replica can serve the public port perfectly while its
//     overlay listener is dead, and agents will keep round-robining onto it:
//     they discover replicas from EnrollResponse.AgentEndpoints, which is built
//     from control-plane heartbeats and says nothing about whether the agent
//     port answers. The exposure cost is nil — the overlay is reachable only by
//     certificate-verified mesh peers.
//
// Not on the metrics listener. It already answers this question in more detail,
// it is bound to localhost by default, and a third place to ask invites probing
// the wrong one.
//
// Deliberately unauthenticated, and it is worth being explicit about what that
// gives away. A stranger who can reach the port already knows the process is
// listening; what they gain is whether it can reach its database, whether push
// is up, and the build string. The first two are inferable from behaviour
// anyway — a degraded control plane fails requests — and the third is the real
// disclosure, which is why HealthResponse carries a version and nothing else
// about the deployment: no hostname, no network names, no counts.
func (s *Server) HealthRoutes(mux *http.ServeMux) { register(mux, s.healthRoutes()) }

func (s *Server) healthRoutes() []route {
	h := func(pattern string, fn http.HandlerFunc) route {
		return route{pattern: pattern, surface: surfaceHealth, h: fn}
	}
	return []route{
		h("GET /healthz", s.handleLive),
		h("GET /readyz", s.handleReady),
	}
}

func (s *Server) enrollRoutes() []route {
	e := func(pattern string, h http.HandlerFunc) route {
		// Every enroll route is rate limited. It is the only public,
		// unauthenticated, cryptographically expensive surface, so the limit is
		// applied here rather than per-route: a new route added without it
		// would be the gap, and this shape makes forgetting impossible.
		return route{pattern: pattern, surface: surfaceEnroll, h: s.limitEnroll(h)}
	}
	return []route{
		e("POST /enroll/v1/enroll", s.handleEnroll),
		// Joining and claiming live here rather than on the agent surface for
		// the reason recovery does, and more strongly: a device that has just
		// joined has no certificate, so it has no overlay, so it cannot reach
		// the only place the agent API listens.
		e("POST /enroll/v1/join", s.handleJoin),
		e("POST /enroll/v1/claim", s.handleClaim),
	}
}

func (s *Server) agentRoutes() []route {
	a := func(pattern string, h http.HandlerFunc) route {
		return route{pattern: pattern, surface: surfaceAgent, h: h}
	}
	return []route{
		a("GET /agent/v1/state", s.handleAgentState),
		a("GET /agent/v1/watch", s.handleAgentWatch),
		a("POST /agent/v1/report", s.handleAgentReport),
		a("POST /agent/v1/renew", s.handleAgentRenew),
	}
}

func (s *Server) adminRoutes() []route {
	a := func(pattern, scope string, h http.HandlerFunc) route {
		return route{pattern: pattern, surface: surfaceAdmin, scope: scope, h: s.admin(scope, h)}
	}
	out := []route{
		// There is deliberately no POST /v1/memberships.
		//
		// It created a membership that named no machine, which is the one thing
		// docs/model.md §5 invariant 1 forbids and the reason device_id could
		// not be NOT NULL. What it was FOR — deciding a machine's name, address
		// and role before it exists — is now a reservation: same intent,
		// recorded on the credential, redeemed into a membership that names its
		// device from the moment it exists.
		a("POST /v1/networks/{ref}/reservations", "memberships:create", s.handleReserve),
		a("GET /v1/memberships", "memberships:read", s.handleListHosts),
		a("GET /v1/memberships/{id}", "memberships:read", s.handleGetHost),
		// hosts:read, not a scope of its own: the response carries no PEM and
		// no key material, only what a host's own listing already implies.
		a("GET /v1/memberships/{id}/certificates", "memberships:read", s.handleHostCertificates),
		a("PATCH /v1/memberships/{id}", "memberships:write", s.handleUpdateHost),
		// Deletion revokes, so it takes hosts:block rather than hosts:write. A
		// token trusted to edit a host but not to cut one off must not reach
		// the stronger outcome through a different verb.
		a("DELETE /v1/memberships/{id}", "memberships:block", s.handleDeleteHost),
		a("POST /v1/memberships/{id}/enrollment-code", "memberships:enroll", s.handleCreateEnrollCode),
		// The authorization queue.
		//
		// hosts:create, not hosts:write. Authorizing a pending join is what
		// brings a machine onto the network — it allocates the address and
		// makes the membership real — so it is the same power POST /v1/memberships
		// carries, arriving through a different door. A token trusted to edit
		// existing hosts but not to add one must not be able to admit a
		// machine by approving it.
		a("GET /v1/networks/{ref}/pending", "memberships:read", s.handleListPending),
		a("POST /v1/memberships/{id}/authorize", "memberships:create", s.handleAuthorizeMembership),
		// Address changes take hosts:write, but the endpoint gates them behind a
		// typed acknowledgement of its own: an address change forces a nebula
		// restart, which drops every tunnel on that host and, for a relay, the
		// traffic it forwards for others.
		a("POST /v1/memberships/{id}/addresses", "memberships:write", s.handleAddHostAddress),
		a("DELETE /v1/memberships/{id}/addresses/{addr}", "memberships:write", s.handleRemoveHostAddress),
		a("POST /v1/memberships/{id}/block", "memberships:block", s.handleBlockHost),
		a("POST /v1/memberships/{id}/unblock", "memberships:block", s.handleUnblockHost),
		// Devices. Not network-scoped, deliberately: a machine on three
		// networks is one device with one posture, which is the whole reason
		// the noun exists.
		a("GET /v1/devices", "devices:read", s.handleListDevices),
		a("GET /v1/devices/{id}", "devices:read", s.handleGetDevice),
		// devices:write, not devices:block: setting where a machine is reachable
		// is an ordinary configuration change, and a token trusted to do it must
		// not thereby be able to cut machines off the network.
		a("PATCH /v1/devices/{id}/addrs", "devices:write", s.handleSetDeviceAddrs),
		a("POST /v1/devices/{id}/block", "devices:block", s.handleBlockDevice),
		a("POST /v1/devices/{id}/unblock", "devices:block", s.handleUnblockDevice),
		a("GET /v1/networks/{id}/convergence", "networks:read", s.handleConvergence),
	}
	return append(out, s.resourceRoutes()...)
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
		// Labelled by class, not by error string: an unbounded label set is
		// how a metrics endpoint becomes the thing that falls over.
		switch {
		case errors.Is(err, enroll.ErrInvalidCredential), errors.Is(err, enroll.ErrHostBlocked):
			s.cfg.Metrics.EnrollAttempt("rejected")
		case errors.Is(err, enroll.ErrInvalidPublicKey), errors.Is(err, enroll.ErrCurveMismatch):
			s.cfg.Metrics.EnrollAttempt("bad_request")
		default:
			s.cfg.Metrics.EnrollAttempt("error")
		}

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
		case errors.Is(err, ca.ErrOutsideCAValidity):
			// An expired active CA. The maintenance sweep deliberately leaves it
			// in place rather than retiring it (retirement is a rotation step and
			// cannot be undone through the API), so this state persists until an
			// operator acts — and without this branch it would surface as a
			// generic 500 with the actual cause visible only in the server log.
			s.log.Error("enrollment failed: the active CA cannot issue", "error", err)
			writeErr(w, http.StatusServiceUnavailable,
				"the network's certificate authority cannot issue: "+err.Error())
		default:
			s.log.Error("enrollment failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "enrollment failed")
		}
		return
	}
	s.cfg.Metrics.EnrollAttempt("ok")
	s.cfg.Metrics.CertificateIssued("enroll")
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
	if id.State == store.MembershipSuspended {
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

	resp, err := s.enroll.State(r.Context(), id.MembershipID, knownConfig, knownBlock)
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
		// Facts and posture describe the MACHINE and are recorded against the
		// device, not this membership. Best effort by design: a membership
		// created the old way has no device, and a report from one must still
		// record its epochs rather than fail because it has nowhere to put a
		// posture reading it did not have to send.
		if req.Facts != nil || req.Posture != nil {
			d, derr := tx.DeviceForHost(ctx, id.MembershipID)
			switch {
			case derr == nil:
				if req.Facts != nil {
					if err := tx.RecordDeviceFacts(ctx, d.ID, store.DeviceFacts{
						OS:            req.Facts.OS,
						OSVersion:     req.Facts.OSVersion,
						Kernel:        req.Facts.Kernel,
						Arch:          req.Facts.Arch,
						AgentVersion:  req.Facts.AgentVersion,
						NebulaVersion: req.Facts.NebulaVersion,
					}); err != nil {
						return err
					}
				}
				if req.Posture != nil {
					if err := tx.RecordDevicePosture(ctx, d.ID, store.DevicePosture{
						DiskEncrypted:   req.Posture.DiskEncrypted,
						SecureBoot:      req.Posture.SecureBoot,
						FirewallEnabled: req.Posture.FirewallEnabled,
						TPMPresent:      req.Posture.TPMPresent,
					}); err != nil {
						return err
					}
				}
			case errors.Is(derr, store.ErrNotFound):
				s.log.Debug("host reported posture but has no device; it predates the join path",
					"host", id.MembershipID)
			default:
				return derr
			}
		}

		return tx.RecordAgentReport(ctx, id.MembershipID, store.AgentReport{
			ConfigEpoch:    req.ConfigEpoch,
			BlocklistEpoch: req.BlocklistEpoch,
			NebulaVersion:  req.NebulaVersion,
			AgentVersion:   req.AgentVersion,

			// The revert fields are what let a recorded epoch move backwards —
			// the one exception to monotonicity, and the reason convergence can
			// stop reporting a host as converged on a generation its guard has
			// since thrown away. Dropping them here would leave the agent
			// reporting a revert that the control plane silently ignores, which
			// is exactly the failure this whole path exists to close.
			RevertedFromConfigEpoch:    req.RevertedFromConfigEpoch,
			RevertedFromBlocklistEpoch: req.RevertedFromBlocklistEpoch,
			QuarantinedConfigEpoch:     req.QuarantinedConfigEpoch,
		})
	})
	if err != nil {
		s.log.Error("agent report failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Counted and logged only for an actual revert. A pushed generation that
	// severs the fleet is invisible in every other channel: the hosts that
	// reverted look merely "behind", and the CA rotation gate would pass.
	if req.RevertedFromConfigEpoch != 0 {
		s.cfg.Metrics.ConfigReverted()
		s.log.Warn("host reverted a pushed generation; it could not reach the control plane after applying",
			"host", id.MembershipID,
			"revertedFrom", req.RevertedFromConfigEpoch,
			"nowAt", req.ConfigEpoch,
			"quarantined", req.QuarantinedConfigEpoch)
	}

	// A host whose agent is healthy but whose nebula is not carries no traffic
	// at all, and is invisible in every other channel: it polls, it reports an
	// applied epoch, and convergence counts it as converged. The agent
	// deliberately does not restart nebula — systemd owns that, and two
	// supervisors racing one process turns a crash loop into two — so saying so
	// here is the only way anyone finds out.
	if req.DataPlaneDown {
		s.log.Error("host reports nebula is not running; it is converged on paper and carrying no traffic",
			"host", id.MembershipID, "configEpoch", req.ConfigEpoch)
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

	resp, err := s.enroll.Renew(r.Context(), id.MembershipID, req)
	if err != nil {
		if errors.Is(err, enroll.ErrInvalidPublicKey) || errors.Is(err, enroll.ErrCurveMismatch) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.log.Error("renewal failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "renewal failed")
		return
	}
	s.cfg.Metrics.CertificateIssued("renew")
	writeJSON(w, http.StatusOK, resp)
}

//------------------------------------------------------------------------------
// Health surface
//------------------------------------------------------------------------------

// healthSnapshot is one observation of this process's dependencies.
type healthSnapshot struct {
	database bool
	push     bool
	// at is when the probe ran. The zero value is the seed from New, which is
	// always treated as stale.
	at time.Time
}

const (
	// healthCacheTTL bounds how often a probe reaches Postgres.
	//
	// Probes are the one caller that scales with the number of things watching
	// rather than with the work being done: a load balancer, a Kubernetes
	// readinessProbe, and an operator's curl loop all hit the same endpoint on
	// their own schedules, and an unbounded /readyz turns "add another monitor"
	// into "add another connection to the database". Two seconds pins that at
	// half a query per second per replica no matter how many watchers there
	// are, while staying under the shortest probe interval anyone configures in
	// practice — so a probe still sees a change on its very next poll, and the
	// answer is never more than one cycle behind the truth.
	healthCacheTTL = 2 * time.Second

	// healthProbeTimeout caps the probe itself. Shorter than any sane probe
	// timeout, because a readiness check that hangs is reported as a failure
	// with no detail, whereas one that answers "database: false" says what is
	// wrong.
	healthProbeTimeout = 2 * time.Second
)

// handleLive answers liveness: is this process running.
//
// Always 200, and it touches nothing. That is the entire point. A liveness
// probe that consulted Postgres would turn a single database outage into every
// replica being killed and restarted at once — which cannot fix the database,
// and which destroys the in-process state (parked watchers, the LISTEN
// connection) that would otherwise let the fleet recover the instant Postgres
// comes back. Restart is the wrong remedy for a dependency failure, so the
// dependency does not appear in this status code.
//
// The body still reports what the readiness path last observed, because it is
// free — no lock, no I/O — and because `curl /healthz` is what someone reaches
// for first. Status says "degraded" when that observation was bad, so the
// distinction is visible without the status code carrying it.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse(*s.health.Load()))
}

// handleReady answers readiness: can this process serve a useful request.
//
// It cannot, without Postgres — every endpoint here reads or writes it — so a
// database that is unreachable is a 503 and the load balancer takes this
// replica out. That is the opposite disposition from liveness, and deliberately
// so: taking one replica out of rotation is cheap and reversible, restarting it
// is neither.
//
// Push being down does not fail readiness. Agents fall back to polling, which
// is slower but entirely correct, and a replica that still serves every request
// should keep serving them. It shows in the body instead.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	snap := s.probeHealth(r.Context())

	status := http.StatusOK
	if !snap.database {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, healthResponse(snap))
}

func healthResponse(snap healthSnapshot) wire.HealthResponse {
	// "degraded" tracks the database only. Push has its own field, and a
	// deployment running with -no-push has deliberately turned it off — folding
	// that into the top-line status would report a deliberate configuration as
	// a fault forever.
	status := "degraded"
	if snap.database {
		status = "ok"
	}
	out := wire.HealthResponse{
		Status:   status,
		Database: snap.database,
		Push:     snap.push,
		Version:  Version,
	}
	// Omitted entirely when at is the zero value, which is the seed New stores:
	// that reading is inferred from store.Open having pinged, not measured, and
	// time.Since on a zero time is 292 years — a number that looks like a bug
	// and tells a reader nothing. Absent says "unverified" without pretending to
	// a precision that does not exist.
	if !snap.at.IsZero() {
		age := time.Since(snap.at).Round(time.Millisecond).Seconds()
		out.ObservedAgeSeconds = &age
	}
	return out
}

// probeHealth returns a recent observation, measuring a new one if the cached
// one has aged out.
func (s *Server) probeHealth(ctx context.Context) healthSnapshot {
	if snap := s.health.Load(); time.Since(snap.at) < healthCacheTTL {
		return *snap
	}

	s.healthProbe.Lock()
	defer s.healthProbe.Unlock()
	// Re-check under the lock. Probes queued behind one that has just finished
	// must read its result rather than each running their own, which is the
	// thundering herd the cache exists to prevent — and it arrives exactly when
	// the database is slow and every probe is waiting.
	if snap := s.health.Load(); time.Since(snap.at) < healthCacheTTL {
		return *snap
	}

	snap := healthSnapshot{at: time.Now(), push: s.pushUp()}
	if s.store != nil {
		// Not the caller's context. This result is cached and served to
		// everyone, so a client that hangs up mid-probe must not record
		// "database unreachable" on behalf of the next hundred probes.
		probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), healthProbeTimeout)
		defer cancel()

		// A real round trip, not a pool statistic. A pool happily reports idle
		// connections to a Postgres that has been promoted away, is out of
		// disk, or is refusing new transactions; the only honest test of "can I
		// serve a request" is to do what serving a request does.
		err := s.store.Read(probeCtx, func(context.Context, *store.Tx) error { return nil })
		snap.database = err == nil
		if err != nil {
			s.log.Warn("readiness probe could not reach the database", "error", err)
		}
	}

	s.health.Store(&snap)
	return snap
}

// pushUp reports whether the Postgres LISTEN connection is currently up.
//
// Nil notifier is false: push is not configured on this server at all, so every
// agent talking to it is polling. That is the operational truth even when it is
// the intended configuration.
//
// The state comes from the notifier and not from s.cfg.Metrics, which is the
// other place it is observable. Routing through the metrics collector would
// make a server built without metrics report push as up on the strength of it
// being configured, and "configured" is the one answer a health probe must
// never give to "is it working".
func (s *Server) pushUp() bool {
	return s.cfg.Notifier != nil && s.cfg.Notifier.Up()
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
