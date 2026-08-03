package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// identityKey carries the authenticated identity through the request.
type identityKey struct{}

func identityFrom(ctx context.Context) *store.Identity {
	id, _ := ctx.Value(identityKey{}).(*store.Identity)
	return id
}

// IdentityFrom returns the authenticated caller, or nil outside an
// authenticated handler. Exported for internal/web, whose handlers run behind
// the same middleware and read the identity the same way.
func IdentityFrom(ctx context.Context) *store.Identity { return identityFrom(ctx) }

// credential is one way of turning a request into a store.Identity.
//
// This is the seam. Authentication and the scope check are separate steps, and
// splitting the credential out makes the FIRST step pluggable without anything
// below it changing: a handler, a scope check, and an audit entry are written
// against an Identity and cannot tell which credential produced it. An OIDC
// subject is the next one that fits here.
//
// Each carries its own refusal messages because /v1's are load-bearing: they
// are what an operator's tooling reads, and this refactor must not change them
// by a byte.
type credential struct {
	// missing is the 401 body for a request carrying nothing of this kind.
	missing string
	// invalid is the 401 body for one carrying something that does not resolve.
	// Unknown, revoked, and expired all land here, undistinguished, for the
	// same reason enrollment does not distinguish them: a legible failure is a
	// probing oracle.
	invalid string
	// logAs names this credential in the log line the 500 path writes.
	logAs string
	// resolve returns errNoCredential when the request carries nothing of this
	// kind, store.ErrNotFound when it carries one that does not resolve.
	resolve func(*http.Request) (*store.Identity, error)
}

// errNoCredential means the request carried nothing of the kind the
// authenticator reads. Distinct from a credential that failed to resolve, so
// "you sent no cookie" and "your session has ended" stay tellable apart by the
// person in front of the browser. Neither reveals whether any particular
// credential exists, which is the property that matters to a prober.
var errNoCredential = errors.New("no credential")

// ErrBearerOnUISurface refuses an Authorization header on the browser surface.
//
// THE HARD RULE, in its second direction. The browser surface is not an API:
// every /v1 route was written assuming bearer authentication, which is
// CSRF-immune, and the browser surface exists precisely because a cookie is
// not. Accepting a bearer token here would create a second, unaudited way to
// reach UI handlers and would invite a client to be written against it — at
// which point "the UI surface is cookie-only" stops being true and the
// isolation stops being checkable.
//
// Exported so internal/web can tell this apart from an ordinary sign-in
// failure; it is a caller mistake, not a credential problem.
var ErrBearerOnUISurface = errors.New(
	"the browser surface does not accept an Authorization header; use /v1 with a bearer token")

// authenticate wraps a handler with a credential and a scope check.
//
// Authentication establishes identity; the scope check is separate and explicit
// per route, so adding a route without deciding its scope is a compile-time
// omission rather than an accidentally-public endpoint.
//
// Nothing below this function knows what a token is, and now nothing below it
// knows what a session is either.
func (s *Server) authenticate(c credential, scope string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := c.resolve(r)
		switch {
		case errors.Is(err, errNoCredential):
			writeErr(w, http.StatusUnauthorized, c.missing)
			return
		case errors.Is(err, ErrBearerOnUISurface):
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		case errors.Is(err, store.ErrNotFound):
			writeErr(w, http.StatusUnauthorized, c.invalid)
			return
		case err != nil:
			s.log.Error(c.logAs, "error", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}

		if !RequireScope(w, id, scope) {
			return
		}

		// The token's last_used_at is recorded for a session too. A session IS
		// use of the token it references, and "was this credential used after
		// we revoked it" is the question an incident asks — it would be
		// answered wrongly if a token with a live browser attached to it looked
		// untouched.
		s.store.TouchToken(r.Context(), id.TokenID)
		h(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	})
}

// RequireScope enforces a route's scope, writing the 403 if it fails and
// reporting whether the caller may proceed.
//
// An empty scope means authentication only. Used by /v1/whoami, which must
// answer for any valid credential — including one whose scopes the caller is
// trying to discover.
//
// Exported so the browser surface refuses with the identical response rather
// than a second dialect of the same refusal. The message says "token" for a
// session too, and correctly: a session's scopes ARE the token's, narrowed, and
// there is no separate grant to point an operator at.
func RequireScope(w http.ResponseWriter, id *store.Identity, scope string) bool {
	if scope == "" || id.HasScope(scope) {
		return true
	}
	writeErr(w, http.StatusForbidden, "token lacks required scope: "+scope)
	return false
}

// bearerCredential is /v1: scoped API tokens in an Authorization header, and
// nothing else. It does not look at cookies and must never learn how.
func (s *Server) bearerCredential() credential {
	return credential{
		missing: "missing bearer token",
		invalid: "invalid token",
		logAs:   "token authentication failed",
		resolve: func(r *http.Request) (*store.Identity, error) {
			token, ok := bearerToken(r)
			if !ok {
				return nil, errNoCredential
			}
			return s.store.AuthenticateToken(r.Context(), hashToken(token))
		},
	}
}

// admin wraps a handler for the /v1 surface.
//
// Bearer tokens, and only bearer tokens. THE HARD RULE lives in this one line:
// /v1 is built from bearerCredential, which reads the Authorization header and
// has no path to a cookie, so no /v1 route can be reached by a cross-site
// request no matter what a browser attaches to it. Every route here was written
// on that assumption — DELETE /v1/hosts/{id} takes its reason from a query
// parameter — so honouring a cookie on this surface would make all of them
// CSRF-able at once. e2e/session_isolation_test.go asserts both directions.
func (s *Server) admin(scope string, h http.HandlerFunc) http.Handler {
	return s.authenticate(s.bearerCredential(), scope, h)
}

// SessionCookieName is the browser session cookie.
//
// The __Host- prefix is a browser-enforced invariant, and it is the closest
// thing a cookie has to a database constraint: a browser refuses to store a
// __Host- cookie unless it is Secure, has Path=/, and carries NO Domain
// attribute. That last one is what matters. Without it, a compromised or merely
// sloppy sibling host — anything under the registrable domain — can set a
// cookie the console will then present as its own, and session fixation stops
// being a theoretical entry in a checklist.
//
// It also means the cookie cannot be scoped to a subdomain even deliberately,
// which is a constraint worth accepting rather than working around.
const SessionCookieName = "__Host-orbit_session"

// checkHint turns a CHECK-constraint refusal into something an operator can act
// on.
//
// The constraint name alone is accurate and nearly useless — "violates
// network_ipv6_requires_cert_v2" states the rule without the reason, and the
// reason is the part that stops someone retrying the same request. Constraints
// whose intent is self-evident from their name are left to speak for
// themselves.
func checkHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "network_ipv6_requires_cert_v2"):
		// The one an operator is most likely to hit and least likely to guess:
		// nothing about "add this prefix" suggests the certificate version is
		// involved.
		return "a network with an IPv6 prefix must use cert_version 2: nebula's " +
			"version 1 certificate format cannot carry an IPv6 address at all " +
			"(cert/cert_v1.go refuses it outright), so this would be stored cleanly " +
			"and then fail at the first issuance, with the enrollment code already spent"
	case strings.Contains(msg, "network_slug_immutable"):
		return "a network's slug cannot be changed: it is the directory name " +
			"(/var/lib/orbit/<slug>) on every managed host in the network, so changing " +
			"it would not rename anything — it would strand the old directory and make " +
			"every agent create a second one beside it. Edit the display name instead"
	case strings.Contains(msg, "network_slug_charset"):
		return "a network slug must be 1-32 lowercase letters, digits, and hyphens with " +
			"no leading or trailing hyphen: it becomes a directory name and the stem of " +
			"an interface name, which is why periods and underscores are not usable"
	case strings.Contains(msg, "network_name_shape"):
		return "a network name must be 1-65 letters, digits, spaces, apostrophes, and " +
			"hyphens with no leading or trailing whitespace: it is a display label, and " +
			"one that ends in a space renders identically to one that does not while " +
			"comparing unequal"
	case strings.Contains(msg, "network_policy_source_requires_document"):
		return "a network cannot draw its firewall from a policy document it does not have: " +
			"nebula's firewall is default-deny, so every host would render an empty rule set " +
			"and drop all traffic while reporting a successful apply. " +
			"PUT a policy document first"
	case strings.Contains(msg, "host_tun_dev"):
		return "a tun device name must be 15 characters or fewer: Linux copies it into a " +
			"fixed 16-byte field with no error, so a longer one is silently truncated and " +
			"two long names collide into a single interface"
	default:
		return "the database refused that value: " + msg
	}
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
	case errors.Is(err, store.ErrInvalid):
		// A CHECK constraint refused the value. 400, not 500: the request will
		// never succeed as sent, and the operator needs to know that rather
		// than retry. The constraint name is in the error and is the only thing
		// distinguishing one rule from another, so it goes in the message —
		// checkHint turns the ones with a non-obvious reason into a sentence.
		writeErr(w, http.StatusBadRequest, checkHint(err))
	case errors.Is(err, enroll.ErrHostBlocked):
		writeErr(w, http.StatusForbidden, "host is blocked")
	case errors.Is(err, store.ErrNoActived):
		writeErr(w, http.StatusServiceUnavailable, "network has no active certificate authority")
	default:
		s.log.Error("admin request failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

// handleCreateHost creates a host, allocating its overlay address unless one is
// named.
//
// The address is optional now, and that is the important half. Requiring one
// made every caller keep a record of which addresses are in use — a spreadsheet,
// a runbook, a colleague's memory — and be wrong about it occasionally, at which
// point the database's primary key refused the request and the operator picked
// another number by hand. The control plane already holds the only authoritative
// answer to "what is free"; asking it is strictly better than asking a human to
// remember.
//
// Allocation runs inside this transaction, so a host and its address commit
// together. A host that exists with no address is not partially configured, it
// is one that can never be issued a certificate.
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
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}

	var addr netip.Addr
	if req.OverlayAddr != "" {
		if addr, err = netip.ParseAddr(req.OverlayAddr); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid overlay_addr")
			return
		}
	}
	var prefix netip.Prefix
	if req.OverlayPrefix != "" {
		if prefix, err = netip.ParsePrefix(req.OverlayPrefix); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid overlay_prefix")
			return
		}
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

	var (
		host store.Host
		net  *store.Network
	)
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		net, err = tx.GetNetwork(ctx, networkID)
		if err != nil {
			return err
		}

		host = store.Host{
			NetworkID:    networkID,
			Name:         req.Name,
			RoleID:       roleID,
			Tags:         req.Tags,
			IsLighthouse: req.IsLighthouse,
			IsRelay:      req.IsRelay,
			StaticAddrs:  req.StaticAddrs,
		}

		if addr.IsValid() {
			// Catch an out-of-range address here rather than at issuance. The
			// database would accept it, and the failure would then surface much
			// later as a certificate the CA refuses to sign.
			if !net.ContainsAddr(addr) {
				return errOutOfRange
			}
			host.Addrs = []netip.Addr{addr}
			if err := tx.CreateHost(ctx, &host); err != nil {
				return err
			}
		} else if err := tx.CreateHostAllocating(ctx, net, &host, prefix); err != nil {
			return err
		}

		return tx.AppendAudit(ctx, id.Audit(store.ActionHostCreated, "host", host.ID.String()))
	})
	if err != nil {
		if errors.Is(err, errOutOfRange) {
			writeErr(w, http.StatusBadRequest, "overlay_addr is not within the network")
			return
		}
		if s.writeAllocationError(w, err) {
			return
		}
		s.notFoundOr(w, err, "network")
		return
	}

	writeJSON(w, http.StatusCreated, hostResponse(&host, net))
}

var errOutOfRange = errors.New("overlay address is not within the network")

// writeAllocationError renders the failures specific to claiming an address,
// and reports whether it handled err.
//
// Exhaustion is a 409 that NAMES THE PREFIX. It is not a 500, because nothing
// broke; it is not a 400, because the request was well-formed; and it must never
// be a timeout, which is what an allocator that retried until the context died
// would produce — an operator watching a request hang has no way to tell a full
// /24 from a database that has stopped answering.
func (s *Server) writeAllocationError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, store.ErrAddressExhausted):
		writeErr(w, http.StatusConflict, err.Error()+
			"; add another prefix to the network, or release an address")
		return true
	case errors.Is(err, store.ErrAddrOutOfRange):
		writeErr(w, http.StatusBadRequest, err.Error())
		return true
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict,
			"that overlay address is already claimed by another host in this network")
		return true
	}
	return false
}

// handleListHosts serves the fleet: filtered, keyset-paginated, in an envelope.
//
// Every filter is passed to the store and applied in SQL. A parameter accepted
// and dropped here would be worse than one not offered, for the same reason it
// is on the audit trail: the caller reads an unfiltered page as the answer to
// the question they asked, and "nothing matches" is the wrong conclusion to
// draw during an incident. So an unparseable value is a 400 that names it.
func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	networkID, err := uuid.Parse(q.Get("network_id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "network_id query parameter is required")
		return
	}

	f := store.HostFilter{
		NetworkID:    networkID,
		Tag:          q.Get("tag"),
		NameContains: q.Get("name_contains"),
	}

	if v := q.Get("state"); v != "" {
		if !containsStr(listableHostStates, v) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf(
				"state must be one of %s; any other value matches no host and would read as an empty fleet",
				strings.Join(listableHostStates, ", ")))
			return
		}
		f.State = v
	}
	if v := q.Get("role_id"); v != "" {
		roleID, err := uuid.Parse(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest,
				"role_id must be a uuid, not a role name; anything else matches no host "+
					"and would read as a role nobody carries")
			return
		}
		f.RoleID = &roleID
	}

	var ok bool
	if f.Behind, ok = boolParam(w, q, "behind"); !ok {
		return
	}
	if f.WithCount, ok = boolParam(w, q, "count"); !ok {
		return
	}
	if f.Limit, ok = pageLimitParam(w, q, store.HostPageMax); !ok {
		return
	}
	if v := q.Get("cursor"); v != "" {
		c, err := decodeHostCursor(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest,
				"cursor is not one this endpoint issued; pass next_cursor back unmodified, "+
					"or omit it to start from the beginning")
			return
		}
		f.After = &c
	}

	var (
		page store.HostPage
		net  *store.Network
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if page, err = tx.ListHosts(ctx, f); err != nil {
			return err
		}
		// Read once for the whole page, so resolving each host's inherited
		// listen port and config mode costs one query rather than one per row —
		// the same cost the role name is denormalized into hostCols to avoid.
		// A missing network is not an error here; see the note below on why an
		// unknown id yields an empty page.
		if net, err = tx.GetNetwork(ctx, f.NetworkID); errors.Is(err, store.ErrNotFound) {
			net = nil
			return nil
		}
		return err
	})
	if err != nil {
		s.notFoundOr(w, err, "network")
		return
	}

	// An unknown network id yields an empty page rather than a 404, as it did
	// before pagination: the filter is a network id, and a listing endpoint
	// that distinguishes "no such network" from "no hosts yet" is one more way
	// to probe for which ids exist.
	resp := wire.HostListResponse{
		Hosts:      make([]wire.HostResponse, 0, len(page.Hosts)),
		TotalCount: page.Total,
	}
	for i := range page.Hosts {
		resp.Hosts = append(resp.Hosts, hostResponse(&page.Hosts[i], net))
	}
	// The cursor comes from the last row actually returned, and only when the
	// store saw one more beyond it. A cursor emitted on a full final page would
	// send every client one request further to learn nothing.
	if page.More && len(page.Hosts) > 0 {
		resp.NextCursor = encodeHostCursor(&page.Hosts[len(page.Hosts)-1])
	}
	writeJSON(w, http.StatusOK, resp)
}

// listableHostStates are the states a host can be listed in. 'deleted' is
// absent because DeleteHost removes the row: the state exists for a host on its
// way out, and offering it as a filter would promise a listing of decommissioned
// machines that is always empty.
var listableHostStates = []string{
	store.HostCreated, store.HostEnrolled, store.HostActive, store.HostSuspended,
}

// handleHostCertificates serves a host's certificate history.
//
// The question at the centre of every rotation and every renewal failure —
// when does this expire, which CA signed it, has it been renewing — was
// answerable only from psql before this route existed.
func (s *Server) handleHostCertificates(w http.ResponseWriter, r *http.Request) {
	hostID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	q := r.URL.Query()
	var f store.CertFilter
	if v := q.Get("state"); v != "" {
		if !containsStr(certStates, v) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf(
				"state must be one of %s; any other value matches nothing and would read "+
					"as a host that has never been issued a certificate",
				strings.Join(certStates, ", ")))
			return
		}
		f.State = v
	}
	if f.Limit, ok = pageLimitParam(w, q, store.CertPageMax); !ok {
		return
	}
	if v := q.Get("cursor"); v != "" {
		c, err := decodeCertCursor(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest,
				"cursor is not one this endpoint issued; pass next_cursor back unmodified, "+
					"or omit it to start from the newest certificate")
			return
		}
		f.After = &c
	}

	var page store.CertPage
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		// Resolve the host first so an unknown id is a 404. Without it, a typo'd
		// host id and a host that has never enrolled both return an empty list,
		// and during a failed enrollment those are opposite diagnoses.
		if _, err := tx.GetHost(ctx, hostID); err != nil {
			return err
		}
		var err error
		page, err = tx.HostCertificates(ctx, hostID, f)
		return err
	})
	if err != nil {
		s.notFoundOr(w, err, "host")
		return
	}

	resp := wire.CertificateListResponse{
		Certificates: make([]wire.CertificateResponse, 0, len(page.Certificates)),
	}
	for _, c := range page.Certificates {
		resp.Certificates = append(resp.Certificates, certificateResponse(c))
	}
	if page.More && len(page.Certificates) > 0 {
		resp.NextCursor = encodeCertCursor(page.Certificates[len(page.Certificates)-1])
	}
	writeJSON(w, http.StatusOK, resp)
}

var certStates = []string{
	store.CertPending, store.CertActive, store.CertSuperseded, store.CertRevoked,
}

// Cursors are opaque to the client on purpose: they encode a sort key, and a
// client that learns to read one has taken a dependency on an ordering this API
// is free to change. They are not signed, because a cursor names a position in a
// listing the caller is already authorized to read — a forged one either fails
// to decode or starts a page somewhere harmless, and neither reveals a row the
// caller could not have paged to anyway.
//
// NUL is the field separator because Postgres text cannot contain one, so no
// host name can ever collide with it.

func encodeHostCursor(h *store.Host) string {
	return base64.RawURLEncoding.EncodeToString([]byte(h.Name + "\x00" + h.ID.String()))
}

func decodeHostCursor(s string) (store.HostCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return store.HostCursor{}, err
	}
	name, rest, found := strings.Cut(string(raw), "\x00")
	if !found {
		return store.HostCursor{}, errBadCursor
	}
	id, err := uuid.Parse(rest)
	if err != nil {
		return store.HostCursor{}, err
	}
	return store.HostCursor{Name: name, ID: id}, nil
}

func encodeCertCursor(c store.CertificateRow) string {
	// Nanosecond precision, because two renewals inside the same second are
	// ordinary and a cursor rounded to the second would re-serve or skip them.
	return base64.RawURLEncoding.EncodeToString(
		[]byte(c.IssuedAt.Format(time.RFC3339Nano) + "\x00" + c.ID.String()))
}

func decodeCertCursor(s string) (store.CertCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return store.CertCursor{}, err
	}
	at, rest, found := strings.Cut(string(raw), "\x00")
	if !found {
		return store.CertCursor{}, errBadCursor
	}
	issued, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return store.CertCursor{}, err
	}
	id, err := uuid.Parse(rest)
	if err != nil {
		return store.CertCursor{}, err
	}
	return store.CertCursor{IssuedAt: issued, ID: id}, nil
}

var errBadCursor = errors.New("malformed cursor")

// boolParam parses an optional flag. Absent means false; present and
// unparseable is refused rather than treated as false, because silently
// ignoring ?behind=yes returns the whole fleet as the answer to "who is behind".
func boolParam(w http.ResponseWriter, q url.Values, name string) (bool, bool) {
	v := q.Get(name)
	if v == "" {
		return false, true
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		writeErr(w, http.StatusBadRequest, name+" must be true or false")
		return false, false
	}
	return b, true
}

// pageLimitParam parses an optional page size. Zero means the store's default.
//
// A limit above the ceiling is refused rather than clamped: the store falls back
// to its default page for an out-of-range value, so asking for more than the
// maximum would return fewer rows than asking for nothing, with nothing in the
// response to say why.
func pageLimitParam(w http.ResponseWriter, q url.Values, max int) (int, bool) {
	v := q.Get("limit")
	if v == "" {
		return 0, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
		return 0, false
	}
	if n > max {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(
			"limit must be %d or fewer; a larger value returns the default page, not more", max))
		return 0, false
	}
	return n, true
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

	var (
		host *store.Host
		net  *store.Network
	)
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		host, err = tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		if net, err = tx.GetNetwork(ctx, host.NetworkID); err != nil {
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
	writeJSON(w, http.StatusOK, hostResponse(host, net))
}

var errLighthouseNeedsAddr = errors.New("lighthouse requires static_addrs")

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	hostID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var (
		host  *store.Host
		net   *store.Network
		certs store.CertPage
	)
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		host, err = tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		if net, err = tx.GetNetwork(ctx, host.NetworkID); err != nil {
			return err
		}
		// The current certificate, on the detail response rather than behind a
		// second request. Expiry is the first thing an operator opening a host
		// wants, and one extra query on a single-host read is a different cost
		// from one per row in a listing, which is why this is not in ListHosts.
		//
		// The limit is a bound, not a page: certificate_one_active_per_host_version
		// permits one active certificate per cert_version, so this is one row,
		// or two during a v1-to-v2 migration.
		certs, err = tx.HostCertificates(ctx, hostID,
			store.CertFilter{State: store.CertActive, Limit: 8})
		return err
	})
	if err != nil {
		s.notFoundOr(w, err, "host")
		return
	}

	resp := hostResponse(host, net)
	for _, c := range certs.Certificates {
		resp.ActiveCertificates = append(resp.ActiveCertificates, certificateResponse(c))
	}
	writeJSON(w, http.StatusOK, resp)
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

//------------------------------------------------------------------------------
// Overlay addresses
//------------------------------------------------------------------------------

// THE ADDRESS-CHANGE GATE.
//
// Adding, changing, or removing an overlay address is refused with 409 unless
// the caller sends a typed acknowledgement, in the same shape CA activation
// uses. The shape is deliberate — a typed field rather than a query flag,
// because it must be impossible to take by accident, and its own audit action
// rather than a flag in metadata, because "which changes knowingly restarted a
// running host" is a question an incident review asks with a WHERE clause.
//
// ONE IMPORTANT DIFFERENCE FROM CA ACTIVATION, and every word of the response
// depends on it. That gate is a CONVERGENCE gate: it refuses because hosts have
// not caught up, and waiting fixes it, so the message tells an operator to
// retry later. This one is not. Nebula compares the networks in a reloaded
// certificate against the running one and refuses the whole reload if they
// differ (pki.go reloadCert), so after an address change the host installs the
// new certificate, nebula declines it, and the process keeps running the old
// one. No amount of waiting changes that. Telling an operator to retry later
// would be advice that can never come true, so this gate says what the change
// costs and how to proceed instead.
//
// And the cost is NOT the same for every host, which is why the refusal carries
// a role-aware impact rather than one sentence. A restart on an ordinary host
// drops its own tunnels. A restart on a relay drops traffic it is forwarding FOR
// OTHER HOSTS — machines nobody making this change was thinking about — so that
// line leads.

// addressGate decides whether an address change may proceed, and describes what
// it costs.
//
// Returns (impact, refuse). refuse is false when the caller acknowledged, and
// also when there is nothing to disrupt: a host that has never enrolled has no
// certificate and no running nebula, and one being deleted is on its way off the
// mesh anyway. Gating those would train operators to send the acknowledgement
// reflexively, which is how a gate becomes worse than no gate.
func addressGate(impact *store.AddressImpact, acknowledged bool) (*wire.AddressImpact, bool) {
	if !impact.Disruptive() {
		return nil, false
	}
	return addressImpactResponse(impact), !acknowledged
}

func addressImpactResponse(i *store.AddressImpact) *wire.AddressImpact {
	out := &wire.AddressImpact{
		HostID:         i.HostID.String(),
		HostName:       i.HostName,
		IsLighthouse:   i.IsLighthouse,
		IsRelay:        i.IsRelay,
		IsControlPlane: i.IsControlPlane,

		OnlyLighthouse:   i.OnlyLighthouse(),
		OnlyRelay:        i.OnlyRelay(),
		OnlyControlPlane: i.OnlyControlPlane(),

		HostsInNetwork:    i.Hosts,
		Lighthouses:       i.Lighthouses,
		Relays:            i.Relays,
		LiveControlPlanes: i.LiveControlPlanes,
	}

	// Worst first, and the relay line is first on purpose: it is the only one
	// whose damage lands on machines that have nothing to do with this request.
	if i.IsRelay {
		out.HostsUsingRelays = i.RelayClients
		line := fmt.Sprintf(
			"%s RELAYS FOR OTHER HOSTS. Restarting it drops the traffic it is forwarding, "+
				"not just its own: %d host(s) in this network are configured to use relays",
			i.HostName, i.RelayClients)
		if i.OnlyRelay() {
			line += ", and it is the ONLY relay in this network, so every pair that " +
				"cannot reach each other directly loses its path until it is back"
		} else {
			line += fmt.Sprintf(", and %d other relay(s) remain to carry them", i.Relays-1)
		}
		out.Consequences = append(out.Consequences, line)
	}

	if i.IsControlPlane {
		line := fmt.Sprintf("%s serves the agent API for this network", i.HostName)
		if i.OnlyControlPlane() {
			line += ", and it is the ONLY live replica: for the duration of the restart " +
				"every agent on this network loses renewal and revocation"
		} else {
			line += fmt.Sprintf(", and %d other live replica(s) keep answering", i.LiveControlPlanes-1)
		}
		out.Consequences = append(out.Consequences, line)
	}

	if i.IsLighthouse {
		line := fmt.Sprintf("%s is a lighthouse, so discovery through it stops for the duration; "+
			"hosts that already hold a tunnel are unaffected, hosts still looking for a peer are not",
			i.HostName)
		if i.OnlyLighthouse() {
			line += ". It is the ONLY lighthouse in this network"
		} else {
			line += fmt.Sprintf(". %d other lighthouse(s) remain", i.Lighthouses-1)
		}
		out.Consequences = append(out.Consequences, line)
	}

	out.Consequences = append(out.Consequences, fmt.Sprintf(
		"nebula restarts on %s: its own tunnels drop and re-handshake", i.HostName))
	return out
}

// restartRequiredBody is the 409.
func restartRequiredBody(impact *wire.AddressImpact) wire.RestartRequiredError {
	lead := "changing this host's overlay addresses requires restarting its nebula"
	if impact.IsRelay {
		lead = "changing this host's overlay addresses requires restarting a RELAY, " +
			"which drops traffic it forwards for other hosts"
	}
	return wire.RestartRequiredError{
		Error: lead + "; resend with acknowledge_restart to proceed",
		// No "retry once it converges". The restart is unavoidable however long
		// anyone waits, and saying otherwise would send an operator to poll a
		// number that will never move.
		Detail: "The addresses are inside the signed certificate, and nebula refuses a " +
			"certificate reload whose networks changed: the host will install the new " +
			"certificate, nebula will decline it, and the old one keeps running until the " +
			"process restarts. Waiting does not help. Proceed when you can absorb the " +
			"restart, or leave the address alone",
		Impact: impact,
	}
}

// handleAddHostAddress claims an additional overlay address for a host.
//
// The second address is a real operation rather than a curiosity: a host moving
// between prefixes needs both for the transition, and a dual-stack host needs
// one per family. It is gated because adding one still rewrites the certificate,
// and a certificate whose networks changed is one nebula will not hot-reload.
func (s *Server) handleAddHostAddress(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	hostID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var req wire.AddHostAddressRequest
	if r.ContentLength > 0 {
		if !decode(w, r, &req) {
			return
		}
	}

	var (
		addr   netip.Addr
		prefix netip.Prefix
		err    error
	)
	if req.Addr != "" {
		if addr, err = netip.ParseAddr(req.Addr); err != nil {
			writeErr(w, http.StatusBadRequest, "addr is not an IP address")
			return
		}
	}
	if req.Prefix != "" {
		if prefix, err = netip.ParsePrefix(req.Prefix); err != nil {
			writeErr(w, http.StatusBadRequest, "prefix is not a CIDR")
			return
		}
	}

	var (
		resp    wire.HostAddressesResponse
		impact  *wire.AddressImpact
		refused bool
	)
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		net, err := tx.GetNetwork(ctx, host.NetworkID)
		if err != nil {
			return err
		}

		raw, err := tx.AddressChangeImpact(ctx, hostID, time.Now().Add(-enroll.DefaultControlPlaneStaleAfter))
		if err != nil {
			return err
		}
		impact, refused = addressGate(raw, req.AcknowledgeRestart)
		if refused {
			return errRestartRequired
		}

		if addr.IsValid() {
			if err := tx.ClaimHostAddress(ctx, net, hostID, addr); err != nil {
				return err
			}
		} else if addr, err = tx.AllocateHostAddress(ctx, net, hostID, prefix); err != nil {
			return err
		}

		epoch, err := tx.MarkAddressChanged(ctx, host.NetworkID, hostID)
		if err != nil {
			return err
		}

		after, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		resp = addressesResponse(after, epoch, impact != nil)

		return tx.AppendAudit(ctx, addressAudit(*id, hostID, store.ActionHostAddressAdded,
			store.ActionHostAddressAddedWithRestart, addr, impact))
	})
	if err != nil {
		if errors.Is(err, errRestartRequired) {
			writeJSON(w, http.StatusConflict, restartRequiredBody(impact))
			return
		}
		if s.writeAllocationError(w, err) {
			return
		}
		s.notFoundOr(w, err, "host")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRemoveHostAddress releases one of a host's overlay addresses.
//
// Removing the last one is refused outright and is not something the
// acknowledgement can override, because it is not a disruption to weigh: a host
// with no address cannot be issued a certificate at all (enroll.certNetworks
// refuses it), so the result is not a host that is down until it restarts, it is
// a host that can never come back without an operator noticing and adding an
// address by hand.
func (s *Server) handleRemoveHostAddress(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	hostID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	addr, err := netip.ParseAddr(r.PathValue("addr"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "addr is not an IP address")
		return
	}

	var req wire.RemoveHostAddressRequest
	if r.ContentLength > 0 {
		if !decode(w, r, &req) {
			return
		}
	}

	var (
		resp    wire.HostAddressesResponse
		impact  *wire.AddressImpact
		refused bool
	)
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}

		raw, err := tx.AddressChangeImpact(ctx, hostID, time.Now().Add(-enroll.DefaultControlPlaneStaleAfter))
		if err != nil {
			return err
		}
		impact, refused = addressGate(raw, req.AcknowledgeRestart)
		if refused {
			return errRestartRequired
		}

		if err := tx.RemoveHostAddress(ctx, host.NetworkID, hostID, addr); err != nil {
			return err
		}
		epoch, err := tx.MarkAddressChanged(ctx, host.NetworkID, hostID)
		if err != nil {
			return err
		}

		after, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		resp = addressesResponse(after, epoch, impact != nil)

		return tx.AppendAudit(ctx, addressAudit(*id, hostID, store.ActionHostAddressRemoved,
			store.ActionHostAddressRemovedWithRestart, addr, impact))
	})
	if err != nil {
		switch {
		case errors.Is(err, errRestartRequired):
			writeJSON(w, http.StatusConflict, restartRequiredBody(impact))
		case errors.Is(err, store.ErrLastAddress):
			// 409, not 400: the request is well-formed and the system is simply
			// not in a state that permits it. Named consequence, because "cannot
			// remove" without the reason invites someone to look for a force flag.
			writeErr(w, http.StatusConflict, err.Error()+
				"; a host with no overlay address can never be issued a certificate, "+
				"so add the replacement address first")
		default:
			s.notFoundOr(w, err, "host address")
		}
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

var errRestartRequired = errors.New("address change requires a nebula restart")

func addressesResponse(h *store.Host, epoch int64, disruptive bool) wire.HostAddressesResponse {
	out := wire.HostAddressesResponse{
		HostID:               h.ID.String(),
		OverlayAddrs:         addrStrings(h.Addrs),
		RestartRequiredEpoch: h.RestartRequiredEpoch,
		ConfigEpoch:          epoch,
	}
	switch {
	case !disruptive:
		out.Detail = "the host has not enrolled, so there is nothing running to disrupt; " +
			"it will be issued a certificate carrying these addresses when it does"
	default:
		out.Detail = fmt.Sprintf(
			"renewal is pulled forward so this host reissues with the new addresses, "+
				"and its agent restarts nebula once it has applied generation %d — "+
				"a reload cannot carry an address change", h.RestartRequiredEpoch)
	}
	return out
}

// addressAudit files the acknowledged path under its own action.
//
// Not the ordinary action with a flag in the metadata, for the same reason
// ca.force_activated is not ca.activated: an entry that says a running host was
// knowingly restarted — and whether that host was a relay — is what an incident
// review looks for, and it should be a WHERE clause rather than a scan through
// jsonb.
func addressAudit(id store.Identity, hostID uuid.UUID, plain, withRestart string, addr netip.Addr, impact *wire.AddressImpact) store.AuditEntry {
	action := plain
	meta := fmt.Sprintf(`{"addr":%q}`, addr.String())
	if impact != nil {
		action = withRestart
		meta = fmt.Sprintf(
			`{"addr":%q,"is_relay":%t,"is_lighthouse":%t,"is_control_plane":%t,`+
				`"only_relay":%t,"only_lighthouse":%t,"only_control_plane":%t,`+
				`"hosts_using_relays":%d}`,
			addr.String(), impact.IsRelay, impact.IsLighthouse, impact.IsControlPlane,
			impact.OnlyRelay, impact.OnlyLighthouse, impact.OnlyControlPlane,
			impact.HostsUsingRelays)
	}
	e := id.Audit(action, "host", hostID.String())
	e.Meta = []byte(meta)
	return e
}

//------------------------------------------------------------------------------
// Network prefixes and the display name
//------------------------------------------------------------------------------

// handleAddNetworkCIDR grows a network's address space.
//
// No config epoch bump, and that was checked rather than assumed: renderFor
// builds its Input from the topology, the blocklist, the trust bundle and the
// host's role, and a network's prefixes appear in none of them. They reach a
// host only through its certificate, at issuance. Bumping would wake every agent
// in the network to re-render a byte-identical file.
func (s *Server) handleAddNetworkCIDR(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())

	var req wire.NetworkCIDRRequest
	if !decode(w, r, &req) {
		return
	}
	p, err := netip.ParsePrefix(req.CIDR)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "cidr is not a CIDR, e.g. \"10.42.0.0/16\"")
		return
	}

	var out *store.Network
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		net, err := s.resolveNetwork(ctx, tx, r)
		if err != nil {
			return err
		}
		out, err = tx.AddNetworkCIDR(ctx, net.ID, p.Masked())
		if err != nil {
			return err
		}
		e := id.Audit(store.ActionNetworkCIDRAdded, "network", net.ID.String())
		e.Meta = []byte(fmt.Sprintf(`{"cidr":%q}`, p.Masked().String()))
		return tx.AppendAudit(ctx, e)
	})
	if err != nil {
		if errors.Is(err, store.ErrCIDROverlap) {
			// 409 with the reason. Overlapping prefixes make the certificate a
			// host is issued depend on array order, and the difference between a
			// /16 and a /24 in a certificate is the difference between reaching
			// the overlay and treating every peer as off-net.
			writeErr(w, http.StatusConflict, err.Error()+
				"; overlapping prefixes make a host's certificate depend on the order "+
				"the prefixes happen to be stored in")
			return
		}
		if errors.Is(err, store.ErrInvalid) {
			// The likeliest one by far: an IPv6 prefix on a version 1 network.
			writeErr(w, http.StatusBadRequest, checkHint(err))
			return
		}
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, networkResponse(out))
}

// handleRemoveNetworkCIDR shrinks a network's address space.
//
// The prefix arrives as a query parameter rather than a path segment because a
// CIDR contains a slash, and encoding one into a path segment is a decade-old
// source of proxy-specific behaviour that would surface as a 404 nobody can
// reproduce.
func (s *Server) handleRemoveNetworkCIDR(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())

	raw := r.URL.Query().Get("cidr")
	if raw == "" {
		writeErr(w, http.StatusBadRequest, "cidr query parameter is required")
		return
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "cidr is not a CIDR, e.g. \"10.42.0.0/16\"")
		return
	}

	var (
		out     *store.Network
		holders []store.AddressHolder
	)
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		net, err := s.resolveNetwork(ctx, tx, r)
		if err != nil {
			return err
		}
		// Read the blockers before attempting the removal, so the 409 can name
		// them. A bare "still in use" leaves an operator scanning a host list by
		// hand for an address inside a prefix.
		if holders, err = tx.CIDRHolders(ctx, net.ID, p.Masked()); err != nil {
			return err
		}
		out, err = tx.RemoveNetworkCIDR(ctx, net.ID, p.Masked())
		if err != nil {
			return err
		}
		e := id.Audit(store.ActionNetworkCIDRRemoved, "network", net.ID.String())
		e.Meta = []byte(fmt.Sprintf(`{"cidr":%q}`, p.Masked().String()))
		return tx.AppendAudit(ctx, e)
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrCIDRInUse):
			hosts := make([]wire.AddressHolder, 0, len(holders))
			for _, h := range holders {
				hosts = append(hosts, wire.AddressHolder{
					HostID: h.HostID.String(), Name: h.Name, Addr: h.Addr.String(),
				})
			}
			writeJSON(w, http.StatusConflict, wire.CIDRInUseError{
				Error: err.Error() + ". Removing it would not take the addresses away — " +
					"the hosts keep answering on them — it would break their NEXT renewal, " +
					"hours later, when the address no longer falls inside any prefix. " +
					"Move these hosts first",
				Hosts: hosts,
			})
		case errors.Is(err, store.ErrLastCIDR):
			writeErr(w, http.StatusConflict, err.Error()+
				"; a network with no address space can hold no host that can be issued a certificate")
		default:
			s.notFoundOr(w, err, "network prefix")
		}
		return
	}
	writeJSON(w, http.StatusOK, networkResponse(out))
}

// handleUpdateNetwork edits the display name, the per-network instance defaults,
// and which firewall the network draws from.
//
// There is no slug here, and that is the feature. The slug is a directory name
// on every managed host in the network; changing it would not rename anything,
// it would strand the old directory and make every agent create a second one
// beside it. The database refuses the change outright, so this endpoint does not
// have to be the place that remembers.
//
// FIREWALL_SOURCE IS THE ODD ONE OUT and carries two things nothing else here
// does.
//
// It needs the policy:write scope on top of the networks:write this route
// declares. A token minted to rename networks and add prefixes must not be able
// to replace the firewall on every host in one of them, and that is exactly what
// this field does. The route table cannot express a per-field scope, so the check
// is here; routes.go's knownScopes records the arrangement so it is not folklore.
//
// And it is gated behind a typed acknowledgement, in the shape ActivateCARequest
// and AddHostAddressRequest use. The blast radius is the whole network at once,
// and the failure is quiet in a way neither of those is: if the new source
// compiles to fewer rules than the old one, every host applies successfully,
// reports the new epoch, and convergence reads 100% while traffic stops. There is
// no status code that shows up anywhere for that. Making an operator say so out
// loud is the only signal available.
func (s *Server) handleUpdateNetwork(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())

	var req wire.UpdateNetworkRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Name == nil && req.ListenPort == nil && req.ConfigMode == nil && req.FirewallSource == nil {
		writeErr(w, http.StatusBadRequest,
			"no fields supplied; set name, listen_port, config_mode, or firewall_source. "+
				"The slug is immutable and cannot be edited")
		return
	}
	if req.ConfigMode != nil &&
		*req.ConfigMode != store.ConfigModeAuthoritative && *req.ConfigMode != store.ConfigModeFragment {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("config_mode must be %q or %q",
			store.ConfigModeAuthoritative, store.ConfigModeFragment))
		return
	}
	if req.ListenPort != nil && (*req.ListenPort <= 0 || *req.ListenPort > 65535) {
		writeErr(w, http.StatusBadRequest, "listen_port must be between 1 and 65535")
		return
	}
	if req.FirewallSource != nil {
		if *req.FirewallSource != store.FirewallSourceRole && *req.FirewallSource != store.FirewallSourcePolicy {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("firewall_source must be %q or %q",
				store.FirewallSourceRole, store.FirewallSourcePolicy))
			return
		}
		// The second scope. Named in the message the way the middleware names the
		// first, so the CLI's APIError.MissingScope parses it and can print the
		// `orbit token create` that would grant it.
		if !id.HasScope("policy:write") {
			writeErr(w, http.StatusForbidden,
				"changing firewall_source replaces the firewall on every host in the network; "+
					"token lacks required scope: policy:write")
			return
		}
	}

	var (
		out           *store.Network
		sourceChanged bool
		affected      int
	)
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		net, err := s.resolveNetwork(ctx, tx, r)
		if err != nil {
			return err
		}
		before := net.Name

		if req.Name != nil {
			if out, err = tx.UpdateNetworkName(ctx, net.ID, *req.Name); err != nil {
				return err
			}
		} else {
			out = net
		}
		if req.ListenPort != nil || req.ConfigMode != nil {
			if out, err = tx.UpdateNetworkInstanceDefaults(ctx, net.ID, req.ListenPort, req.ConfigMode); err != nil {
				return err
			}
		}

		if req.FirewallSource != nil && *req.FirewallSource != net.FirewallSource {
			if err := s.gateFirewallSource(ctx, tx, net, *req.FirewallSource, req, &affected); err != nil {
				return err
			}
			if out, sourceChanged, err = tx.SetFirewallSource(ctx, net.ID, *req.FirewallSource); err != nil {
				return err
			}
			// Its own audit action, not metadata on network.renamed. "When did
			// this network stop enforcing its role rules" is a WHERE clause an
			// incident review runs, and it is the entry that explains why a rule
			// still visible on a role stopped having any effect — the same
			// argument that separates ca.force_activated from ca.activated.
			e := id.Audit(store.ActionFirewallSourceChanged, "network", net.ID.String())
			meta, merr := json.Marshal(map[string]any{
				"slug":           net.Slug,
				"source_before":  net.FirewallSource,
				"source_after":   out.FirewallSource,
				"hosts_affected": affected,
				"config_epoch":   out.ConfigEpoch,
			})
			if merr != nil {
				return fmt.Errorf("encode firewall source audit metadata: %w", merr)
			}
			e.Meta = meta
			if err := tx.AppendAudit(ctx, e); err != nil {
				return err
			}
			s.log.Warn("network firewall source changed; every host re-renders its rule set",
				"network", net.Slug, "from", net.FirewallSource, "to", out.FirewallSource,
				"hosts", affected, "configEpoch", out.ConfigEpoch)
		}

		if req.Name == nil && req.ListenPort == nil && req.ConfigMode == nil {
			// Nothing here is a rename, so do not write a network.renamed entry
			// claiming one. The switch above already audited itself.
			return nil
		}
		e := id.Audit(store.ActionNetworkRenamed, "network", net.ID.String())
		e.Meta = []byte(fmt.Sprintf(`{"slug":%q,"name_before":%q,"name_after":%q}`,
			net.Slug, before, out.Name))
		return tx.AppendAudit(ctx, e)
	})
	if err != nil {
		var gate *firewallSourceGate
		if errors.As(err, &gate) {
			writeJSON(w, http.StatusConflict, gate.body)
			return
		}
		if errors.Is(err, store.ErrNoPolicy) {
			writeErr(w, http.StatusBadRequest,
				"this network has no policy document to switch to. Nebula's firewall is "+
					"default-deny, so switching now would render an empty rule set on every "+
					"host and drop all traffic. PUT a policy document first")
			return
		}
		s.notFoundOr(w, err, "network")
		return
	}

	resp := wire.NetworkUpdateResponse{
		NetworkResponse:       networkResponse(out),
		FirewallSourceChanged: sourceChanged,
	}
	if sourceChanged {
		resp.HostsAffected = affected
		resp.Detail = firewallSourceDetail(out.FirewallSource, affected, out.ConfigEpoch)
	}
	writeJSON(w, http.StatusOK, resp)
}

// firewallSourceGate is the refusal to switch a network's firewall source
// without an acknowledgement. It carries the response body so the handler does
// not rebuild it from an error string.
type firewallSourceGate struct {
	body wire.FirewallSourceChangeError
}

func (g *firewallSourceGate) Error() string { return g.body.Error }

// gateFirewallSource refuses an unacknowledged switch, and refuses a switch to
// policy mode with no document.
//
// The acknowledgement is required only when there are live hosts. A switch on a
// network nobody has enrolled into disrupts nothing, and demanding a confirmation
// there would teach operators to pass the flag reflexively — which is precisely
// what makes a confirmation on the dangerous case worthless. It also keeps the
// natural bring-up order working without ceremony: create the network, write the
// policy, switch it on, then enroll.
func (s *Server) gateFirewallSource(ctx context.Context, tx *store.Tx, net *store.Network,
	to string, req wire.UpdateNetworkRequest, affected *int) error {

	if to == store.FirewallSourcePolicy {
		// Checked here so the operator gets a sentence. The trigger added in
		// migration 0009 is what makes the invariant true for every other caller,
		// including psql — an invariant enforced in one handler is enforced in
		// whichever handler someone remembers.
		if _, err := tx.GetPolicy(ctx, net.ID); err != nil {
			return err
		}
	}

	live, err := tx.LiveHostCount(ctx, net.ID)
	if err != nil {
		return err
	}
	*affected = live
	if live == 0 || req.AcknowledgeFirewallChange {
		return nil
	}
	return &firewallSourceGate{body: wire.FirewallSourceChangeError{
		Error: "changing firewall_source replaces the firewall on every host in this network. " +
			"Resend with acknowledge_firewall_change to proceed",
		From:          net.FirewallSource,
		To:            to,
		HostsAffected: live,
		Detail:        firewallSourceGateDetail(net.FirewallSource, to, live),
	}}
}

func firewallSourceGateDetail(from, to string, hosts int) string {
	// Worst first. The rule set being REPLACED rather than merged is the part
	// operators get wrong, because every other firewall edit in this API is
	// additive within one source.
	base := fmt.Sprintf(
		"%d host(s) discard their entire current rule set and render the %s one on their next "+
			"poll. Nebula's firewall is allow-only and default-deny, so anything the new source "+
			"does not permit stops being reachable — and the hosts will apply it successfully, "+
			"report the new epoch, and read as fully converged while doing so. "+
			"Nothing about that failure is visible from the control plane. ",
		hosts, to)
	if to == store.FirewallSourcePolicy {
		return base + fmt.Sprintf(
			"Per-role rules are kept, not deleted, so switching back to %q restores them exactly. "+
				"Check the document against a specific host first: "+
				"POST /v1/networks/{ref}/policy/check?host=<name>", from)
	}
	return base + "The policy document is kept, not deleted, so switching back restores it exactly."
}

func firewallSourceDetail(source string, hosts int, epoch int64) string {
	if source == store.FirewallSourcePolicy {
		return fmt.Sprintf(
			"the policy document is now the firewall for this network; %d host(s) re-render at "+
				"config epoch %d, with no certificate reissued. Per-role rules are kept and are "+
				"no longer enforced — editing one is refused while this is set",
			hosts, epoch)
	}
	return fmt.Sprintf(
		"per-role firewall rules are in force again; %d host(s) re-render at config epoch %d. "+
			"The policy document is kept and is no longer enforced", hosts, epoch)
}

// resolveNetwork reads the {ref} path value as a uuid or a slug.
//
// Both, and nothing else. The two cannot be confused: a slug is at most 32
// characters and a uuid's canonical form is 36, so uuid.Parse either succeeds on
// something that is definitely not a slug or fails on something that might be
// one. The display name is deliberately not accepted — it is mutable, and
// resolving by a mutable string is how a rename silently retargets automation.
func (s *Server) resolveNetwork(ctx context.Context, tx *store.Tx, r *http.Request) (*store.Network, error) {
	ref := r.PathValue("ref")
	if ref == "" {
		ref = r.PathValue("id")
	}
	if ref == "" {
		return nil, fmt.Errorf("network reference: %w", store.ErrNotFound)
	}
	if id, err := uuid.Parse(ref); err == nil {
		return tx.GetNetwork(ctx, id)
	}
	return tx.GetNetworkBySlug(ctx, ref)
}

// networkPrefixes is the network response these handlers return.
//
// A local renderer rather than resources.go's networkResponse only because that
// one is in a file this change does not own; they should become one function.

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

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

// hostResponse renders a host, resolving its instance resources against the
// network.
//
// net may be nil, in which case only values set on the host itself are reported.
// Passing it is preferred: a caller asking what port a host listens on wants the
// answer, not "nothing is set here, go read the network" — the inheritance is an
// implementation detail of where the value is stored, not something every client
// should have to reimplement.
func hostResponse(h *store.Host, net *store.Network) wire.HostResponse {
	addrs := addrStrings(h.Addrs)
	out := wire.HostResponse{
		ID:                    h.ID.String(),
		Name:                  h.Name,
		NetworkID:             h.NetworkID.String(),
		OverlayAddrs:          addrs,
		State:                 h.State,
		Tags:                  h.Tags,
		IsLighthouse:          h.IsLighthouse,
		IsRelay:               h.IsRelay,
		RoleName:              h.RoleName,
		StaticAddrs:           h.StaticAddrs,
		AppliedConfigEpoch:    h.AppliedConfigEpoch,
		AppliedBlocklistEpoch: h.AppliedBlocklistEpoch,
		LastSeenAt:            h.LastSeenAt,
		NebulaVersion:         h.NebulaVersion,
		AgentVersion:          h.AgentVersion,
		CreatedAt:             h.CreatedAt,

		TunDev:               h.TunDev,
		ConfigMode:           h.ConfigMode,
		RestartRequiredEpoch: h.RestartRequiredEpoch,
	}
	if h.RoleID != nil {
		out.RoleID = h.RoleID.String()
	}
	if h.ListenPort != nil {
		out.ListenPort = *h.ListenPort
	}

	// Resolve the inheritance the same way renderFor does. Reimplementing the
	// precedence in a second place is how the API comes to report a value the
	// rendered configuration does not use, so this stays a short, obvious mirror
	// of enroll.instanceFor rather than anything cleverer.
	if net != nil {
		if out.ListenPort == 0 && net.ListenPort != nil {
			out.ListenPort = *net.ListenPort
		}
		if out.ConfigMode == "" {
			out.ConfigMode = net.ConfigMode
		}
		if out.TunDev == "" && out.ConfigMode != "" {
			out.TunDev = nebulacfg.TunDevSuggestion(net.Slug)
		}
	}
	return out
}

func certificateResponse(c store.CertificateRow) wire.CertificateResponse {
	return wire.CertificateResponse{
		ID:          c.ID.String(),
		Fingerprint: c.Fingerprint,
		State:       c.State,
		CAID:        c.CAID.String(),
		CAName:      c.CAName,
		CertVersion: int(c.CertVer),
		NotBefore:   c.NotBefore,
		NotAfter:    c.NotAfter,
		RenewAt:     c.RenewAt(),
		IssuedAt:    c.IssuedAt,
	}
}
