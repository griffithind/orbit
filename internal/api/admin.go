package api

import (
	"context"
	"encoding/base64"
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

		// An empty scope means authentication only. Used by /v1/whoami, which
		// must answer for any valid credential — including one whose scopes the
		// caller is trying to discover.
		if scope != "" && !id.HasScope(scope) {
			writeErr(w, http.StatusForbidden, "token lacks required scope: "+scope)
			return
		}

		s.store.TouchToken(r.Context(), id.TokenID)
		h(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	})
}

// checkHint turns a CHECK-constraint refusal into something an operator can act
// on.
//
// The constraint name alone is accurate and nearly useless — "violates
// network_name_is_not_a_uuid" states the rule without the reason, and the
// reason is the part that stops someone retrying the same request. Constraints
// whose intent is self-evident from their name are left to speak for
// themselves.
func checkHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "network_name_is_not_a_uuid"):
		return "a network name may not look like a uuid: names and ids share " +
			"the /v1/networks/{ref} route, so one that could be either is refused"
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

	var page store.HostPage
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		page, err = tx.ListHosts(ctx, f)
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
		resp.Hosts = append(resp.Hosts, hostResponse(&page.Hosts[i]))
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
	var (
		host  *store.Host
		certs store.CertPage
	)
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		host, err = tx.GetHost(ctx, hostID)
		if err != nil {
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

	resp := hostResponse(host)
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
	}
	if h.RoleID != nil {
		out.RoleID = h.RoleID.String()
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
