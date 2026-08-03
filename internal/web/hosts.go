package web

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

//------------------------------------------------------------------------------
// The host list
//------------------------------------------------------------------------------

type hostListView struct {
	Network networkView
	Hosts   []hostView
	Total   *int

	// Filter carries the current query back into the form, so a filtered listing
	// survives a refresh and can be linked to. Every filter is applied in SQL by
	// the store; none is applied here. A filter that silently did nothing would
	// show an unfiltered fleet as the answer to a narrow question, which during
	// an incident is the wrong conclusion to draw.
	Filter hostFilterView

	NextCursor string
	PrevURL    string
}

type hostFilterView struct {
	State  string
	Behind bool
	Query  string
	States []string
}

// listableHostStates mirrors internal/api's list. 'deleted' is absent because
// DeleteHost removes the row.
var listableHostStates = []string{
	store.HostCreated, store.HostEnrolled, store.HostActive, store.HostSuspended,
}

func (s *Server) handleHostList(w http.ResponseWriter, r *http.Request) error {
	networkID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	q := r.URL.Query()

	f := store.HostFilter{
		NetworkID:    networkID,
		NameContains: strings.TrimSpace(q.Get("q")),
		Behind:       q.Get("behind") == "1",
		WithCount:    true,
		Limit:        hostPageSize,
	}
	if v := q.Get("state"); v != "" && containsStr(listableHostStates, v) {
		// An unknown state is dropped rather than refused. On the JSON API that
		// would be a 400, because a script has no way to notice a silently
		// widened filter; here the rendered form shows exactly which filter is in
		// force, so the operator can see that "state: any" is what they got.
		f.State = v
	}
	if c := q.Get("cursor"); c != "" {
		cur, err := decodeHostCursor(c)
		if err == nil {
			f.After = &cur
		}
	}

	var (
		net  *store.Network
		page store.HostPage
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if net, err = tx.GetNetwork(ctx, networkID); err != nil {
			return err
		}
		page, err = tx.ListHosts(ctx, f)
		return err
	})
	if err != nil {
		return err
	}

	v := hostListView{
		Network: newNetworkView(net),
		Total:   page.Total,
		Filter: hostFilterView{
			State:  f.State,
			Behind: f.Behind,
			Query:  f.NameContains,
			States: listableHostStates,
		},
	}
	for i := range page.Hosts {
		v.Hosts = append(v.Hosts, newHostView(&page.Hosts[i], net))
	}
	if page.More && len(page.Hosts) > 0 {
		next := q
		next.Set("cursor", encodeHostCursor(&page.Hosts[len(page.Hosts)-1]))
		v.NextCursor = "?" + next.Encode()
	}
	if q.Get("cursor") != "" {
		// One link back to the start rather than a full back-stack. Keyset
		// pagination has no cheap "previous", and a wrong Previous is worse than
		// none: it silently skips rows.
		first := q
		first.Del("cursor")
		v.PrevURL = "?" + first.Encode()
	}

	p := s.newPage(r, "Hosts — "+net.Name)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.Data = v
	return s.render(w, r, "hosts.html", http.StatusOK, p)
}

const hostPageSize = 100

//------------------------------------------------------------------------------
// Host detail — the most important page in the product
//------------------------------------------------------------------------------

// It answers "why is this host not renewing" and executes "block it" without
// leaving. Everything it needs is already in the store: the host record carries
// role, static addresses, and the nebula and agent versions; the certificate
// history carries the renew-at and the issuing CA; and the network carries the
// epochs to compare against. The diagnosis is assembled in views.go so that it
// can be tested without rendering HTML.

type hostDetailView struct {
	Host     hostView
	Network  networkView
	Findings []finding

	// Certificates is the whole recent history, not just the active one.
	// "Has this host been renewing" is answered by the CADENCE — a column of
	// issue times a day apart that stops three days ago says more than any single
	// row does.
	Certificates []certView
	More         bool

	ActiveCAName string
	ActiveCAID   string
}

const hostCertHistory = 20

func (s *Server) handleHostDetail(w http.ResponseWriter, r *http.Request) error {
	hostID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}

	now := time.Now()
	var (
		host     *store.Host
		net      *store.Network
		certs    store.CertPage
		activeCA *store.CA
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if host, err = tx.GetHost(ctx, hostID); err != nil {
			return err
		}
		if net, err = tx.GetNetwork(ctx, host.NetworkID); err != nil {
			return err
		}
		if certs, err = tx.HostCertificates(ctx, hostID,
			store.CertFilter{Limit: hostCertHistory}); err != nil {
			return err
		}
		// Not an error when absent: a network with no active CA is a real state
		// the diagnosis has something to say about, and failing the page would
		// hide the one line that explains why nothing is renewing.
		if activeCA, err = tx.GetActiveCA(ctx, host.NetworkID); errors.Is(err, store.ErrNoActived) {
			activeCA = nil
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}

	v := hostDetailView{
		Host:    newHostView(host, net),
		Network: newNetworkView(net),
		More:    certs.More,
	}
	for _, c := range certs.Certificates {
		v.Certificates = append(v.Certificates, newCertView(c, now))
	}
	if activeCA != nil {
		v.ActiveCAID = activeCA.ID.String()
		v.ActiveCAName = activeCA.Name
	}
	v.Findings = diagnose(v.Host, v.Certificates, now, v.ActiveCAID, activeCA != nil)

	p := s.newPage(r, host.Name)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.LiveNetwork = net.ID.String()
	p.Data = v
	return s.render(w, r, "host.html", http.StatusOK, p)
}

//------------------------------------------------------------------------------
// Block, with a confirmation that is a page rather than a dialog
//------------------------------------------------------------------------------

// The confirmation is a GET that renders a page, and the action is a POST from
// that page. Not a JavaScript confirm() with the POST behind it, for two
// reasons that both matter here.
//
// It works with JavaScript disabled, which is the rule for every screen. And a
// dialog can only ask "are you sure"; a page can say what blocking this
// PARTICULAR host costs — that it is the only lighthouse, that it relays for
// other machines, that it is a control plane replica — which is the information
// that actually changes a decision. app.js adds a confirm() on top of the final
// button as a guard against a misclick, and if it never loads the page is
// unchanged.

type blockConfirmView struct {
	Host    hostView
	Network networkView
	// Consequences are the role-specific costs, worst first.
	Consequences []string
}

func (s *Server) handleBlockConfirm(w http.ResponseWriter, r *http.Request) error {
	hostID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}

	var (
		host *store.Host
		net  *store.Network
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if host, err = tx.GetHost(ctx, hostID); err != nil {
			return err
		}
		net, err = tx.GetNetwork(ctx, host.NetworkID)
		return err
	})
	if err != nil {
		return err
	}

	p := s.newPage(r, "Block "+host.Name)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.Data = blockConfirmView{
		Host:         newHostView(host, net),
		Network:      newNetworkView(net),
		Consequences: blockConsequences(host),
	}
	return s.render(w, r, "block.html", http.StatusOK, p)
}

// blockConsequences names what blocking THIS host costs.
//
// Worst first, and the relay line leads for the reason the address-change gate
// puts it first: it is the only consequence whose damage lands on machines that
// have nothing to do with the decision being made.
func blockConsequences(h *store.Host) []string {
	var out []string
	if h.IsRelay {
		out = append(out, h.Name+" RELAYS FOR OTHER HOSTS. Blocking it drops the traffic "+
			"it is forwarding on their behalf, not just its own — pairs that cannot reach "+
			"each other directly lose their path.")
	}
	if h.IsLighthouse {
		out = append(out, h.Name+" is a lighthouse. Discovery through it stops: hosts that "+
			"already hold a tunnel keep it, hosts still looking for a peer do not find one.")
	}
	out = append(out,
		"Its certificates are revoked and its fingerprints are distributed to every "+
			"other host in the network. It loses the overlay within one blocklist "+
			"convergence, and it cannot renew or re-enroll while blocked.",
		"This is reversible: unblocking restores it, and it keeps its name and its "+
			"overlay address throughout. Deletion is the irreversible one, and this UI "+
			"does not do it.")
	return out
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) error {
	hostID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	id := identityFrom(r.Context())

	var (
		epoch int64
		name  string
	)
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		name = host.Name

		if epoch, err = tx.BlockHost(ctx, hostID, "blocked from the operator UI"); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, s.audit(r, *id, store.ActionHostBlocked, "host", hostID.String()))
	})
	if err != nil {
		return err
	}

	// Loud in the log as well as in the audit trail. Blocking is the one action
	// in this UI that takes a machine off the mesh, and the log is where someone
	// correlating an outage with a change will look first.
	s.log.Warn("host blocked from the operator UI",
		"host", hostID, "name", name, "actor", id.Display, "blocklistEpoch", epoch)

	return s.redirectWithNotice(w, r, "/ui/hosts/"+hostID.String(),
		fmt.Sprintf("%s is blocked. Blocklist epoch %d — watch convergence to see it reach the fleet.",
			name, epoch))
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) error {
	hostID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	id := identityFrom(r.Context())

	var epoch int64
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if epoch, err = tx.UnblockHost(ctx, hostID); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, s.audit(r, *id, store.ActionHostUnblocked, "host", hostID.String()))
	})
	if err != nil {
		return err
	}
	s.log.Info("host unblocked from the operator UI", "host", hostID, "actor", id.Display)

	return s.redirectWithNotice(w, r, "/ui/hosts/"+hostID.String(),
		fmt.Sprintf("Unblocked. Blocklist epoch %d. The host must still re-enroll or "+
			"recover before it holds a valid certificate again.", epoch))
}

//------------------------------------------------------------------------------
// Add a host, and hand out its enrollment code
//------------------------------------------------------------------------------

type hostNewView struct {
	Network networkView
	Roles   []roleOption
	// Form carries a rejected submission back rather than discarding it.
	Form    newHostForm
	Problem string
}

type roleOption struct {
	ID   string
	Name string
}

type newHostForm struct {
	Name         string
	RoleID       string
	Tags         string
	IsLighthouse bool
	IsRelay      bool
	StaticAddrs  string
}

func (s *Server) handleNewHostForm(w http.ResponseWriter, r *http.Request) error {
	return s.renderNewHost(w, r, newHostForm{}, "", http.StatusOK)
}

func (s *Server) renderNewHost(w http.ResponseWriter, r *http.Request, form newHostForm, problem string, status int) error {
	networkID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}

	var (
		net   *store.Network
		roles []store.Role
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if net, err = tx.GetNetwork(ctx, networkID); err != nil {
			return err
		}
		roles, err = tx.ListRoles(ctx, networkID)
		return err
	})
	if err != nil {
		return err
	}

	v := hostNewView{Network: newNetworkView(net), Form: form, Problem: problem}
	for _, role := range roles {
		v.Roles = append(v.Roles, roleOption{ID: role.ID.String(), Name: role.Name})
	}

	p := s.newPage(r, "Add a host — "+net.Name)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.Data = v
	// The caller's status, not a blanket 200. A refused submission that answers
	// 200 is one no monitoring system and no scripted check can tell from a
	// success.
	return s.render(w, r, "host_new.html", status, p)
}

// handleCreateHost creates a host with an ALLOCATED overlay address.
//
// The form does not offer an address field. The control plane holds the only
// authoritative answer to what is free, and asking a person to remember instead
// is how two hosts end up claiming one address — the case store.CreateHostAllocating
// exists to make impossible.
func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) error {
	networkID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	id := identityFrom(r.Context())

	form := newHostForm{
		Name:         strings.TrimSpace(r.PostFormValue("name")),
		RoleID:       r.PostFormValue("role_id"),
		Tags:         strings.TrimSpace(r.PostFormValue("tags")),
		IsLighthouse: r.PostFormValue("is_lighthouse") != "",
		IsRelay:      r.PostFormValue("is_relay") != "",
		StaticAddrs:  strings.TrimSpace(r.PostFormValue("static_addrs")),
	}
	if form.Name == "" {
		return s.renderNewHost(w, r, form, "A name is required.", http.StatusBadRequest)
	}
	static := splitCSV(form.StaticAddrs)
	if form.IsLighthouse && len(static) == 0 {
		// The same refusal PATCH /v1/hosts/{id} makes, and for the same reason:
		// a lighthouse nobody can reach is worse than no lighthouse, because
		// every host keeps dialling it.
		return s.renderNewHost(w, r, form,
			"A lighthouse needs at least one public address. Without one, every host "+
				"in the network keeps trying to reach it and never can.", http.StatusBadRequest)
	}

	var roleID *uuid.UUID
	if form.RoleID != "" {
		rid, err := uuid.Parse(form.RoleID)
		if err != nil {
			return s.renderNewHost(w, r, form, "That role is not valid.", http.StatusBadRequest)
		}
		roleID = &rid
	}

	host := store.Host{
		NetworkID:    networkID,
		Name:         form.Name,
		RoleID:       roleID,
		Tags:         splitCSV(form.Tags),
		IsLighthouse: form.IsLighthouse,
		IsRelay:      form.IsRelay,
		StaticAddrs:  static,
	}

	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		net, err := tx.GetNetwork(ctx, networkID)
		if err != nil {
			return err
		}
		if err := tx.CreateHostAllocating(ctx, net, &host, netip.Prefix{}); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, s.audit(r, *id, store.ActionHostCreated, "host", host.ID.String()))
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			return s.renderNewHost(w, r, form,
				"A host with that name already exists in this network.", http.StatusConflict)
		case errors.Is(err, store.ErrAddressExhausted):
			return s.renderNewHost(w, r, form,
				err.Error()+". Add another prefix to the network, or release an address.",
				http.StatusConflict)
		}
		return err
	}

	// Straight to the code handout when the caller may mint one: creating a host
	// and then hunting for the button that makes it usable is two steps where the
	// operator only ever wanted one.
	if id.HasScope("hosts:enroll") {
		return s.issueEnrollmentCode(w, r, host.ID, *id)
	}
	return s.redirectWithNotice(w, r, "/ui/hosts/"+host.ID.String(),
		"Host created. It needs an enrollment code before it can join, and this "+
			"credential does not carry the hosts:enroll scope.")
}

//------------------------------------------------------------------------------
// The enrollment code, shown once
//------------------------------------------------------------------------------

type enrollCodeView struct {
	Host      hostView
	Network   networkView
	Code      string
	ExpiresAt time.Time
	EnrollURL string
	// Command is the exact line to run on the new machine. It is the whole
	// deliverable of this page: a code with no context is a string somebody has
	// to look up how to use.
	Command string
}

func (s *Server) handleEnrollmentCode(w http.ResponseWriter, r *http.Request) error {
	hostID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	return s.issueEnrollmentCode(w, r, hostID, *identityFrom(r.Context()))
}

// issueEnrollmentCode mints a code and renders it exactly once.
//
// Rendered directly from the POST rather than redirected to a page that would
// re-read it, because there is nothing to re-read: the code is stored as a
// peppered hash and this response is the only place the plaintext will ever
// exist. That is also why the whole surface sets Cache-Control: no-store — a
// back button that re-rendered this page from cache would be a second copy of a
// credential that is supposed to have exactly one.
func (s *Server) issueEnrollmentCode(w http.ResponseWriter, r *http.Request, hostID uuid.UUID, id store.Identity) error {
	resp, err := s.enroll.CreateCode(r.Context(), hostID, 0, id)
	if err != nil {
		return err
	}

	var (
		host *store.Host
		net  *store.Network
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if host, err = tx.GetHost(ctx, hostID); err != nil {
			return err
		}
		net, err = tx.GetNetwork(ctx, host.NetworkID)
		return err
	})
	if err != nil {
		return err
	}

	s.log.Info("enrollment code issued from the operator UI",
		"host", hostID, "name", host.Name, "actor", id.Display, "expires", resp.ExpiresAt)

	p := s.newPage(r, "Enrollment code — "+host.Name)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.Data = enrollCodeView{
		Host:      newHostView(host, net),
		Network:   newNetworkView(net),
		Code:      resp.Code,
		ExpiresAt: resp.ExpiresAt,
		EnrollURL: resp.EnrollURL,
		Command:   enrollCommand(net.Slug, resp),
	}
	return s.render(w, r, "enroll_code.html", http.StatusOK, p)
}

func enrollCommand(slug string, resp *wire.EnrollmentCodeResponse) string {
	url := resp.EnrollURL
	if url == "" {
		url = "https://<control-plane>/enroll/v1/enroll"
	}
	return fmt.Sprintf("orbit-agent enroll -url %s -code %s -network %s", url, resp.Code, slug)
}

//------------------------------------------------------------------------------
// Shared helpers
//------------------------------------------------------------------------------

// audit builds an audit entry for a UI action, with the operator's address.
//
// SourceIP is filled in here where internal/api leaves it empty, because the two
// surfaces have different callers: an API request comes from automation whose
// address is a load balancer, and a UI request comes from a person at a browser
// whose address is the one an incident review actually wants.
func (s *Server) audit(r *http.Request, id store.Identity, action, targetType, targetID string) store.AuditEntry {
	e := id.Audit(action, targetType, targetID)
	e.SourceIP = clientAddr(r)
	// Marked as having come from the UI. "Was this done by a person or by a
	// script" is the first question asked of a surprising change, and without
	// this the two are indistinguishable — both are actor_type 'token' under the
	// same token name.
	e.Meta = []byte(`{"via":"ui"}`)
	return e
}

// redirectWithNotice completes a POST with a 303 and a message.
//
// Post/Redirect/Get, so that a refresh after blocking a host does not block it
// again. The message rides in the query string, which is safe because it is
// server-authored text rendered through html/template — never anything the
// caller supplied.
func (s *Server) redirectWithNotice(w http.ResponseWriter, r *http.Request, path, notice string) error {
	q := url.Values{"notice": {notice}}
	http.Redirect(w, r, path+"?"+q.Encode(), http.StatusSeeOther)
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// The cursor encoding is the same one internal/api uses, so a cursor is the same
// opaque string on both surfaces. Duplicated rather than exported from there
// because it is four lines and because exporting it would make an internal
// pagination detail part of that package's API.

func encodeHostCursor(h *store.Host) string {
	return base64RawURL(h.Name + "\x00" + h.ID.String())
}

func decodeHostCursor(s string) (store.HostCursor, error) {
	raw, err := base64RawURLDecode(s)
	if err != nil {
		return store.HostCursor{}, err
	}
	name, rest, found := strings.Cut(raw, "\x00")
	if !found {
		return store.HostCursor{}, errors.New("malformed cursor")
	}
	id, err := uuid.Parse(rest)
	if err != nil {
		return store.HostCursor{}, err
	}
	return store.HostCursor{Name: name, ID: id}, nil
}

func base64RawURL(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func base64RawURLDecode(s string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return string(raw), err
}
