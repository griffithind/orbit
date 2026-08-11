package web

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

//------------------------------------------------------------------------------
// The host list
//------------------------------------------------------------------------------

type membershipListView struct {
	Network     networkView
	Memberships []membershipView
	Total       *int

	// Filter carries the current query back into the form, so a filtered listing
	// survives a refresh and can be linked to. Every filter is applied in SQL by
	// the store; none is applied here. A filter that silently did nothing would
	// show an unfiltered fleet as the answer to a narrow question, which during
	// an incident is the wrong conclusion to draw.
	Filter membershipFilterView

	NextCursor string
	PrevURL    string
}

type membershipFilterView struct {
	State  string
	Behind bool
	Query  string
	States []string
}

// listableHostStates mirrors internal/api's list. 'deleted' is absent because
// DeleteHost removes the row.
var listableHostStates = []string{
	store.MembershipCreated, store.MembershipEnrolled, store.MembershipActive, store.MembershipSuspended,
}

func (s *Server) handleHostList(w http.ResponseWriter, r *http.Request) error {
	networkID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	q := r.URL.Query()

	f := store.MembershipFilter{
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
		page store.MembershipPage
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

	v := membershipListView{
		Network: newNetworkView(net),
		Total:   page.Total,
		Filter: membershipFilterView{
			State:  f.State,
			Behind: f.Behind,
			Query:  f.NameContains,
			States: listableHostStates,
		},
	}
	for i := range page.Memberships {
		v.Memberships = append(v.Memberships, newMembershipView(&page.Memberships[i], net))
	}
	if page.More && len(page.Memberships) > 0 {
		next := q
		next.Set("cursor", encodeHostCursor(&page.Memberships[len(page.Memberships)-1]))
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

	p := s.newPage(r, "Memberships — "+net.Name)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.Data = v
	return s.render(w, r, "memberships.html", http.StatusOK, p)
}

const hostPageSize = 100

//------------------------------------------------------------------------------
// Membership detail — the most important page in the product
//------------------------------------------------------------------------------

// It answers "why is this host not renewing" and executes "block it" without
// leaving. Everything it needs is already in the store: the host record carries
// role, static addresses, and the nebula and agent versions; the certificate
// history carries the renew-at and the issuing CA; and the network carries the
// epochs to compare against. The diagnosis is assembled in views.go so that it
// can be tested without rendering HTML.

type membershipDetailView struct {
	Membership membershipView
	Network    networkView
	Findings   []finding

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
	membershipID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}

	now := time.Now()
	var (
		host     *store.Membership
		net      *store.Network
		certs    store.CertPage
		activeCA *store.CA
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if host, err = tx.GetHost(ctx, membershipID); err != nil {
			return err
		}
		if net, err = tx.GetNetwork(ctx, host.NetworkID); err != nil {
			return err
		}
		if certs, err = tx.MembershipCertificates(ctx, membershipID,
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

	v := membershipDetailView{
		Membership: newMembershipView(host, net),
		Network:    newNetworkView(net),
		More:       certs.More,
	}
	for _, c := range certs.Certificates {
		v.Certificates = append(v.Certificates, newCertView(c, now))
	}
	if activeCA != nil {
		v.ActiveCAID = activeCA.ID.String()
		v.ActiveCAName = activeCA.Name
	}
	v.Findings = diagnose(v.Membership, v.Certificates, now, v.ActiveCAID, activeCA != nil)

	p := s.newPage(r, host.Name)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.LiveNetwork = net.ID.String()
	p.Data = v
	return s.render(w, r, "membership.html", http.StatusOK, p)
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
	Membership membershipView
	Network    networkView
	// Consequences are the role-specific costs, worst first.
	Consequences []string
}

func (s *Server) handleBlockConfirm(w http.ResponseWriter, r *http.Request) error {
	membershipID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}

	var (
		host *store.Membership
		net  *store.Network
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if host, err = tx.GetHost(ctx, membershipID); err != nil {
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
		Membership:   newMembershipView(host, net),
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
func blockConsequences(h *store.Membership) []string {
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
	membershipID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	id := identityFrom(r.Context())

	var (
		epoch int64
		name  string
	)
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, membershipID)
		if err != nil {
			return err
		}
		name = host.Name

		if epoch, err = tx.BlockHost(ctx, membershipID, "blocked from the operator UI"); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, s.audit(r, *id, store.ActionMembershipBlocked, "host", membershipID.String()))
	})
	if err != nil {
		return err
	}

	// Loud in the log as well as in the audit trail. Blocking is the one action
	// in this UI that takes a machine off the mesh, and the log is where someone
	// correlating an outage with a change will look first.
	s.log.Warn("host blocked from the operator UI",
		"host", membershipID, "name", name, "actor", id.Display, "blocklistEpoch", epoch)

	return s.redirectWithNotice(w, r, "/ui/memberships/"+membershipID.String(),
		fmt.Sprintf("%s is blocked. Blocklist epoch %d — watch convergence to see it reach the fleet.",
			name, epoch))
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) error {
	membershipID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	id := identityFrom(r.Context())

	var epoch int64
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if epoch, err = tx.UnblockHost(ctx, membershipID); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, s.audit(r, *id, store.ActionMembershipUnblocked, "host", membershipID.String()))
	})
	if err != nil {
		return err
	}
	s.log.Info("host unblocked from the operator UI", "host", membershipID, "actor", id.Display)

	return s.redirectWithNotice(w, r, "/ui/memberships/"+membershipID.String(),
		fmt.Sprintf("Unblocked. Blocklist epoch %d. The machine must still re-enroll, or "+
			"re-run `orbit join`, before it holds a valid certificate again.", epoch))
}

//------------------------------------------------------------------------------
// Reserve a place, and hand out its code
//------------------------------------------------------------------------------

type membershipNewView struct {
	Network networkView
	Roles   []roleOption
	// Form carries a rejected submission back rather than discarding it.
	Form    newMembershipForm
	Problem string
}

type roleOption struct {
	ID   string
	Name string
}

type newMembershipForm struct {
	Name         string
	RoleID       string
	Tags         string
	IsLighthouse bool
	IsRelay      bool
	StaticAddrs  string
}

func (s *Server) handleNewHostForm(w http.ResponseWriter, r *http.Request) error {
	return s.renderNewHost(w, r, newMembershipForm{}, "", http.StatusOK)
}

func (s *Server) renderNewHost(w http.ResponseWriter, r *http.Request, form newMembershipForm, problem string, status int) error {
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

	v := membershipNewView{Network: newNetworkView(net), Form: form, Problem: problem}
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
	return s.render(w, r, "membership_new.html", status, p)
}

// handleReserveHost holds a place for a machine that has not arrived.
//
// This was handleCreateHost, and the change is not cosmetic. Creating a host
// made a row that named no machine; a reservation records the operator's intent
// on a credential, and the membership is created — already naming its device —
// when a machine redeems it. See docs/model.md §4.
//
// The form no longer offers lighthouse, relay, static addresses or tags. A
// reservation carries what an UNATTENDED machine must have decided for it —
// name, address, role — and the rest is set from the host page once the machine
// is there. Carrying them here would mean four more columns on the credential to
// serve a case (setting up a lighthouse) where an operator is present anyway.
//
// There is still no address field, for the reason there never was: the control
// plane holds the only authoritative answer to what is free, and asking a person
// to remember instead is how two hosts end up claiming one address.
func (s *Server) handleReserveHost(w http.ResponseWriter, r *http.Request) error {
	networkID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	id := identityFrom(r.Context())

	form := newMembershipForm{
		Name:   strings.TrimSpace(r.PostFormValue("name")),
		RoleID: r.PostFormValue("role_id"),
	}
	if form.Name == "" {
		return s.renderNewHost(w, r, form, "A name is required.", http.StatusBadRequest)
	}

	res := store.Reservation{Name: form.Name}
	if form.RoleID != "" {
		rid, err := uuid.Parse(form.RoleID)
		if err != nil {
			return s.renderNewHost(w, r, form, "That role is not valid.", http.StatusBadRequest)
		}
		res.RoleID = &rid
	}

	resp, err := s.enroll.Reserve(r.Context(), networkID.String(), res, 0, *id)
	if err != nil {
		switch {
		case errors.Is(err, enroll.ErrReservedNameTaken), errors.Is(err, store.ErrConflict):
			return s.renderNewHost(w, r, form,
				"That name is already taken in this network, either by a host or by "+
					"an unspent reservation.", http.StatusConflict)
		case errors.Is(err, enroll.ErrJoinName):
			return s.renderNewHost(w, r, form, err.Error(), http.StatusBadRequest)
		}
		return err
	}

	var net *store.Network
	if err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		net, err = tx.GetNetwork(ctx, networkID)
		return err
	}); err != nil {
		return err
	}

	s.log.Info("reservation issued from the operator UI",
		"network", net.Slug, "name", form.Name, "actor", id.Display, "expires", resp.ExpiresAt)

	return s.renderCode(w, r, net, nil, form.Name, resp)
}

//------------------------------------------------------------------------------
// The enrollment code, shown once
//------------------------------------------------------------------------------

type enrollCodeView struct {
	// Membership is nil for a reservation: the membership does not exist yet, which
	// is the whole point of a reservation. The template branches on it rather
	// than rendering a placeholder, because a page showing an address and a
	// state for a machine that has not arrived would be inventing both.
	Membership *membershipView

	// Name is what the machine will be called, whether or not it exists yet.
	Name      string
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
	membershipID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	return s.issueEnrollmentCode(w, r, membershipID, *identityFrom(r.Context()))
}

// issueEnrollmentCode mints a code and renders it exactly once.
//
// Rendered directly from the POST rather than redirected to a page that would
// re-read it, because there is nothing to re-read: the code is stored as a
// peppered hash and this response is the only place the plaintext will ever
// exist. That is also why the whole surface sets Cache-Control: no-store — a
// back button that re-rendered this page from cache would be a second copy of a
// credential that is supposed to have exactly one.
func (s *Server) issueEnrollmentCode(w http.ResponseWriter, r *http.Request, membershipID uuid.UUID, id store.Identity) error {
	resp, err := s.enroll.CreateCode(r.Context(), membershipID, 0, id)
	if err != nil {
		return err
	}

	var (
		host *store.Membership
		net  *store.Network
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if host, err = tx.GetHost(ctx, membershipID); err != nil {
			return err
		}
		net, err = tx.GetNetwork(ctx, host.NetworkID)
		return err
	})
	if err != nil {
		return err
	}

	s.log.Info("enrollment code issued from the operator UI",
		"host", membershipID, "name", host.Name, "actor", id.Display, "expires", resp.ExpiresAt)

	hv := newMembershipView(host, net)
	return s.renderCode(w, r, net, &hv, host.Name, resp)
}

// renderCode shows a credential exactly once.
//
// Shared by the two things that mint one — a code for an existing host, and a
// reservation for a machine that has not arrived — because the page's whole job
// is the same in both cases: display a plaintext that exists nowhere else, and
// the exact command that consumes it.
//
// Rendered directly from the POST rather than redirected to a page that would
// re-read it, because there is nothing to re-read.
func (s *Server) renderCode(w http.ResponseWriter, r *http.Request, net *store.Network,
	host *membershipView, name string, resp *wire.EnrollmentCodeResponse) error {

	title := "Enrollment code — " + name
	if host == nil {
		title = "Reservation — " + name
	}
	p := s.newPage(r, title)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.Data = enrollCodeView{
		Membership: host,
		Name:       name,
		Network:    newNetworkView(net),
		Code:       resp.Code,
		ExpiresAt:  resp.ExpiresAt,
		EnrollURL:  resp.EnrollURL,
		Command:    joinCommand(net.Slug, host != nil, resp),
	}
	return s.render(w, r, "enroll_code.html", http.StatusOK, p)
}

// joinCommand is the exact line to run on the new machine.
//
// Two commands, because the two credentials mean different things. A
// reservation is redeemed by `join`: the machine generates its device identity,
// presents the code, and the membership comes into existence naming it. A code
// for an EXISTING host is redeemed by `enroll`, which is re-issuing a
// certificate to a membership that is already there.
//
// Printing the wrong one would fail in a way that is hard to read — join would
// refuse a code bound to a host, saying it belongs to an existing host and not
// a reservation.
func joinCommand(slug string, hostExists bool, resp *wire.EnrollmentCodeResponse) string {
	url := resp.EnrollURL
	if url == "" {
		url = "https://<control-plane>"
	}
	if hostExists {
		return fmt.Sprintf("orbit agent enroll -url %s -code %s -network %s", url, resp.Code, slug)
	}
	return fmt.Sprintf("orbit join -url %s -network %s -code %s", url, slug, resp.Code)
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
// again.
//
// The message is SIGNED, not merely server-authored. This comment used to say
// the query string was safe because the text always came from here — true of
// this function and not enforced anywhere, so newPage rendered whatever arrived.
// See signNotice.
func (s *Server) redirectWithNotice(w http.ResponseWriter, r *http.Request, path, notice string) error {
	http.Redirect(w, r, path+"?"+s.signNotice(notice).Encode(), http.StatusSeeOther)
	return nil
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

func encodeHostCursor(h *store.Membership) string {
	return base64RawURL(h.Name + "\x00" + h.ID.String())
}

func decodeHostCursor(s string) (store.MembershipCursor, error) {
	raw, err := base64RawURLDecode(s)
	if err != nil {
		return store.MembershipCursor{}, err
	}
	name, rest, found := strings.Cut(raw, "\x00")
	if !found {
		return store.MembershipCursor{}, errors.New("malformed cursor")
	}
	id, err := uuid.Parse(rest)
	if err != nil {
		return store.MembershipCursor{}, err
	}
	return store.MembershipCursor{Name: name, ID: id}, nil
}

func base64RawURL(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func base64RawURLDecode(s string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return string(raw), err
}
