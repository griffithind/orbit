package web

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/version"
)

// html/template, never text/template.
//
// The difference is not "one escapes and one does not" — it is that html/template
// escapes according to WHERE in the document a value lands, so the same string is
// treated differently inside an attribute, inside a URL, and inside a <script>.
// Nothing in this package produces a template.HTML value from stored data, and
// nothing should: the two blobs that look like they want raw rendering, firewall
// rule JSON and certificate PEM, are exactly the two an attacker would aim at,
// and both go through <pre>{{ . }}</pre> where the escaping is doing real work.

// templates holds one parsed set per page.
//
// One set per page rather than a single set with every file in it, because each
// page defines a block named "content" and a shared set can only hold one
// definition of a name. The alternative — a unique block name per page — moves
// the coupling into strings, where a typo renders an empty page instead of
// failing.
type templates struct {
	pages map[string]*template.Template
	// names is the sorted page list, so the test that executes every template
	// enumerates them from here rather than from a hand-maintained list that
	// would drift the moment someone adds a screen.
	names []string
}

func parseTemplates() (*templates, error) {
	entries, err := fs.ReadDir(assetFS, "templates/pages")
	if err != nil {
		return nil, fmt.Errorf("read page templates: %w", err)
	}

	t := &templates{pages: map[string]*template.Template{}}
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".html" {
			continue
		}
		set, err := template.New("layout.html").Funcs(funcMap).ParseFS(assetFS,
			"templates/layout.html",
			"templates/partials/*.html",
			"templates/pages/"+e.Name(),
		)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		t.pages[e.Name()] = set
		t.names = append(t.names, e.Name())
	}
	if len(t.pages) == 0 {
		return nil, errors.New("no page templates found")
	}
	return t, nil
}

//------------------------------------------------------------------------------
// Page data
//------------------------------------------------------------------------------

// pageData is what every template receives.
//
// The page-specific payload hangs off Data rather than the template receiving a
// per-page struct directly, so the layout can rely on Actor, CSRF, and Assets
// being present on every single render — including on the error pages, which are
// the ones a hand-rolled path would forget.
type pageData struct {
	Title  string
	Assets *assets
	CSRF   string

	// Actor is the signed-in identity's display name, empty when signed out.
	Actor  string
	Scopes []string

	// ReadOnly says this session carries no scope that can change anything.
	//
	// Shown in the header, because the alternative is an operator hunting for a
	// Block button that is not there. Derived from the scopes the session
	// actually resolved with rather than from a flag: store.ResolveSession
	// narrows a read-only session's scopes on every request, so the absence of
	// write scopes IS the read-only state, and a second copy of that fact could
	// only ever disagree with it.
	ReadOnly bool

	// Networks feeds the network picker in the header. Capped at
	// navNetworkLimit; past that it holds only the current one and the header
	// links to the full list instead.
	Networks []networkLink
	// NetworkCount is how many exist, which is what the header shows when there
	// are too many to list.
	NetworkCount int
	// CurrentNetwork is the id of the network being looked at, for highlighting
	// and for the "hosts" and "audit" links in the nav.
	CurrentNetwork string

	// LiveNetwork, when set, marks this page as one that updates by itself:
	// app.js opens an event stream for this network, and the <noscript> meta
	// refresh covers the case where app.js never loaded.
	LiveNetwork string

	// Notice and Problem are the two banners. Separate fields rather than one
	// with a level, because a template that has to branch on a level is a
	// template that renders a failure in the success colour when someone passes
	// the wrong constant.
	Notice  string
	Problem string

	Version string
	Data    any
}

type networkLink struct {
	ID   string
	Slug string
	Name string
}

// newPage builds the common half of a render.
func (s *Server) newPage(r *http.Request, title string) *pageData {
	p := &pageData{
		Title:   title,
		Assets:  s.assets,
		Version: version.Version,
	}
	if id := identityFrom(r.Context()); id != nil {
		p.Actor = id.Display
		p.Scopes = id.Scopes
		p.ReadOnly = readOnlyScopes(id.Scopes)
	}
	if cookie := cookieFrom(r.Context()); cookie != "" {
		p.CSRF = s.csrfToken(cookie)
	}
	if n := r.URL.Query().Get("notice"); n != "" {
		p.Notice = n
	}
	return p
}

// render executes a page into a buffer and then writes it.
//
// The buffer is the point. A template that fails halfway through — a nil deref
// in a field access, a range over something that is not a slice — has already
// written a 200 and half a document by the time it errors, and the operator sees
// a truncated page with no indication that anything went wrong. Buffering means
// a broken template produces a proper error page, and a proper log line, at 3am.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, status int, data *pageData) error {
	set, ok := s.tpl.pages[page]
	if !ok {
		return fmt.Errorf("no such page template: %s", page)
	}

	var buf bytes.Buffer
	if err := set.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		return fmt.Errorf("render %s: %w", page, err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
	return nil
}

//------------------------------------------------------------------------------
// Errors
//------------------------------------------------------------------------------

// errorPage turns a handler's returned error into a rendered page.
//
// Handlers return errors rather than writing them, so that the mapping from a
// store error to a status happens in one place. The alternative — every handler
// calling a helper — is the arrangement where one handler eventually forgets and
// answers a missing host with a 500.
func (s *Server) errorPage(h handlerFunc) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		err := h(w, r)
		if err == nil {
			return nil
		}

		switch {
		case errors.Is(err, store.ErrNotFound):
			s.writeStatus(w, r, http.StatusNotFound, "not found",
				"That host, network, or certificate authority does not exist. "+
					"It may have been deleted, or the link may be from a different deployment.")
		case errors.Is(err, store.ErrNoActived):
			s.writeStatus(w, r, http.StatusServiceUnavailable,
				"this network has no active certificate authority",
				"Nothing can be issued a certificate until one is promoted. "+
					"See the rotation page.")
		default:
			// The cause goes to the log, not to the page. This surface is
			// authenticated, but an error string here can carry a table name, a
			// constraint, or a fragment of a query, and a screenshot of an
			// incident page ends up in a ticket.
			s.log.Error("ui request failed",
				"method", r.Method, "path", r.URL.Path, "error", err)
			s.writeStatus(w, r, http.StatusInternalServerError, "something went wrong",
				"The control plane could not answer that. The details are in its log, "+
					"under the timestamp on this page.")
		}
		return nil
	}
}

// writeStatus renders a full page for a status.
//
// A rendered page rather than http.Error, because half the value of this UI is
// that the failures explain themselves — and because http.Error writes
// text/plain, which the CSP and the nosniff header would then be decorating a
// page that is not a page.
func (s *Server) writeStatus(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	p := s.newPage(r, title)
	p.Data = statusView{
		Status: status,
		Title:  title,
		Detail: detail,
		At:     time.Now(),
	}
	if err := s.render(w, r, "status.html", status, p); err != nil {
		// The error page itself is broken. Fall back to something that cannot
		// be: this is the one place in the package that writes a bare response.
		s.log.Error("ui could not render its own error page", "error", err)
		http.Error(w, title, status)
	}
}

type statusView struct {
	Status int
	Title  string
	Detail string
	At     time.Time
}

//------------------------------------------------------------------------------
// Template functions
//------------------------------------------------------------------------------

// funcMap is deliberately small. Anything that needs a decision belongs in Go,
// where it can be tested; a template function that computes a status is a
// status nobody can write a test for without rendering HTML.
var funcMap = template.FuncMap{
	"ago":      ago,
	"agoPtr":   agoPtr,
	"stamp":    stamp,
	"stampPtr": stampPtr,
	"pct":      pct,
	"hasScope": hasScope,
	"join":     strings.Join,
}

// ago renders a duration the way an operator reads one: coarse, and never more
// precise than the thing it measures.
func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	if d < 0 {
		return "in " + humanDuration(-d)
	}
	return humanDuration(d) + " ago"
}

// agoPtr is ago for the many nullable timestamps in the store.
//
// "never" rather than a zero timestamp, for the reason api/convergence.go gives:
// a host that has never reported has a different problem from one that reported
// an hour ago, and 0001-01-01 makes them look the same.
func agoPtr(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return ago(*t)
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// stamp is the absolute time, always alongside a relative one.
//
// Both, never one: the relative time is what someone reads at a glance, and the
// absolute one is what they paste into a message to a colleague in another
// timezone. UTC because that is what the logs are in.
func stamp(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

func stampPtr(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return stamp(*t)
}

func pct(n, total int) string {
	if total == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(total))
}

func hasScope(scopes []string, want string) bool {
	return store.Identity{Scopes: scopes}.HasScope(want)
}

// readOnlyScopes reports whether every scope this session holds is a read.
//
// The suffix rule rather than a list, matching store.narrowToReadOnly: a scope
// added to the API later and not yet listed anywhere must not make a session
// look writable, and a write scope must never be missed however it is spelled.
// An empty scope set counts as read-only, which is the honest answer — such a
// session can do nothing at all.
func readOnlyScopes(scopes []string) bool {
	for _, s := range scopes {
		if !strings.HasSuffix(s, ":read") {
			return false
		}
	}
	return true
}
