package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/griffithind/orbit/internal/store"
)

//------------------------------------------------------------------------------
// The audit trail
//------------------------------------------------------------------------------

// Read-only, and it could not be anything else: the application role holds no
// UPDATE or DELETE grant on orbit.audit_log, so an audit trail this process
// could rewrite would not be an audit trail. Corrections are new entries.
//
// The metadata column is jsonb and goes through <pre>{{ . }}</pre>. It is
// server-authored today, but it is also the one column here that carries values
// that came from a request — a host name in a deletion entry, a CIDR in a prefix
// entry — so it is treated as untrusted and never as template.HTML.

type auditView struct {
	Records []auditRecordView
	Filter  auditFilterView
	Actions []string
	// AtLimit says the page is full, which is the only honest way to tell a
	// reader that older entries exist without running a second count over a table
	// that only grows.
	AtLimit bool
	Limit   int
}

type auditFilterView struct {
	Action     string
	TargetID   string
	SinceHours int
}

type auditRecordView struct {
	At           time.Time
	Action       string
	ActorType    string
	ActorDisplay string
	TargetType   string
	TargetID     string
	SourceIP     string
	Meta         string
	// HostLink is set when the target is a host, so an entry is one click from
	// the machine it describes. An audit line that names a uuid and stops is a
	// line that sends the reader to a search box.
	HostLink string
}

const auditPageSize = 200

// auditActions are the filters offered in the dropdown.
//
// A curated list rather than every constant in store: these are the ones an
// incident actually asks about, and a select with forty options is one nobody
// reads to the end of. The free-text target filter covers the rest.
var auditActions = []string{
	store.ActionHostBlocked,
	store.ActionHostUnblocked,
	store.ActionHostCreated,
	store.ActionHostDeleted,
	store.ActionHostUpdated,
	store.ActionEnrollCodeCreated,
	store.ActionEnrolled,
	store.ActionEnrollFailed,
	store.ActionRecovered,
	store.ActionCAActivated,
	store.ActionCAForceActivated,
	store.ActionCARetired,
	store.ActionTokenCreated,
	store.ActionTokenRevoked,
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()

	f := store.AuditFilter{
		TargetID: strings.TrimSpace(q.Get("target")),
		Limit:    auditPageSize,
	}
	if a := q.Get("action"); a != "" && containsStr(auditActions, a) {
		f.Action = a
	}
	hours := 0
	if v := q.Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 24*365 {
			hours = n
			f.Since = time.Now().Add(-time.Duration(n) * time.Hour)
		}
	}

	var records []store.AuditRecord
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		records, err = tx.ListAudit(ctx, f)
		return err
	})
	if err != nil {
		return err
	}

	v := auditView{
		Filter:  auditFilterView{Action: f.Action, TargetID: f.TargetID, SinceHours: hours},
		Actions: auditActions,
		AtLimit: len(records) >= auditPageSize,
		Limit:   auditPageSize,
	}
	for _, rec := range records {
		rv := auditRecordView{
			At:           rec.At,
			Action:       rec.Action,
			ActorType:    rec.ActorType,
			ActorDisplay: rec.ActorDisplay,
			TargetType:   rec.TargetType,
			TargetID:     rec.TargetID,
			Meta:         string(rec.Meta),
		}
		if rec.SourceIP != nil {
			rv.SourceIP = rec.SourceIP.String()
		}
		if rec.TargetType == "host" && rec.TargetID != "" {
			rv.HostLink = "/ui/hosts/" + rec.TargetID
		}
		v.Records = append(v.Records, rv)
	}

	p := s.newPage(r, "Audit")
	if err := s.withNav(r.Context(), p, q.Get("network")); err != nil {
		return err
	}
	p.Data = v
	return s.render(w, r, "audit.html", http.StatusOK, p)
}

//------------------------------------------------------------------------------
// Tokens
//------------------------------------------------------------------------------

// Listing only. Creating a token from a browser would mean rendering a
// credential into a page, which this UI does exactly once — for an enrollment
// code, which is single-use and short-lived. An API token is neither.
//
// last_used_at is the column this page exists for, and it is the leftmost one
// after the name for that reason: after a leak, the question is not what scopes
// a token had, it is whether it was used and when. Revoked tokens stay listed,
// because a row that vanishes cannot answer "was it used AFTER we revoked it" —
// and that is the question.

type tokensView struct {
	Tokens []tokenView
}

type tokenView struct {
	ID         string
	Name       string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	Badge      badge
	// UsedAfterRevocation is the alarming case, computed rather than left for a
	// reader to spot by comparing two timestamps in different columns.
	UsedAfterRevocation bool
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) error {
	var tokens []store.APIToken
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		tokens, err = tx.ListAPITokens(ctx)
		return err
	})
	if err != nil {
		return err
	}

	now := time.Now()
	v := tokensView{}
	for _, t := range tokens {
		tv := tokenView{
			ID:         t.ID.String(),
			Name:       t.Name,
			Scopes:     t.Scopes,
			CreatedAt:  t.CreatedAt,
			ExpiresAt:  t.ExpiresAt,
			LastUsedAt: t.LastUsedAt,
			RevokedAt:  t.RevokedAt,
		}
		switch {
		case t.RevokedAt != nil:
			tv.Badge = badgeMuted("revoked")
			tv.UsedAfterRevocation = t.LastUsedAt != nil && t.LastUsedAt.After(*t.RevokedAt)
			if tv.UsedAfterRevocation {
				tv.Badge = badgeBad("USED AFTER REVOCATION")
			}
		case t.ExpiresAt != nil && now.After(*t.ExpiresAt):
			tv.Badge = badgeMuted("expired")
		case t.LastUsedAt == nil:
			// Not a fault, but worth seeing: a token minted and never used is
			// either a credential waiting to be deployed or one that was written
			// down somewhere and forgotten.
			tv.Badge = badgeWarn("never used")
		default:
			tv.Badge = badgeOK("in use")
		}
		v.Tokens = append(v.Tokens, tv)
	}

	p := s.newPage(r, "API tokens")
	if err := s.withNav(r.Context(), p, r.URL.Query().Get("network")); err != nil {
		return err
	}
	p.Data = v
	return s.render(w, r, "tokens.html", http.StatusOK, p)
}
