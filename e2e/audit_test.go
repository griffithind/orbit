package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// Audit log filtering.
//
// The store has implemented all six filters since the table existed; the
// handler wired up three of them, so "what happened in the last hour" and
// "show me more than a page" were both inexpressible against an append-only
// table that only grows. These tests hold the two halves of the fix: the
// window and the cap actually narrow, and a bound the server cannot parse is
// refused rather than dropped — a dropped bound answers a wider question than
// the one asked, and reads as if nothing happened.

func TestAuditTimeWindowAndLimitNarrow(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	var ids []string
	for i, name := range []string{"audit-a", "audit-b", "audit-c"} {
		var host wire.MembershipResponse
		if code := h.createHost(t, ts.URL, membershipSpec{
			NetworkID: h.netID.String(), Name: name,
			OverlayAddr: fmt.Sprintf("10.42.31.%d", i+1),
			RoleID:      h.roleID.String(),
		}, &host); code != http.StatusCreated {
			t.Fatalf("create host %s: %d", name, code)
		}
		ids = append(ids, host.ID)
	}

	// Wide enough to absorb any disagreement between this process's clock and
	// the database's, which stamps `at` with now().
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	// Scoped to one host, so the count is exact despite an audit table shared
	// with every other test in this database.
	one := "action=" + store.ActionMembershipCreated + "&target_id=" + ids[0]

	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"no window", one, 1},
		{"since before the event", one + "&since=" + url.QueryEscape(past), 1},
		{"since after the event", one + "&since=" + url.QueryEscape(future), 0},
		{"until after the event", one + "&until=" + url.QueryEscape(future), 1},
		{"until before the event", one + "&until=" + url.QueryEscape(past), 0},
		{"window around the event", one + "&since=" + url.QueryEscape(past) +
			"&until=" + url.QueryEscape(future), 1},
	}
	for _, c := range cases {
		var got []wire.AuditRecordResponse
		if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/audit-logs?"+c.query, nil, &got); code != http.StatusOK {
			t.Fatalf("%s: status %d", c.name, code)
		}
		if len(got) != c.want {
			t.Errorf("%s: %d entries, want %d", c.name, len(got), c.want)
		}
	}

	// The cap has to be the caller's, not the store's default: three hosts were
	// created and only two are asked for.
	var capped []wire.AuditRecordResponse
	if code := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/audit-logs?action="+store.ActionMembershipCreated+"&limit=2", nil, &capped); code != http.StatusOK {
		t.Fatalf("limited listing: %d", code)
	}
	if len(capped) != 2 {
		t.Errorf("limit=2 returned %d entries", len(capped))
	}

	// Newest first, so a limit is a page rather than an arbitrary sample.
	if len(capped) == 2 && capped[0].At.Before(capped[1].At) {
		t.Errorf("entries are not newest first: %s then %s", capped[0].At, capped[1].At)
	}
}

// TestAuditRejectsUnparseableFilters covers the failure the store cannot: a
// filter the handler quietly discards returns a wider result set that looks
// like an answer.
func TestAuditRejectsUnparseableFilters(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	now := time.Now().UTC().Format(time.RFC3339)
	cases := []struct {
		query string
		names string // must appear in the message, so the caller can fix it
	}{
		{"since=yesterday", "since"},
		{"since=2026-01-02", "since"},
		{"until=nope", "until"},
		{"limit=abc", "limit"},
		{"limit=0", "limit"},
		{"limit=-5", "limit"},
		{"limit=100000", "limit"},
		{"since=" + url.QueryEscape(now) + "&until=" +
			url.QueryEscape(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)), "until"},
	}
	for _, c := range cases {
		code, body := h.rawGet(t, ts.URL+"/v1/audit-logs?"+c.query)
		if code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (a filter that is ignored reads as a quiet period)", c.query, code)
			continue
		}
		if !strings.Contains(body, c.names) {
			t.Errorf("%s: 400 body %q does not name the offending parameter", c.query, body)
		}
	}
}

// rawGet returns the status and body, which adminReq deliberately does not:
// asserting on an error message is the point here.
func (h *harness) rawGet(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
