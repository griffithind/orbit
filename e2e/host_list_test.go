package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// listHosts issues one page request and returns the envelope.
func (h *harness) listHosts(t *testing.T, baseURL, query string) wire.MembershipListResponse {
	t.Helper()
	var out wire.MembershipListResponse
	u := baseURL + "/v1/memberships?network_id=" + h.netID.String()
	if query != "" {
		u += "&" + query
	}
	if code := h.adminReq(t, http.MethodGet, u, nil, &out); code != http.StatusOK {
		t.Fatalf("list hosts (%s): %d", query, code)
	}
	return out
}

func listedNames(resp wire.MembershipListResponse) []string {
	out := make([]string, 0, len(resp.Memberships))
	for _, h := range resp.Memberships {
		out = append(out, h.Name)
	}
	return out
}

// TestHostListPagesAndFilters is the listing contract over HTTP: an envelope
// that says whether there is another page, a cursor that survives a concurrent
// insert, and filters that reach SQL.
//
// The envelope is the breaking change. A bare array cannot tell a CLI drawing a
// table or a UI drawing a list whether it has the whole fleet, and a client that
// cannot tell assumes it does.
func TestHostListPagesAndFilters(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	// Four hosts and a page size of two: the last page is exactly full, which is
	// the boundary where a naive "len(page) == limit means more" is wrong.
	for i, name := range []string{"alpha", "bravo", "charlie", "delta"} {
		spec := membershipSpec{
			NetworkID: h.netID.String(), Name: name,
			OverlayAddr: fmt.Sprintf("10.42.60.%d", i+1),
			RoleID:      h.roleID.String(),
			Tags:        []string{"paged"},
		}
		if i < 2 {
			spec.Tags = append(spec.Tags, "front")
		}
		if code := h.createHost(t, ts.URL, spec, nil); code != http.StatusCreated {
			t.Fatalf("create %s: %d", name, code)
		}
	}

	first := h.listHosts(t, ts.URL, "limit=2")
	if got := listedNames(first); fmt.Sprint(got) != fmt.Sprint([]string{"alpha", "bravo"}) {
		t.Fatalf("first page = %v, want [alpha bravo]", got)
	}
	if first.NextCursor == "" {
		t.Fatal("first page carries no cursor, so a client cannot reach the rest of the fleet")
	}
	if first.TotalCount != nil {
		t.Errorf("total_count was returned without count=true: %d", *first.TotalCount)
	}

	// A host created between the two fetches. It sorts before the cursor, which
	// under OFFSET would shift the second page and silently drop "charlie".
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "alpha-2", OverlayAddr: "10.42.60.20",
		RoleID: h.roleID.String(), Tags: []string{"paged"},
	}, nil); code != http.StatusCreated {
		t.Fatal("create alpha-2")
	}

	second := h.listHosts(t, ts.URL, "limit=2&cursor="+url.QueryEscape(first.NextCursor))
	if got := listedNames(second); fmt.Sprint(got) != fmt.Sprint([]string{"charlie", "delta"}) {
		t.Fatalf("second page = %v, want [charlie delta] — an insert before the cursor moved the window", got)
	}
	// Exactly full and still the last page: no cursor, or every client makes one
	// more request and shows an empty page.
	if second.NextCursor != "" {
		third := h.listHosts(t, ts.URL, "limit=2&cursor="+url.QueryEscape(second.NextCursor))
		t.Fatalf("full final page handed out a cursor that returned %d hosts", len(third.Memberships))
	}

	// count is opt-in, and counts the filter rather than the page.
	counted := h.listHosts(t, ts.URL, "limit=2&count=true&tag=paged")
	if counted.TotalCount == nil {
		t.Fatal("count=true returned no total_count")
	}
	if *counted.TotalCount != 5 {
		t.Errorf("total_count = %d, want 5", *counted.TotalCount)
	}
	if len(counted.Memberships) != 2 {
		t.Errorf("page size = %d, want 2 — the count must not widen the page", len(counted.Memberships))
	}

	// Filters.
	if got := listedNames(h.listHosts(t, ts.URL, "tag=front")); fmt.Sprint(got) != fmt.Sprint([]string{"alpha", "bravo"}) {
		t.Errorf("tag=front = %v, want [alpha bravo]", got)
	}
	if got := listedNames(h.listHosts(t, ts.URL, "name_contains=ALP")); fmt.Sprint(got) != fmt.Sprint([]string{"alpha", "alpha-2"}) {
		t.Errorf("name_contains=ALP = %v, want [alpha alpha-2]", got)
	}
	if got := listedNames(h.listHosts(t, ts.URL, "role_id="+h.roleID.String())); len(got) != 5 {
		t.Errorf("role filter returned %v, want all 5", got)
	}
	if got := h.listHosts(t, ts.URL, "state=suspended"); len(got.Memberships) != 0 {
		t.Errorf("state=suspended returned %d hosts, want none", len(got.Memberships))
	}
}

// TestHostListBehindFilter covers the incident question as a filter. It is the
// same population /v1/networks/{id}/convergence reports as lagging, in a form
// that can be acted on host by host.
func TestHostListBehindFilter(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var caughtUp, behind wire.MembershipResponse
	for _, spec := range []struct {
		name, addr string
		out        *wire.MembershipResponse
	}{
		{"converged", "10.42.61.1", &caughtUp},
		{"laggard", "10.42.61.2", &behind},
	} {
		if code := h.createHost(t, ts.URL, membershipSpec{
			NetworkID: h.netID.String(), Name: spec.name, OverlayAddr: spec.addr,
			RoleID: h.roleID.String(),
		}, spec.out); code != http.StatusCreated {
			t.Fatalf("create %s: %d", spec.name, code)
		}
	}

	// Both hosts must be enrolled or active to count toward convergence at all.
	epochs := h.networkEpochs(t, ts.URL)
	for _, membershipID := range []string{caughtUp.ID, behind.ID} {
		id := uuid.MustParse(membershipID)
		h.setState(t, id, store.MembershipActive)
	}
	h.reportAs(t, uuid.MustParse(caughtUp.ID), store.AgentReport{
		ConfigEpoch: epochs.ConfigEpoch, BlocklistEpoch: epochs.BlocklistEpoch,
	})

	got := listedNames(h.listHosts(t, ts.URL, "behind=true"))
	if fmt.Sprint(got) != fmt.Sprint([]string{"laggard"}) {
		t.Errorf("behind=true = %v, want [laggard]", got)
	}
}

// setState moves a host directly, the way enrollment would. Used where a test
// needs a host that counts toward convergence without running the whole
// enrollment handshake for it.
func (h *harness) setState(t *testing.T, membershipID uuid.UUID, state string) {
	t.Helper()
	err := h.store.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return tx.SetHostState(ctx, membershipID, state)
	})
	if err != nil {
		t.Fatalf("set host state: %v", err)
	}
}

// TestHostResponseCarriesWhatPatchAccepts is the read-modify-write property.
//
// role_id and static_addrs are settable through PATCH. While they were absent
// from the response, a client that read a host, changed its tags, and wrote it
// back had no way to preserve them — and for a lighthouse, dropping
// static_addrs is an address every host in the mesh keeps dialling and none can
// reach.
func TestHostResponseCarriesWhatPatchAccepts(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var created wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "lighthouse-1", OverlayAddr: "10.42.62.1",
		RoleID: h.roleID.String(), IsLighthouse: true,
		StaticAddrs: []string{"198.51.100.7:4242"},
		Tags:        []string{"edge"},
	}, &created); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	// Versions arrive with an agent report and are the first diagnostic for a
	// host that has stopped renewing.
	h.reportAs(t, uuid.MustParse(created.ID), store.AgentReport{
		ConfigEpoch: 1, BlocklistEpoch: 1,
		NebulaVersion: "1.9.5", AgentVersion: "0.4.2",
	})

	var got wire.MembershipResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/memberships/"+created.ID, nil, &got); code != http.StatusOK {
		t.Fatalf("get host: %d", code)
	}
	if got.RoleID != h.roleID.String() {
		t.Errorf("role_id = %q, want %s", got.RoleID, h.roleID)
	}
	if got.RoleName != "default" {
		t.Errorf("role_name = %q, want default — a uuid alone forces a lookup per host", got.RoleName)
	}
	if fmt.Sprint(got.StaticAddrs) != fmt.Sprint([]string{"198.51.100.7:4242"}) {
		t.Errorf("static_addrs = %v, want [198.51.100.7:4242]", got.StaticAddrs)
	}
	if got.NebulaVersion != "1.9.5" || got.AgentVersion != "0.4.2" {
		t.Errorf("versions = %q/%q, want 1.9.5/0.4.2", got.NebulaVersion, got.AgentVersion)
	}
	if got.CreatedAt.IsZero() {
		t.Error("created_at is zero")
	}

	// The listing must carry them too, or a client has to fetch every host it
	// lists to render one.
	page := h.listHosts(t, ts.URL, "name_contains=lighthouse-1")
	if len(page.Memberships) != 1 {
		t.Fatalf("listing returned %d hosts, want 1", len(page.Memberships))
	}
	if page.Memberships[0].RoleName != "default" || len(page.Memberships[0].StaticAddrs) != 1 {
		t.Errorf("listed host is missing role_name or static_addrs: %+v", page.Memberships[0])
	}

	// The round trip: change one field, write back everything the response gave
	// us, and lose nothing.
	tags := []string{"edge", "retagged"}
	roleID, static := got.RoleID, got.StaticAddrs
	var updated wire.MembershipResponse
	if code := h.adminReq(t, http.MethodPatch, ts.URL+"/v1/memberships/"+created.ID,
		wire.UpdateHostRequest{Tags: &tags, RoleID: &roleID, StaticAddrs: &static},
		&updated); code != http.StatusOK {
		t.Fatalf("patch host: %d", code)
	}
	if updated.RoleID != h.roleID.String() {
		t.Errorf("read-modify-write dropped the role: %q", updated.RoleID)
	}
	if len(updated.StaticAddrs) != 1 {
		t.Errorf("read-modify-write dropped static_addrs: %v", updated.StaticAddrs)
	}
	if fmt.Sprint(updated.Tags) != fmt.Sprint(tags) {
		t.Errorf("tags = %v, want %v", updated.Tags, tags)
	}
}

// TestHostListRejectsParametersItCannotHonour covers the failure mode a silent
// filter creates: a caller reads an unfiltered page as the answer to the
// question they asked.
func TestHostListRejectsParametersItCannotHonour(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	for _, q := range []string{
		"state=retired",     // not a host state
		"state=deleted",     // a state, but never listable
		"behind=yes",        // not a bool
		"count=sure",        // not a bool
		"limit=0",           // not a page
		"limit=100000",      // above the ceiling; clamping would return fewer than asking for nothing
		"role_id=web",       // a name where a uuid belongs
		"cursor=not-base64", // not a cursor this endpoint issued
	} {
		var out wire.MembershipListResponse
		code := h.adminReq(t, http.MethodGet,
			ts.URL+"/v1/memberships?network_id="+h.netID.String()+"&"+q, nil, &out)
		if code != http.StatusBadRequest {
			t.Errorf("GET /v1/memberships?%s = %d, want 400", q, code)
		}
	}
}
