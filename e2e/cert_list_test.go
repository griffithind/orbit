package e2e

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// TestHostCertificatesAreVisibleOverTheAPI covers the question that used to
// need psql: when does this host's certificate expire, which CA signed it, and
// has it been renewing.
//
// The host is enrolled for real, so the current certificate is the one the CA
// actually issued; the history behind it is written directly, because what is
// being tested is the listing rather than the renewal loop.
func TestHostCertificatesAreVisibleOverTheAPI(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	ctx := context.Background()

	host := h.createAndEnroll(t, ts, "cert-history", "10.42.63.1", false, false, nil)
	hostID := uuid.MustParse(host.id)

	// Four superseded renewals behind the live certificate. They share an
	// issued_at, which is what a burst of renewals looks like: now() is the
	// transaction timestamp, and nebula's validity is second-granular.
	now := time.Now()
	err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		caRow, err := tx.GetActiveCA(ctx, h.netID)
		if err != nil {
			return err
		}
		for i := 0; i < 4; i++ {
			c := store.Certificate{
				HostID: hostID, CAID: caRow.ID, Fingerprint: uuid.NewString(), PEM: "p",
				CertVer: 2, State: store.CertSuperseded,
				NotBefore: now.Add(-time.Duration(i+2) * time.Hour),
				NotAfter:  now.Add(-time.Duration(i) * time.Hour),
			}
			if err := tx.InsertCertificate(ctx, &c); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("write certificate history: %v", err)
	}

	get := func(query string) wire.CertificateListResponse {
		t.Helper()
		u := ts.URL + "/v1/hosts/" + host.id + "/certificates"
		if query != "" {
			u += "?" + query
		}
		var out wire.CertificateListResponse
		if code := h.adminReq(t, http.MethodGet, u, nil, &out); code != http.StatusOK {
			t.Fatalf("list certificates (%s): %d", query, code)
		}
		return out
	}

	all := get("")
	if len(all.Certificates) != 5 {
		t.Fatalf("history = %d certificates, want 5", len(all.Certificates))
	}
	// Newest first: every question asked of a history is about the recent end.
	for i := 1; i < len(all.Certificates); i++ {
		if all.Certificates[i].IssuedAt.After(all.Certificates[i-1].IssuedAt) {
			t.Errorf("history is not newest-first at row %d: %s after %s",
				i, all.Certificates[i].IssuedAt, all.Certificates[i-1].IssuedAt)
		}
	}

	// The live certificate is the one the CA actually issued at enrollment; the
	// backfilled history rows were written later, so position does not identify
	// it — state does.
	var current wire.CertificateResponse
	for _, c := range all.Certificates {
		if c.State == "active" {
			current = c
		}
	}
	if current.ID == "" {
		t.Fatal("an enrolled host has no active certificate in its history")
	}
	if current.CAName != "e2e-ca" {
		t.Errorf("ca_name = %q, want e2e-ca — a uuid alone makes rotation unreadable", current.CAName)
	}
	if current.CAID == "" || current.Fingerprint == "" {
		t.Errorf("certificate is missing ca_id or fingerprint: %+v", current)
	}
	if current.NotAfter.IsZero() || current.NotBefore.IsZero() {
		t.Errorf("certificate has no validity window: %+v", current)
	}
	// RenewAt is what makes "overdue" legible without the reader doing the
	// arithmetic themselves.
	if want := current.NotBefore.Add(current.NotAfter.Sub(current.NotBefore) / 2); !current.RenewAt.Equal(want) {
		t.Errorf("renew_at = %s, want %s (the midpoint)", current.RenewAt, want)
	}
	if current.CertVersion != 2 {
		t.Errorf("cert_version = %d, want 2", current.CertVersion)
	}

	// The state filter answers "which one is live" in one request.
	active := get("state=active")
	if len(active.Certificates) != 1 || active.Certificates[0].ID != current.ID {
		t.Errorf("state=active returned %d certificates, want just the current one",
			len(active.Certificates))
	}

	// Pagination over rows that all share a timestamp: without the id in the
	// key this would repeat or skip.
	seen := map[string]bool{}
	cursor := ""
	for i := 0; ; i++ {
		q := "limit=2"
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		page := get(q)
		for _, c := range page.Certificates {
			if seen[c.ID] {
				t.Errorf("certificate %s served on two pages", c.ID)
			}
			seen[c.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if i > 5 {
			t.Fatal("certificate pagination did not terminate")
		}
	}
	if len(seen) != 5 {
		t.Errorf("paged %d certificates, want 5", len(seen))
	}

	// An unknown host is a 404, not an empty list. During a failed enrollment
	// "no such host" and "this host has no certificate yet" are opposite
	// diagnoses, and an empty array says neither.
	var empty wire.CertificateListResponse
	if code := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/hosts/"+uuid.NewString()+"/certificates", nil, &empty); code != http.StatusNotFound {
		t.Errorf("certificates for an unknown host = %d, want 404", code)
	}

	// And the same rejection discipline as the host listing.
	for _, q := range []string{"state=expired", "limit=0", "cursor=zzzz"} {
		if code := h.adminReq(t, http.MethodGet,
			ts.URL+"/v1/hosts/"+host.id+"/certificates?"+q, nil, nil); code != http.StatusBadRequest {
			t.Errorf("certificates?%s = %d, want 400", q, code)
		}
	}
}

// TestHostDetailCarriesTheCurrentCertificate covers the one thing an operator
// opening a host wants immediately: its expiry, without a second request.
func TestHostDetailCarriesTheCurrentCertificate(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "detail-cert", "10.42.64.1", false, false, nil)

	var got wire.HostResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/hosts/"+host.id, nil, &got); code != http.StatusOK {
		t.Fatalf("get host: %d", code)
	}
	if len(got.ActiveCertificates) != 1 {
		t.Fatalf("host detail carries %d active certificates, want 1", len(got.ActiveCertificates))
	}
	cert := got.ActiveCertificates[0]
	if cert.State != "active" || cert.CAName != "e2e-ca" {
		t.Errorf("active certificate = %+v, want an active one signed by e2e-ca", cert)
	}
	if cert.NotAfter.Before(time.Now()) {
		t.Errorf("not_after is in the past: %s", cert.NotAfter)
	}

	// A host that has never enrolled has none, and says so by omission rather
	// than by a zero-valued certificate.
	var fresh wire.HostResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts", wire.CreateHostRequest{
		NetworkID: h.netID.String(), Name: "no-cert-yet", OverlayAddr: "10.42.64.2",
		RoleID: h.roleID.String(),
	}, &fresh); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/hosts/"+fresh.ID, nil, &fresh); code != http.StatusOK {
		t.Fatalf("get host: %d", code)
	}
	if len(fresh.ActiveCertificates) != 0 {
		t.Errorf("unenrolled host reports %d certificates", len(fresh.ActiveCertificates))
	}

	// The listing must NOT carry them: that would be one query per host, which
	// is the cost the whole listing design is avoiding.
	page := h.listHosts(t, ts.URL, "name_contains=detail-cert")
	if len(page.Hosts) != 1 {
		t.Fatalf("listing returned %d hosts, want 1", len(page.Hosts))
	}
	if len(page.Hosts[0].ActiveCertificates) != 0 {
		t.Error("the listing carries certificates; that is a query per row")
	}
}
