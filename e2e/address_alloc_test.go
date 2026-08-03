package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

// TestHostCreationAllocatesAnAddress.
//
// Omitting overlay_addr is the normal case now. Requiring one made every caller
// keep its own record of what was in use — a spreadsheet, a runbook, a
// colleague's memory — and be wrong about it occasionally; the control plane
// holds the only authoritative answer.
func TestHostCreationAllocatesAnAddress(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	seen := map[string]bool{}
	for i := range 3 {
		var host wire.HostResponse
		if code := h.adminPost(t, ts.URL+"/v1/hosts", wire.CreateHostRequest{
			NetworkID: h.netID.String(),
			Name:      "alloc-" + uuid.NewString()[:8],
			RoleID:    h.roleID.String(),
		}, &host); code != http.StatusCreated {
			t.Fatalf("create host %d without an address: %d", i, code)
		}
		if len(host.OverlayAddrs) != 1 {
			t.Fatalf("host has %d addresses, want exactly one allocated: %v",
				len(host.OverlayAddrs), host.OverlayAddrs)
		}

		addr, err := netip.ParseAddr(host.OverlayAddrs[0])
		if err != nil {
			t.Fatalf("allocated %q, which is not an address: %v", host.OverlayAddrs[0], err)
		}
		if !netip.MustParsePrefix("10.42.0.0/16").Contains(addr) {
			t.Errorf("allocated %s, which is outside the network", addr)
		}
		if seen[addr.String()] {
			t.Fatalf("allocated %s twice", addr)
		}
		seen[addr.String()] = true
	}

	// One address, not one per family. Dual-stacking by default would double
	// what a later address change disrupts and would silently convert a fleet
	// the moment an IPv6 prefix was added to the network.
	for addr := range seen {
		if strings.Contains(addr, ":") {
			t.Errorf("allocated an IPv6 address %s from an IPv4-only network", addr)
		}
	}
}

// TestAddressExhaustionIsAClear409.
//
// A /30 holds two assignable addresses. The third request must fail with a
// conflict that NAMES THE PREFIX — never a timeout, which is what an allocator
// that retried until the context died would produce, and never a 500, which
// tells an operator something broke when nothing did.
func TestAddressExhaustionIsAClear409(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var net wire.NetworkResponse
	if code := h.adminPost(t, ts.URL+"/v1/networks", wire.CreateNetworkRequest{
		Name: "tiny-" + uuid.NewString()[:8], CIDRs: []string{"10.61.0.0/30"},
	}, &net); code != http.StatusCreated {
		t.Fatalf("create a /30 network: %d", code)
	}

	for i := range 2 {
		if code := h.adminPost(t, ts.URL+"/v1/hosts", wire.CreateHostRequest{
			NetworkID: net.ID, Name: "fill-" + uuid.NewString()[:8],
		}, nil); code != http.StatusCreated {
			t.Fatalf("filling a /30, host %d: %d", i, code)
		}
	}

	code, body := h.adminPostExpectingFailure(t, ts.URL+"/v1/hosts",
		wire.CreateHostRequest{NetworkID: net.ID, Name: "overflow-" + uuid.NewString()[:8]})
	if code != http.StatusConflict {
		t.Fatalf("creating a host in a full /30 = %d, want 409", code)
	}
	if !strings.Contains(body.Error, "10.61.0.0/30") {
		t.Errorf("the refusal does not name the prefix that ran out: %q", body.Error)
	}
}

// adminPostExpectingFailure decodes an error body, which the shared helper
// deliberately does not: it only unmarshals on success, and the message is the
// thing under test here.
func (h *harness) adminPostExpectingFailure(t *testing.T, url string, body any) (int, wire.Error) {
	t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var out wire.Error
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestHostReportsItsInstanceResources.
//
// The tun device and the listen port are what keep two nebula processes on one
// machine apart, and the config mode says whether the policy Orbit reports about
// this host is the whole truth or a lower bound. All three have to be readable,
// or an operator debugging a host has to infer them from a rendered file they
// cannot see.
func TestHostReportsItsInstanceResources(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var created wire.HostResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts", wire.CreateHostRequest{
		NetworkID: h.netID.String(), Name: "instance-" + uuid.NewString()[:8],
	}, &created); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	var got wire.HostResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/hosts/"+created.ID, nil, &got); code != http.StatusOK {
		t.Fatalf("get host: %d", code)
	}
	if got.ConfigMode == "" {
		t.Error("config_mode is empty, so a reader cannot tell whether the reported " +
			"policy is complete or a lower bound")
	}
	if got.TunDev == "" {
		t.Error("tun_dev is empty, so nothing says which interface this host takes")
	}
	if len(got.TunDev) > 15 {
		t.Errorf("tun_dev %q is longer than 15 characters and Linux would truncate it in silence", got.TunDev)
	}
	if got.RestartRequiredEpoch != 0 {
		t.Errorf("a freshly created host is already marked restart-required (%d)", got.RestartRequiredEpoch)
	}
}
