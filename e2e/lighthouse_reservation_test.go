package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/wire"
)

// A lighthouse is provisioned in ONE step, by a machine nobody is watching.
//
// This is the topology that most needs unattended provisioning — a fixed-address
// box in a datacentre, brought up from a template — and it was the one that
// needed a human at the end: reserve a name, wait for the machine to appear,
// then PATCH the membership. Between those two the machine sat in the network
// doing nothing while every other machine had been told there is no lighthouse.
//
// The test asserts the gap is gone: after redemption and with no further admin
// call, the membership IS a lighthouse and another machine's rendered config
// names it.
func TestReservedLighthouseNeedsNoFollowUp(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	const publicAddr = "203.0.113.55"
	advertise := 4567

	var code wire.EnrollmentCodeResponse
	if status := h.adminPost(t, ts.URL+"/v1/networks/"+h.netID.String()+"/reservations",
		wire.ReserveRequest{
			Name:          "reserved-lh",
			OverlayAddr:   "10.42.71.1",
			RoleID:        h.roleID.String(),
			IsLighthouse:  true,
			PublicAddrs:   []string{publicAddr},
			AdvertisePort: &advertise,
		}, &code); status != http.StatusCreated {
		t.Fatalf("reserve a lighthouse: status %d", status)
	}

	id, err := device.Generate()
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	client := agent.NewClient(ts.URL)
	joined, err := client.JoinWithCode(
		ctx, id, h.netID.String(), "reserved-lh", "", code.Code, time.Now())
	if err != nil {
		t.Fatalf("join with the reservation: %v", err)
	}

	// Claim, because a reservation authorizes but does not issue: the machine
	// still presents a keypair and gets a certificate. This is the ordinary
	// second half of `orbit join`, not a follow-up ADMIN call — nobody
	// touches the control plane between the reservation and a working
	// lighthouse, which is the property under test.
	kp, err := agent.GenerateKeypair(h.curve)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	if _, err := client.Claim(ctx, id, joined.MembershipID, kp, "e2e", time.Now()); err != nil {
		t.Fatalf("claim: %v", err)
	}

	// NO ADMIN CALL between the reservation and the reads below. That absence is
	// the whole assertion.
	var got wire.MembershipResponse
	if status := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/memberships/"+joined.MembershipID, nil, &got); status != http.StatusOK {
		t.Fatalf("read the membership: status %d", status)
	}
	if !got.IsLighthouse {
		t.Error("the reservation said lighthouse and the membership is not one")
	}
	want := publicAddr + ":4567"
	if len(got.StaticAddrs) != 1 || got.StaticAddrs[0] != want {
		t.Errorf("static_addrs = %v, want [%s] — the address comes from the device and "+
			"the port from advertise_port, both carried on the reservation", got.StaticAddrs, want)
	}

	// The address landed on the DEVICE, which is where it belongs: it is a fact
	// about the machine, shared by every network the machine lights.
	var dev wire.DeviceResponse
	if status := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/devices/"+joined.DeviceID, nil, &dev); status != http.StatusOK {
		t.Fatalf("read the device: status %d", status)
	}
	if len(dev.PublicAddrs) != 1 || dev.PublicAddrs[0] != publicAddr {
		t.Errorf("device public_addrs = %v, want [%s]", dev.PublicAddrs, publicAddr)
	}

	// And the point of all of it: another machine is told to use it.
	other := h.createAndEnroll(t, ts, "ordinary", "10.42.71.9", false, false, nil)
	cfg := readFile(t, agent.DefaultLayout(other.dir).ConfigPath())
	if !strings.Contains(cfg, want) {
		t.Errorf("the fleet was not told about the reserved lighthouse at %s:\n%s", want, cfg)
	}
}

// A lighthouse reservation with nowhere to be reached is refused where an
// operator can still fix it.
//
// The alternative is not an error at all: the membership is created, marked
// am_lighthouse, and every machine in the mesh is handed an empty address list
// for it. The symptom is "nothing can find anything", days later, on a machine
// nobody is watching — and by then the operator who knew the address has moved
// on. Reservation time is the last moment they are present.
func TestReservedLighthouseWithoutAnAddressIsRefused(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	var out wire.Error
	status := h.adminPost(t, ts.URL+"/v1/networks/"+h.netID.String()+"/reservations",
		wire.ReserveRequest{Name: "blind-lh", IsLighthouse: true}, &out)
	if status != http.StatusBadRequest {
		t.Fatalf("reserving an unreachable lighthouse: status %d, want 400", status)
	}
	if !strings.Contains(out.Error, "public address") {
		t.Errorf("the error does not name the missing thing: %q", out.Error)
	}

	// A relay is a different matter: it is found by the same discovery every
	// other machine uses, so it needs no fixed address and must not be refused.
	var code wire.EnrollmentCodeResponse
	if status := h.adminPost(t, ts.URL+"/v1/networks/"+h.netID.String()+"/reservations",
		wire.ReserveRequest{Name: "plain-relay", IsRelay: true}, &code); status != http.StatusCreated {
		t.Fatalf("reserving a relay with no address: status %d, want 201", status)
	}
}

// A port on a public address is refused, not trimmed.
//
// An operator who wrote "203.0.113.55:4242" believes they set the port.
// Stripping it silently would leave them believing a number that is not in
// effect — and the port they wanted is a different field on a different noun,
// so saying that is the useful answer.
func TestReservedPublicAddrRejectsAPort(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	for _, addr := range []string{"203.0.113.55:4242", "[2001:db8::1]:4242"} {
		var out wire.Error
		status := h.adminPost(t, ts.URL+"/v1/networks/"+h.netID.String()+"/reservations",
			wire.ReserveRequest{
				Name:         "ported-" + strings.NewReplacer(":", "-", "[", "", "]", "").Replace(addr),
				IsLighthouse: true, PublicAddrs: []string{addr},
			}, &out)
		if status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", addr, status)
		}
	}

	// A bare IPv6 address is NOT a host:port, and a colon count would say
	// otherwise. This is the case that makes the check worth having.
	var code wire.EnrollmentCodeResponse
	if status := h.adminPost(t, ts.URL+"/v1/networks/"+h.netID.String()+"/reservations",
		wire.ReserveRequest{
			Name: "v6-lh", IsLighthouse: true, PublicAddrs: []string{"2001:db8::1"},
		}, &code); status != http.StatusCreated {
		t.Errorf("a bare IPv6 public address was refused: status %d", status)
	}
}

// A reservation SEEDS a machine's public addresses; it does not impose them.
//
// One machine has one set of public addresses. If joining network B could
// rewrite them, it would move where network A believes the machine is — a
// cross-network effect from an operation scoped to a single network, which is
// the exact confusion the device/membership split exists to prevent.
func TestReservationDoesNotOverwriteAMachinesAddresses(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	// The machine joins once, with its real address.
	var first wire.EnrollmentCodeResponse
	if status := h.adminPost(t, ts.URL+"/v1/networks/"+h.netID.String()+"/reservations",
		wire.ReserveRequest{
			Name: "multi-net-lh", RoleID: h.roleID.String(),
			IsLighthouse: true, PublicAddrs: []string{"203.0.113.80"},
		}, &first); status != http.StatusCreated {
		t.Fatalf("first reservation: status %d", status)
	}
	id, err := device.Generate()
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	client := agent.NewClient(ts.URL)
	joined, err := client.JoinWithCode(ctx, id, h.netID.String(), "multi-net-lh", "", first.Code, time.Now())
	if err != nil {
		t.Fatalf("first join: %v", err)
	}

	// A second network, and a reservation for the SAME machine claiming a
	// different address. The machine is the same key, so this is one device.
	var second wire.NetworkResponse
	if status := h.adminPost(t, ts.URL+"/v1/networks", wire.CreateNetworkRequest{
		Name: "second-" + uuid.NewString()[:8], CIDRs: []string{"10.71.0.0/24"},
	}, &second); status != http.StatusCreated {
		t.Fatalf("create a second network: status %d", status)
	}

	var secondCode wire.EnrollmentCodeResponse
	if status := h.adminPost(t, ts.URL+"/v1/networks/"+second.ID+"/reservations",
		wire.ReserveRequest{
			Name: "multi-net-lh", IsLighthouse: true, PublicAddrs: []string{"198.51.100.99"},
		}, &secondCode); status != http.StatusCreated {
		t.Fatalf("second reservation: status %d", status)
	}
	if _, err := client.JoinWithCode(ctx, id, second.ID, "multi-net-lh", "", secondCode.Code, time.Now()); err != nil {
		t.Fatalf("second join: %v", err)
	}

	var dev wire.DeviceResponse
	if status := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/devices/"+joined.DeviceID, nil, &dev); status != http.StatusOK {
		t.Fatalf("read the device: status %d", status)
	}
	if len(dev.PublicAddrs) != 1 || dev.PublicAddrs[0] != "203.0.113.80" {
		t.Errorf("public_addrs = %v, want [203.0.113.80] — a reservation in a second "+
			"network moved where the first network believes this machine is", dev.PublicAddrs)
	}
}
