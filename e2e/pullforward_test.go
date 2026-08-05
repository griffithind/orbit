package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// A role's groups live inside the signed certificate, so editing them does not
// reach a host until it renews — at the midpoint of its own certificate, hours
// away on a day-long one.
//
// The agent has always been able to accept a server-supplied RenewAfter and
// pull renewal forward. What was missing was any reason for the server to send
// one: State emitted the certificate's own midpoint unconditionally, which is
// exactly the value RenewAtWithHint is documented to ignore because it restates
// what the agent already computes. The mechanism was complete on one side and
// never triggered from the other, and every test passed either side of it.
//
// These tests are the trigger.

func TestGroupChangePullsRenewalForward(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	host := h.createAndEnroll(t, ts, "pullfwd", "10.42.12.1", false, false, nil)
	client := xffClient(t, ts.URL, host.addr)

	// Steady state: the server offers the certificate's own midpoint, which is
	// far in the future and which the agent will disregard as a restatement.
	before := renewAfter(t, ctx, client)
	if !before.After(time.Now().Add(time.Hour)) {
		t.Fatalf("baseline RenewAfter = %s, expected roughly the certificate midpoint", before)
	}

	// Change the role's groups. The fixture role carries ["default"] and the
	// CA permits only that group, so dropping it is the one genuine change
	// available — and it is the security-relevant direction anyway: the host's
	// certificate now asserts a group the role no longer grants.
	if code := h.adminReq(t, http.MethodPatch, ts.URL+"/v1/roles/"+h.roleID.String(),
		wire.UpdateRoleRequest{Groups: &[]string{}}, nil); code != http.StatusOK &&
		code != http.StatusAccepted {
		t.Fatalf("patch role groups: %d", code)
	}

	after := renewAfter(t, ctx, client)
	if !after.Before(before) {
		t.Fatalf("RenewAfter did not move earlier after a group change: %s -> %s.\n"+
			"The pull-forward is inert: State is still emitting the certificate\n"+
			"midpoint, which the agent ignores by design.", before, after)
	}
	if after.After(time.Now().Add(time.Minute)) {
		t.Errorf("RenewAfter = %s, expected roughly now so the agent renews promptly", after)
	}
}

// TestFirewallChangeDoesNotPullRenewalForward is the other half of the
// contract, and the one that keeps this from being a fleet-wide resigning
// machine. Firewall rules are config: they converge in seconds and cost no
// certificate. Only a group change touches what is signed.
func TestFirewallChangeDoesNotPullRenewalForward(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	host := h.createAndEnroll(t, ts, "fwonly", "10.42.12.2", false, false, nil)
	client := xffClient(t, ts.URL, host.addr)

	before := renewAfter(t, ctx, client)

	raw := json.RawMessage(`{"inbound":[{"port":"22","proto":"tcp","host":"any"}],
	                         "outbound":[{"port":"any","proto":"any","host":"any"}]}`)
	if code := h.adminReq(t, http.MethodPatch, ts.URL+"/v1/roles/"+h.roleID.String(),
		wire.UpdateRoleRequest{Firewall: &raw}, nil); code != http.StatusOK {
		t.Fatalf("patch role firewall: %d", code)
	}

	after := renewAfter(t, ctx, client)
	if !after.Equal(before) {
		t.Errorf("a firewall-only edit moved RenewAfter %s -> %s; it must not, "+
			"or every config change becomes a fleet-wide reissue", before, after)
	}
}

// TestPullForwardStopsOnceReissued: the marker is never cleared, so the check
// has to be against the certificate's own issued_at rather than a flag. A host
// that has already renewed onto the new groups must go back to its normal
// schedule, or it renews on every poll forever.
func TestPullForwardStopsOnceReissued(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	host := h.createAndEnroll(t, ts, "reissued", "10.42.12.3", false, false, nil)
	membershipID := uuid.MustParse(host.id)
	client := xffClient(t, ts.URL, host.addr)

	if code := h.adminReq(t, http.MethodPatch, ts.URL+"/v1/roles/"+h.roleID.String(),
		wire.UpdateRoleRequest{Groups: &[]string{}}, nil); code != http.StatusOK &&
		code != http.StatusAccepted {
		t.Fatalf("patch role groups: %d", code)
	}
	pulled := renewAfter(t, ctx, client)
	if pulled.After(time.Now().Add(time.Minute)) {
		t.Fatalf("expected a pulled-forward hint, got %s", pulled)
	}

	// Reissue, standing in for the renewal the agent would now perform.
	h.reissue(t, ctx, membershipID)

	settled := renewAfter(t, ctx, client)
	if !settled.After(time.Now().Add(time.Hour)) {
		t.Errorf("RenewAfter is still pulled forward (%s) after reissue; the host "+
			"will renew on every poll", settled)
	}
}

// renewAfter asks the real agent state endpoint, over HTTP, the way an agent
// does. Going through the handler rather than calling enroll.Service directly
// is deliberate here: the whole bug this covers was a value that was correct in
// one layer and never reached the other.
func renewAfter(t *testing.T, ctx context.Context, c *agent.Client) time.Time {
	t.Helper()
	resp, err := c.State(ctx, 0, 0)
	if err != nil {
		t.Fatalf("agent state: %v", err)
	}
	return resp.RenewAfter
}

func (h *harness) reissue(t *testing.T, ctx context.Context, membershipID uuid.UUID) {
	t.Helper()
	err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		cur, err := tx.LatestCertificate(ctx, membershipID)
		if err != nil {
			return err
		}
		next := *cur
		next.ID = uuid.Nil
		next.Fingerprint = "reissued-" + uuid.NewString()
		next.IssuedAt = time.Time{}
		return tx.InsertCertificate(ctx, &next)
	})
	if err != nil {
		t.Fatalf("reissue: %v", err)
	}
}
