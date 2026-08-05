package e2e

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// TestAuditNamesTheActor is the point of carrying a display name.
//
// actor_id is a token uuid. Resolving it means a join against orbit.api_token,
// and the token can be revoked or the deployment rebuilt — so the answer to
// "who did this" degrades over exactly the period an audit cares about.
func TestAuditNamesTheActor(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	name := "deploy-bot-" + uuid.NewString()[:8]
	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: name, Scopes: []string{"memberships:create", "memberships:read", "audit:read"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	// Reserving is the token-authored action that replaced creating a host: an
	// operator decides a machine's place, and a machine takes it later. The
	// entry has to name the operator, not the machine.
	if code := h.reqAs(t, tok.Token, http.MethodPost,
		ts.URL+"/v1/networks/"+h.netID.String()+"/reservations",
		wire.ReserveRequest{Name: "named-actor", OverlayAddr: "10.42.7.1",
			RoleID: h.roleID.String()}, nil); code != http.StatusCreated {
		t.Fatalf("reserve: %d", code)
	}

	entries := h.auditFor(t, ts.URL, store.ActionEnrollCodeCreated, h.netID.String())
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	got := entries[0]

	if got.ActorType != store.ActorToken {
		t.Errorf("actor_type = %q, want %q", got.ActorType, store.ActorToken)
	}
	if got.ActorID != tok.ID {
		t.Errorf("actor_id = %q, want the token uuid %q", got.ActorID, tok.ID)
	}
	if got.ActorDisplay != name {
		t.Errorf("actor_display = %q, want %q", got.ActorDisplay, name)
	}
}

// TestAuditSurvivesTheActorBeingRevoked. Revoking a token must not make past
// entries unreadable — the display name is captured at write time, not joined.
func TestAuditSurvivesTheActorBeingRevoked(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	name := "departed-" + uuid.NewString()[:8]
	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: name, Scopes: []string{"memberships:create"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	if code := h.reqAs(t, tok.Token, http.MethodPost,
		ts.URL+"/v1/networks/"+h.netID.String()+"/reservations",
		wire.ReserveRequest{Name: "orphaned-entry", OverlayAddr: "10.42.7.2",
			RoleID: h.roleID.String()}, nil); code != http.StatusCreated {
		t.Fatalf("reserve: %d", code)
	}

	if code := h.adminReq(t, http.MethodDelete, ts.URL+"/v1/tokens/"+tok.ID, nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}

	entries := h.auditFor(t, ts.URL, store.ActionEnrollCodeCreated, h.netID.String())
	if len(entries) != 1 || entries[0].ActorDisplay != name {
		t.Errorf("after revoking the actor, audit_display = %q, want %q",
			entries[0].ActorDisplay, name)
	}
}

// TestEnrollmentCodeIsAttributedToATokenNotAUser.
//
// This previously recorded actor_type "user" while every caller handed it a
// token uuid — a mislabel that would have an auditor looking for a person who
// does not exist.
func TestEnrollmentCodeIsAttributedToATokenNotAUser(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	name := "enroller-" + uuid.NewString()[:8]
	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: name, Scopes: []string{"memberships:create", "memberships:enroll"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "coded", OverlayAddr: "10.42.7.3",
		RoleID: h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}
	if code := h.reqAs(t, tok.Token, http.MethodPost,
		ts.URL+"/v1/memberships/"+host.ID+"/enrollment-code", nil, nil); code != http.StatusCreated {
		t.Fatalf("create code: %d", code)
	}

	entries := h.auditFor(t, ts.URL, store.ActionEnrollCodeCreated, host.ID)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].ActorType != store.ActorToken {
		t.Errorf("actor_type = %q, want %q — a token is not a user",
			entries[0].ActorType, store.ActorToken)
	}
	if entries[0].ActorDisplay != name {
		t.Errorf("actor_display = %q, want %q", entries[0].ActorDisplay, name)
	}
}

// TestAgentActionsNameTheHost. Memberships are hard-deleted by DELETE /v1/memberships, so
// an agent entry that carried only a uuid would become unreadable the moment
// the host it describes is decommissioned.
func TestAgentActionsNameTheHost(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "self-named", "10.42.7.4", false, false, nil)

	entries := h.auditFor(t, ts.URL, store.ActionEnrolled, host.id)
	if len(entries) != 1 {
		t.Fatalf("got %d enrollment entries, want 1", len(entries))
	}
	if entries[0].ActorType != store.ActorAgent {
		t.Errorf("actor_type = %q, want %q", entries[0].ActorType, store.ActorAgent)
	}
	if entries[0].ActorDisplay != "self-named" {
		t.Errorf("actor_display = %q, want the host name", entries[0].ActorDisplay)
	}

	// And it outlives the host.
	if code := h.adminReq(t, http.MethodDelete, ts.URL+"/v1/memberships/"+host.id, nil, nil); code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	after := h.auditFor(t, ts.URL, store.ActionEnrolled, host.id)
	if len(after) != 1 || after[0].ActorDisplay != "self-named" {
		t.Error("agent attribution did not survive the host being deleted")
	}
}

func (h *harness) auditFor(t *testing.T, baseURL, action, targetID string) []wire.AuditRecordResponse {
	t.Helper()
	var out []wire.AuditRecordResponse
	if code := h.adminReq(t, http.MethodGet,
		baseURL+"/v1/audit-logs?action="+action+"&target_id="+targetID, nil, &out); code != http.StatusOK {
		t.Fatalf("read audit: %d", code)
	}
	return out
}

// TestAMembershipIsAttributedToTheDeviceThatTookIt.
//
// The other half of what reservations changed. Creating a host used to be one
// action by one actor; it is now two, at two times, by two actors — an operator
// reserves a place (ActionEnrollCodeCreated, attributed to their token) and a
// machine takes it (ActionMembershipCreated, attributed to its device fingerprint).
//
// Attributing the second to the operator would be the easy mistake and would
// lose the fact an auditor actually needs: WHICH MACHINE took the place, and
// when. A reservation minted on Monday and redeemed on Friday by a laptop
// nobody expected is exactly the sequence this has to be able to show.
func TestAMembershipIsAttributedToTheDeviceThatTookIt(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "taken-by-a-machine", OverlayAddr: "10.42.7.9",
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	entries := h.auditFor(t, ts.URL, store.ActionMembershipCreated, host.ID)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	got := entries[0]
	if got.ActorType != store.ActorAgent {
		t.Errorf("actor_type = %q, want %q: the machine took the place, not the operator",
			got.ActorType, store.ActorAgent)
	}
	if want := h.membershipDevices[host.ID].Fingerprint(); got.ActorID != want {
		t.Errorf("actor_id = %q, want the device fingerprint %q", got.ActorID, want)
	}
}
