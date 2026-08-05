package e2e

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/service"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/wire"
)

// TestAuthoritativeConfigBootsNebula is the proof the whole authoritative mode
// rests on.
//
// Fragment mode could get away with an incomplete file: nebula merged whatever
// else was in the directory, so a key Orbit forgot was a key an operator had
// probably supplied. Authoritative mode has no second file. If the rendered
// document is missing something nebula needs, the host does not start — and it
// does not start on the first enrollment of a new network, which is the worst
// possible moment to find out.
//
// So this takes the config the control plane actually renders, lets the real
// applier write it, and boots real nebula from the FILE. Nothing here is a
// simulation: config.C.resolve stats the path and loads exactly that one file
// when it is not a directory, which is the property that makes Orbit
// authoritative in the first place.
func TestAuthoritativeConfigBootsNebula(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	ctx := context.Background()

	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(),
		Name:      "authoritative-" + uuid.NewString()[:8],
		RoleID:    h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}

	var codeResp wire.EnrollmentCodeResponse
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+host.ID+"/enrollment-code", nil, &codeResp); code != http.StatusCreated {
		t.Fatalf("enrollment code: %d", code)
	}

	kp, err := agent.GenerateKeypair(h.curve)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := agent.NewClient(ts.URL).Enroll(ctx, codeResp.Code, kp, "e2e")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// The control plane has to say which layout it rendered and where it
	// belongs. An agent that had to guess would create one layout on its first
	// write and discover the other on its first poll, leaving both on disk.
	if resp.ConfigMode == "" {
		t.Error("the enrollment response does not say which config mode this is")
	}
	if resp.NetworkSlug == "" {
		t.Error("the enrollment response does not carry the network slug, so the agent " +
			"has to derive its directory from something that can change")
	}
	if !strings.Contains(resp.Config, "COMPLETE nebula configuration") {
		t.Errorf("the rendered config does not identify itself as complete:\n%s", resp.Config)
	}
	// Every section nebula needs must be in this one file.
	for _, key := range []string{
		"pki:", "static_host_map:", "lighthouse:", "listen:", "punchy:",
		"relay:", "tun:", "firewall:", "logging:",
	} {
		if !strings.Contains(resp.Config, key) {
			t.Errorf("authoritative config omits %q and there is no other file to supply it", key)
		}
	}
	// And the private key is a separate file, not inline PEM. Nebula accepts
	// inline, but inlining would mean every routine firewall push rewrites a
	// document containing the host's private key.
	if strings.Contains(resp.Config, "PRIVATE KEY") {
		t.Error("the private key was inlined into the rendered configuration")
	}

	dir := t.TempDir()
	layout := agent.DefaultLayout(dir)
	applier := &agent.Applier{
		Layout:   layout,
		Reloader: agent.NoopReloader{},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := applier.Apply(ctx, agent.MaterialFromEnroll(resp, kp.PrivatePEM)); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// One file, and nebula is pointed at the file rather than a directory.
	written, err := os.ReadFile(layout.ConfigPath())
	if err != nil {
		t.Fatalf("the agent did not write the config where the control plane expects it: %v", err)
	}
	if len(written) == 0 {
		t.Fatal("the written configuration is empty")
	}

	c := config.NewC(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := c.Load(layout.NebulaConfigArg()); err != nil {
		t.Fatalf("nebula could not load the authoritative config: %v\n%s", err, written)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	ctrl, err := nebula.Main(c, false, "orbit-e2e", logger, overlay.NewUserDeviceFromConfig)
	if err != nil {
		t.Fatalf("nebula refused the authoritative config: %v\n%s", err, written)
	}
	svc, err := service.New(ctrl)
	if err != nil {
		t.Fatalf("nebula started but the service did not: %v", err)
	}
	stopNebulaOnCleanup(t, svc)
}
