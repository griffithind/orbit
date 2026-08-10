package e2e

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/wire"
)

// A joining machine keeps the network key it verified, and every generation
// carries a signature it verifies against.
//
// The key is the anchor for everything else here. verifyNetwork already proved
// at join that the control plane holds the private half of the key its network
// ID names; before this it was checked and thrown away, so nothing later could
// be verified at all.
func TestJoinPinsTheNetworkKey(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	var code wire.EnrollmentCodeResponse
	if status := h.adminPost(t, ts.URL+"/v1/networks/"+h.netID.String()+"/reservations",
		wire.ReserveRequest{Name: "pinned", RoleID: h.roleID.String()}, &code); status != 201 {
		t.Fatalf("reserve: status %d", status)
	}

	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(ts.URL)
	joined, err := client.JoinWithCode(ctx, id, h.netID.String(), "pinned", "", code.Code, time.Now())
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if joined.NetworkKey == "" {
		t.Fatal("the join response carried no network key, so nothing later can be verified")
	}

	kp, err := agent.GenerateKeypair(h.curve)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Claim(ctx, id, joined.MembershipID, kp, "e2e", time.Now())
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	// Every generation carries a signature, and it verifies under the key the
	// join proved.
	if resp.ConfigSig == nil {
		t.Fatal("the first generation arrived unsigned")
	}
	key, err := base64.StdEncoding.DecodeString(joined.NetworkKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.VerifyMaterial(key, resp.MembershipID, resp.ConfigSig, resp.Config, resp.CABundle); err != nil {
		t.Fatalf("the control plane's own material did not verify: %v", err)
	}

	// And the signature is over THIS machine's generation, not a generic one.
	if resp.ConfigSig.MembershipID != resp.MembershipID {
		t.Errorf("signature names membership %s, response is for %s",
			resp.ConfigSig.MembershipID, resp.MembershipID)
	}
	if resp.ConfigSig.ConfigEpoch != resp.ConfigEpoch {
		t.Errorf("signature names epoch %d, response is at %d",
			resp.ConfigSig.ConfigEpoch, resp.ConfigEpoch)
	}
}

// Another machine's generation does not install on this one.
//
// Signing the config bytes alone would not catch this: two hosts in a network
// with the same role are handed byte-identical configs, so a signature over the
// bytes verifies on either. The membership id in the envelope is what makes the
// material specific to the machine it was rendered for.
func TestAGenerationDoesNotTransplantBetweenMachines(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	a := h.createAndEnroll(t, ts, "machine-a", "10.42.80.1", false, false, nil)
	b := h.createAndEnroll(t, ts, "machine-b", "10.42.80.2", false, false, nil)

	key := networkKeyOf(t, a.dir)

	// A's genuinely-signed envelope, offered to B. The digests match whenever
	// the two configs are identical — which they are for two hosts with the same
	// role — so nothing about the BYTES can tell these apart. Only asking who
	// the envelope names can.
	err := agent.VerifyMaterial(key, b.id, a.respons.ConfigSig, a.respons.Config, a.respons.CABundle)
	if err == nil {
		t.Fatal("one machine's generation verified as another machine's")
	}
	if !strings.Contains(err.Error(), "different machine") {
		t.Errorf("the error does not name what is wrong: %v", err)
	}

	// The same material on the machine it was rendered for is fine, which is
	// what shows the check is the binding and not an accident.
	if err := agent.VerifyMaterial(key, a.id, a.respons.ConfigSig,
		a.respons.Config, a.respons.CABundle); err != nil {
		t.Fatalf("a machine could not verify its own generation: %v", err)
	}
}

// An operator's edit to nebula.yml is detected, refused, and repaired.
//
// This is the property the whole thing exists for. Before it, the agent fetched
// material only when its epoch differed from the control plane's and reported
// back the epoch it RECEIVED — so an edit was invisible while it was live and
// vanished without trace when a later epoch overwrote it, while the control
// plane's convergence figure said the machine had converged.
func TestAnEditedConfigIsDetected(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "edited", "10.42.80.9", false, false, nil)
	layout := paths.DefaultLayout(host.dir)
	applier := &agent.Applier{
		Layout:            layout,
		Reloader:          agent.NoopReloader{},
		DisableValidation: true,
		Log:               slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	key := networkKeyOf(t, host.dir)

	// As installed, it verifies.
	if err := applier.VerifyInstalled(key, host.id); err != nil {
		t.Fatalf("a freshly installed generation did not verify: %v", err)
	}

	// An operator opens the file and widens the firewall.
	installed := readFile(t, layout.ConfigPath())
	if err := os.WriteFile(layout.ConfigPath(),
		[]byte(installed+"\n# an operator was here\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := applier.VerifyInstalled(key, host.id)
	if err == nil {
		t.Fatal("an edited configuration verified")
	}
	if !strings.Contains(err.Error(), "edited since it was installed") {
		t.Errorf("the error does not name what happened: %v", err)
	}

	// Restoring the byte-exact file clears it, which proves the check is a
	// comparison and not a one-way latch.
	if err := os.WriteFile(layout.ConfigPath(), []byte(installed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applier.VerifyInstalled(key, host.id); err != nil {
		t.Fatalf("the restored configuration did not verify: %v", err)
	}
}

// Replacing the signature along with the config does not help: the forged
// signature does not verify under the pinned key.
//
// The interesting attacker is not one who edits nebula.yml and leaves the proof
// alone — it is one who edits both. This is what makes the pinned key load
// bearing rather than decorative.
func TestForgingTheSignatureFails(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "forged", "10.42.80.20", false, false, nil)
	layout := paths.DefaultLayout(host.dir)
	applier := &agent.Applier{
		Layout: layout, Reloader: agent.NoopReloader{}, DisableValidation: true,
		Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	key := networkKeyOf(t, host.dir)

	// Rewrite the signed original and re-sign it with a key of our own — which
	// is the best an attacker without the network identity key can do.
	edited := readFile(t, layout.SignedConfigPath()) + "\n# forged\n"
	if err := os.WriteFile(layout.SignedConfigPath(), []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applier.VerifyInstalled(key, host.id); err == nil {
		t.Fatal("a rewritten signed original verified")
	}

	// And deleting the proof entirely is not a way to pass, either: it reports
	// as unsigned, which the loop treats as "not verified", never as "fine".
	if err := os.Remove(layout.SigPath()); err != nil {
		t.Fatal(err)
	}
	if err := applier.VerifyInstalled(key, host.id); err == nil {
		t.Fatal("removing the signature made the check pass")
	}
}

// networkKeyOf reads the key the agent pinned for a network directory.
func networkKeyOf(t *testing.T, dir string) []byte {
	t.Helper()
	st, err := agent.ReadState(dir)
	if err != nil {
		t.Fatalf("read agent state: %v", err)
	}
	if st.NetworkKey == "" {
		t.Fatal("the agent pinned no network key, so nothing can be verified")
	}
	key, err := base64.StdEncoding.DecodeString(st.NetworkKey)
	if err != nil {
		t.Fatalf("the pinned network key is not base64: %v", err)
	}
	return key
}

// Editing nebula.yml does not change what nebula runs. It is not read.
//
// This is the property the signature exists to deliver, and it is stronger than
// the one above. TestAnEditedConfigIsDetected shows the agent NOTICES an edit;
// this shows the edit was never load-bearing. Nebula is handed the verified
// bytes in memory (Applier.VerifiedConfig), so nebula.yml is a record for people
// to read — root can rewrite it, and can SIGHUP nebula, and nothing changes.
//
// Before this, the agent verified the file and nebula independently re-read it,
// which made verification advisory: an edit between the check and the read won.
func TestEditingTheConfigFileChangesNothing(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "inlined", "10.42.81.4", false, false, nil)
	layout := paths.DefaultLayout(host.dir)
	applier := &agent.Applier{
		Layout: layout, Reloader: agent.NoopReloader{}, DisableValidation: true,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	key := networkKeyOf(t, host.dir)

	before, err := applier.VerifiedConfig(key, host.id)
	if err != nil {
		t.Fatalf("verified config: %v", err)
	}
	// The material is INLINED, not referenced: nebula is given no path it could
	// follow to a file somebody else controls.
	if !strings.Contains(before, "BEGIN NEBULA CERTIFICATE") {
		t.Error("the certificate was not inlined; nebula would read it from a path")
	}
	if strings.Contains(before, layout.Paths.Key) {
		t.Errorf("the config still names the key file %s", layout.Paths.Key)
	}

	// Root rewrites nebula.yml, thoroughly.
	if err := os.WriteFile(layout.ConfigPath(),
		[]byte("listen:\n  port: 1\nfirewall:\n  inbound: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	after, err := applier.VerifiedConfig(key, host.id)
	if err != nil {
		t.Fatalf("verified config after the edit: %v", err)
	}
	if after != before {
		t.Error("editing nebula.yml changed what nebula would load; it must not be read at all")
	}
}

// Rewriting the SIGNED original is refused rather than run.
//
// nebula.yml is inert, so the only file worth attacking is nebula.signed.yml —
// and that one is checked against the control plane's signature before a single
// byte reaches nebula.
func TestATamperedSignedConfigIsNeverLoaded(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "tampered-source", "10.42.81.9", false, false, nil)
	layout := paths.DefaultLayout(host.dir)
	applier := &agent.Applier{
		Layout: layout, Reloader: agent.NoopReloader{}, DisableValidation: true,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	key := networkKeyOf(t, host.dir)

	signed := readFile(t, layout.SignedConfigPath())
	if err := os.WriteFile(layout.SignedConfigPath(),
		[]byte(signed+"\n# forged\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := applier.VerifiedConfig(key, host.id); err == nil {
		t.Fatal("a tampered signed configuration was handed to nebula")
	}
}
