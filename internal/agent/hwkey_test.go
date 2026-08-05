package agent

import (
	"strings"
	"testing"
)

func TestIsTokenRef(t *testing.T) {
	for _, ref := range []string{
		"pkcs11:token=orbit;object=host",
		"pkcs11:",
	} {
		if !IsTokenRef(ref) {
			t.Errorf("IsTokenRef(%q) = false, want true", ref)
		}
	}
	for _, ref := range []string{
		"",
		"/var/lib/orbit/prod/host.key",
		"PKCS11:token=orbit", // nebula's own check is case-sensitive; match it
		"file:///var/lib/orbit/host.key",
	} {
		if IsTokenRef(ref) {
			t.Errorf("IsTokenRef(%q) = true, want false", ref)
		}
	}
}

// TestLocalizePointsAtTheTokenWhenOneIsConfigured.
//
// The control plane renders a file path for pki.key and cannot do otherwise —
// it does not know whether this host even has a key file. A host holding its
// key on a token substitutes the URI at the same point the other two paths are
// rewritten. Getting this wrong points nebula at a file that will never exist,
// and the failure appears as a tunnel that does not come up.
func TestLocalizePointsAtTheTokenWhenOneIsConfigured(t *testing.T) {
	const uri = "pkcs11:token=orbit;object=host-key;pin-value=1234"

	a := testApplier(nil)
	a.Layout = DefaultLayout("/opt/orbit/prod")
	a.KeyRef = uri

	got := a.localize("pki:\n  ca: /rendered/ca.crt\n" +
		"  cert: /rendered/host.crt\n" +
		"  key: /rendered/host.key\n")

	want := "pki:\n  ca: /opt/orbit/prod/ca.crt\n" +
		"  cert: /opt/orbit/prod/host.crt\n" +
		"  key: " + uri + "\n"
	if got != want {
		t.Errorf("localize gave:\n%s\nwant:\n%s", got, want)
	}

	// The CA and certificate are still files, and must still be localized. A
	// token holds the private key and nothing else.
	if strings.Contains(got, "/rendered/") {
		t.Errorf("localize left a rendered path in place:\n%s", got)
	}
}

// TestLocalizeUnchangedWithoutAToken pins the default. Every host that does not
// opt in must produce byte-identical output to before KeyRef existed.
func TestLocalizeUnchangedWithoutAToken(t *testing.T) {
	a := testApplier(nil)
	a.Layout = DefaultLayout("/opt/orbit/prod")

	got := a.localize("pki:\n  ca: /rendered/ca.crt\n" +
		"  cert: /rendered/host.crt\n" +
		"  key: /rendered/host.key\n")

	want := "pki:\n  ca: /opt/orbit/prod/ca.crt\n" +
		"  cert: /opt/orbit/prod/host.crt\n" +
		"  key: /opt/orbit/prod/host.key\n"
	if got != want {
		t.Errorf("localize gave:\n%s\nwant:\n%s", got, want)
	}
}

func TestKeypairFromTokenRejectsANonTokenReference(t *testing.T) {
	if _, err := KeypairFromToken("/var/lib/orbit/host.key"); err == nil {
		t.Fatal("KeypairFromToken accepted a filesystem path")
	}
}

// TestKeyRefSurvivesStateRoundTrip.
//
// `orbit agent enroll` decides where a host's key lives; `orbit agent run`
// acts on it, in a different process, possibly weeks later. State is the only
// thing between them.
//
// It matters more than it looks. If KeyRef were lost, `run` would fall back to
// treating the host as file-backed: it would rewrite pki.key to a path that
// does not exist, and on the next renewal it would generate a fresh key on disk
// and ask the control plane to certify it — silently converting a
// hardware-backed identity into a software one, with no error anywhere.
func TestKeyRefSurvivesStateRoundTrip(t *testing.T) {
	const uri = "pkcs11:token=orbit;object=host-key"
	dir := t.TempDir()

	if err := WriteState(dir, State{MembershipID: "h1", BaseURL: "https://cp", KeyRef: uri}); err != nil {
		t.Fatalf("write state: %v", err)
	}
	got, err := ReadState(dir)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if got.KeyRef != uri {
		t.Fatalf("KeyRef = %q after round trip, want %q", got.KeyRef, uri)
	}

	// A file-backed host must still persist an empty KeyRef, not a stray value:
	// omitempty means the field is absent from the JSON entirely, and reading it
	// back has to yield "file", not the previous host's token.
	if err := WriteState(dir, State{MembershipID: "h2", BaseURL: "https://cp"}); err != nil {
		t.Fatalf("write state: %v", err)
	}
	got, err = ReadState(dir)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if got.KeyRef != "" {
		t.Fatalf("KeyRef = %q for a file-backed host, want empty", got.KeyRef)
	}
}

func TestKeyBacking(t *testing.T) {
	if got := keyBacking("pkcs11:token=orbit"); got != "token" {
		t.Errorf("keyBacking(token URI) = %q, want %q", got, "token")
	}
	if got := keyBacking("/var/lib/orbit/host.key"); got != "file" {
		t.Errorf("keyBacking(path) = %q, want %q", got, "file")
	}
	if got := keyBacking(""); got != "file" {
		t.Errorf("keyBacking(empty) = %q, want %q", got, "file")
	}
}
