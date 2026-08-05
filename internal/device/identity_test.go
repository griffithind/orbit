package device_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/store"
)

func TestSignAndVerify(t *testing.T) {
	id, err := device.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	msg := []byte("the statement")
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := device.Verify(id.PublicKey(), msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := device.Verify(id.PublicKey(), []byte("a different statement"), sig); err == nil {
		t.Error("a signature verified against a message it was not made over")
	}

	other, err := device.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := device.Verify(other.PublicKey(), msg, sig); err == nil {
		t.Error("a signature verified against a key that did not make it")
	}
}

// TestFingerprintAgreesWithStore.
//
// The agent prints one of these and the database indexes the other. If they
// ever compute differently, a device that joined would be unrecognisable on its
// next contact, and the symptom would be a fleet of duplicate device rows.
func TestFingerprintAgreesWithStore(t *testing.T) {
	id, err := device.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if got, want := store.DeviceFingerprint(id.PublicKey()), id.Fingerprint(); got != want {
		t.Errorf("store says %s, device says %s", got, want)
	}
}

// TestParsePublicKeyRejectsWeakerCurves.
//
// A P-224 key parses cleanly through x509 and would otherwise be recorded as a
// device identity at a strength nothing else in this system assumes.
func TestParsePublicKeyRejectsWeakerCurves(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p224: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = device.ParsePublicKey(spki)
	if err == nil {
		t.Fatal("a P-224 key was accepted as a device identity")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("error does not say what was wanted: %v", err)
	}
}

func TestParsePublicKeyRejectsNonECDSA(t *testing.T) {
	if _, err := device.ParsePublicKey([]byte("not a key")); err == nil {
		t.Error("garbage was accepted as a device public key")
	}
	if _, err := device.ParsePublicKey(nil); err == nil {
		t.Error("an empty key was accepted as a device public key")
	}
}

func TestLoadOrCreateIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "device.key")

	first, err := device.LoadOrCreate(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	second, err := device.LoadOrCreate(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("the device key changed across a restart: %s then %s",
			first.Fingerprint(), second.Fingerprint())
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("device key mode is %v, want 0600", fi.Mode().Perm())
	}
}

// TestLoadOrCreateUnderRace.
//
// A systemd unit and an operator running the same command by hand start at the
// same moment during installation. Two things can go wrong and this asserts
// both: two different keys ending up believed-in by two processes, and a reader
// picking up a file that exists but has not been written yet.
func TestLoadOrCreateUnderRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.key")

	// A start barrier, not just goroutines. Without one they stagger and the
	// window this is aimed at — a reader opening the file between another
	// process creating it and writing to it — almost never opens. That window
	// is exactly what the first version of LoadOrCreate got wrong.
	const n = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	got := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			id, err := device.LoadOrCreate(path)
			if err != nil {
				errs[i] = err
				return
			}
			got[i] = id.Fingerprint()
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if got[i] != got[0] {
			t.Fatalf("concurrent starts produced different device keys: %s and %s",
				got[0], got[i])
		}
	}
}

func TestLoadDistinguishesMissingFromBroken(t *testing.T) {
	dir := t.TempDir()

	_, err := device.Load(filepath.Join(dir, "absent.key"))
	if !errors.Is(err, device.ErrNoKey) {
		t.Errorf("a missing key gave %v, want ErrNoKey", err)
	}

	// Unreadable must NOT look like missing: the first calls for generating a
	// key, the second for stopping and telling somebody.
	broken := filepath.Join(dir, "broken.key")
	if err := os.WriteFile(broken, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = device.Load(broken)
	if err == nil || errors.Is(err, device.ErrNoKey) {
		t.Errorf("a corrupt key gave %v, want a real error", err)
	}
}

func TestLoadRejectsAKeyOnTheWrongCurve(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "device.key")
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := device.Load(path); err == nil {
		t.Error("a P-384 device key was accepted")
	}
}

func TestVerifyJoin(t *testing.T) {
	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	sig, err := id.SignJoin("orb_7f3k9m2q4x8w1", "laptop", now)
	if err != nil {
		t.Fatalf("sign join: %v", err)
	}
	if err := device.VerifyJoin(id.PublicKey(), "orb_7f3k9m2q4x8w1", "laptop", now, now, sig); err != nil {
		t.Fatalf("verify join: %v", err)
	}

	// Each field must actually be bound. A signature that verifies for a
	// different network or a different name is a signature that can be
	// redirected.
	if err := device.VerifyJoin(id.PublicKey(), "orb_other", "laptop", now, now, sig); err == nil {
		t.Error("a join signature verified against a different network")
	}
	if err := device.VerifyJoin(id.PublicKey(), "orb_7f3k9m2q4x8w1", "desktop", now, now, sig); err == nil {
		t.Error("a join signature verified against a different name")
	}
}

func TestVerifyJoinRejectsStaleAndFutureTimestamps(t *testing.T) {
	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// Both directions: a host with a fast clock is a real machine, not an
	// attack, and the error should not depend on which way the drift went.
	for _, skew := range []time.Duration{
		device.JoinFreshness + time.Minute,
		-(device.JoinFreshness + time.Minute),
	} {
		at := now.Add(skew)
		sig, err := id.SignJoin("orb_x", "laptop", at)
		if err != nil {
			t.Fatal(err)
		}
		err = device.VerifyJoin(id.PublicKey(), "orb_x", "laptop", at, now, sig)
		if !errors.Is(err, device.ErrStaleJoin) {
			t.Errorf("skew %s gave %v, want ErrStaleJoin", skew, err)
		}
	}
}

// TestJoinStatementIsUnambiguous.
//
// Newline-separated encoding is only safe while no field can contain a newline.
// If one ever can, two different field sets collide onto the same bytes and one
// signature covers both meanings.
func TestJoinStatementIsUnambiguous(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	a := device.JoinStatement("net", "a\nb", "fp", at)
	b := device.JoinStatement("net", "a", "b\nfp", at)
	if string(a) == string(b) {
		t.Fatal("two different join statements encode identically; the encoding is ambiguous")
	}
}
