package main

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

const testNet = "0f7d4c1a-6a2e-4a1b-9c3f-2b6d5e8f1a20"

// The port is per network because nebula cannot share one. These are the forms
// an operator will actually type.
func TestMeshSpecParsesAPort(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantAddr string
		wantPort int
	}{
		{testNet + "=10.42.0.1", "10.42.0.1", 0},
		{testNet + "=10.42.0.1:4243", "10.42.0.1", 4243},
		{testNet + "=fd00::1", "fd00::1", 0},
		// An IPv6 address with a port needs brackets, and that is netip's rule
		// rather than one invented here.
		{testNet + "=[fd00::1]:4243", "fd00::1", 4243},

		// THE TRAP, and it resolves the only way it can. "fd00::1:4243" is a
		// perfectly valid IPv6 address — 4243 is four hex digits — so it reads
		// as an address with NO port, not as fd00::1 port 4243. Anyone who
		// meant the latter has to write the brackets, and no heuristic could do
		// better here without guessing.
		{testNet + "=fd00::1:4243", "fd00::1:4243", 0},
	} {
		t.Run(tc.in, func(t *testing.T) {
			var m meshSpecs
			if err := m.Set(tc.in); err != nil {
				t.Fatalf("Set(%q): %v", tc.in, err)
			}
			if got := m[0].Addr.String(); got != tc.wantAddr {
				t.Errorf("addr = %s, want %s", got, tc.wantAddr)
			}
			if m[0].ListenPort != tc.wantPort {
				t.Errorf("port = %d, want %d", m[0].ListenPort, tc.wantPort)
			}
		})
	}
}

func TestMeshSpecRejectsNonsense(t *testing.T) {
	for _, in := range []string{
		"not-a-uuid=10.42.0.1",
		testNet + "=not-an-address",
		testNet + "=10.42.0.1:0", // a lighthouse cannot be found on port 0
		testNet + "=[fd00::1]:0", // the same, bracketed
		testNet,                  // no address at all
		testNet + "=",            // an empty address
		testNet + "=10.42.0.1:99999",
	} {
		var m meshSpecs
		if err := m.Set(in); err == nil {
			t.Errorf("Set(%q) was accepted", in)
		}
	}
}

// Two networks on one port is refused BEFORE anything binds.
//
// Without this the first network comes up, the second fails inside nebula with
// "address already in use", and the operator is reading a library error rather
// than looking at the two flags that collided.
func TestTwoNetworksOnOnePortAreRefused(t *testing.T) {
	a, b := uuid.MustParse(testNet), uuid.New()

	var m meshSpecs
	if err := m.Set(a.String() + "=10.42.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(b.String() + "=10.43.0.1"); err != nil {
		t.Fatal(err)
	}

	err := checkMeshPorts(m, DefaultNebulaPort)
	if err == nil {
		t.Fatal("two networks defaulting to the same port were accepted")
	}
	// The message has to name both networks and the fix, or it is no better
	// than the bind error it replaces.
	for _, want := range []string{a.String(), b.String(), "-mesh", "4242"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q:\n%s", want, err)
		}
	}

	// Giving the second one its own port resolves it.
	var ok meshSpecs
	if err := ok.Set(a.String() + "=10.42.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := ok.Set(b.String() + "=10.43.0.1:4243"); err != nil {
		t.Fatal(err)
	}
	if err := checkMeshPorts(ok, DefaultNebulaPort); err != nil {
		t.Errorf("distinct ports were refused: %v", err)
	}
}

// An explicit port equal to the default still collides with an omitted one.
// The check must compare RESOLVED ports, not written ones.
func TestExplicitPortCollidesWithTheDefault(t *testing.T) {
	var m meshSpecs
	if err := m.Set(testNet + "=10.42.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(uuid.New().String() + "=10.43.0.1:4242"); err != nil {
		t.Fatal(err)
	}
	if err := checkMeshPorts(m, DefaultNebulaPort); err == nil {
		t.Fatal("an explicit 4242 alongside an omitted port was accepted")
	}
}

// The documented range must actually hold the number of networks the firewall
// guidance claims, or the two drift.
func TestPortRangeIsWideEnoughToBeWorthDocumenting(t *testing.T) {
	if n := DefaultNebulaPortMax - DefaultNebulaPort + 1; n != 16 {
		t.Errorf("the range holds %d networks; the firewall rules and docs say 16", n)
	}
}
