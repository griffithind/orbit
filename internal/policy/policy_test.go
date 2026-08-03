package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// doc is a small helper so the tests read as the JSON an operator would write.
func doc(entries string) []byte {
	return []byte(`{"version":1,"allow":[` + entries + `]}`)
}

func TestValidateAcceptsAWholeDocument(t *testing.T) {
	raw := doc(`
		{"src":["tag:web"],"dst":["tag:db"],"proto":"tcp","ports":["5432"],"note":"app to database"},
		{"src":["*"],"dst":["role:bastion"],"proto":"tcp","ports":["22"]},
		{"src":["cidr:10.42.0.0/24"],"dst":["host:metrics"],"proto":"udp","ports":["9000-9010"]},
		{"src":["*"],"dst":["*"],"proto":"icmp"}`)
	if err := Validate(raw); err != nil {
		t.Fatalf("a valid document was refused: %v", err)
	}
}

// The reason this package exists at all: nebula reads the keys it knows and
// ignores the rest, so a typo is a silent change of posture. The document is
// held to a stricter bar than nebula holds itself to, and the message has to
// name the key or it is not actionable.
func TestUnknownFieldIsRefusedAndNamed(t *testing.T) {
	cases := map[string][]byte{
		"top level": []byte(`{"version":1,"allows":[]}`),
		"entry":     doc(`{"src":["*"],"dst":["*"],"protocol":"tcp","ports":["22"]}`),
		"near miss": doc(`{"srcs":["*"],"dst":["*"],"proto":"tcp","ports":["22"]}`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			err := Validate(raw)
			if err == nil {
				t.Fatal("unknown field accepted")
			}
			if !errors.Is(err, ErrUnknownField) {
				t.Fatalf("want ErrUnknownField, got %v", err)
			}
			for _, want := range []string{"allows", "protocol", "srcs"} {
				if strings.Contains(string(raw), want) && !strings.Contains(err.Error(), want) {
					t.Errorf("error does not name the offending key %q: %v", want, err)
				}
			}
		})
	}
}

func TestEntryErrorsSayWhichEntry(t *testing.T) {
	raw := doc(`
		{"src":["*"],"dst":["*"],"proto":"tcp","ports":["22"]},
		{"src":["*"],"dst":["*"],"proto":"tcp","ports":["22"]},
		{"src":["*"],"dst":["*"],"proto":"nope","ports":["22"]}`)
	err := Validate(raw)
	if err == nil || !strings.Contains(err.Error(), "allow[2]") {
		t.Fatalf("error does not locate the entry: %v", err)
	}
}

func TestVersionIsRequired(t *testing.T) {
	if err := Validate([]byte(`{"allow":[]}`)); err == nil {
		t.Fatal("a document with no version was accepted")
	}
	if err := Validate([]byte(`{"version":2,"allow":[]}`)); err == nil {
		t.Fatal("an unknown version was accepted")
	}
}

// Every refusal here is permanent, and the test asserts the error says so
// rather than reading like a missing feature.
func TestRefusedSelectors(t *testing.T) {
	cases := []struct {
		sel      string
		mentions string
	}{
		{"user:alice", "device"},
		{"alice@example.com", "device"},
		{"localpart:alice", "device"},
		{"autogroup:internet", "autogroup"},
		{"autogroup:member", "autogroup"},
		{"via:exit-node", "path"},
		{"svc:database", "registry"},
		{"app:crm", "application"},
		{"posture:latestMac", "posture"},
		{"srcPosture:compliant", "posture"},
		{"group:engineering", "SIGNED"},
		{"ipset:corp", "cidr:"},
	}
	for _, c := range cases {
		t.Run(c.sel, func(t *testing.T) {
			raw := doc(`{"src":["` + c.sel + `"],"dst":["*"],"proto":"tcp","ports":["22"]}`)
			err := Validate(raw)
			if err == nil {
				t.Fatalf("%s was accepted; enforcing a device rule for it would be a lie "+
					"in the permissive direction", c.sel)
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("want ErrRefused, got %v", err)
			}
			if !strings.Contains(err.Error(), c.mentions) {
				t.Errorf("the refusal does not explain itself (want mention of %q): %v",
					c.mentions, err)
			}
		})
	}
}

func TestBareTokenIsNotASelector(t *testing.T) {
	err := Validate(doc(`{"src":["web"],"dst":["*"],"proto":"tcp","ports":["22"]}`))
	if err == nil {
		t.Fatal("a bare token was accepted as a selector")
	}
	// The message has to say what to write instead, or the strictness is just
	// an obstacle.
	if !strings.Contains(err.Error(), "host:web") || !strings.Contains(err.Error(), "tag:web") {
		t.Errorf("the error does not offer the alternatives: %v", err)
	}
}

func TestBareCIDRIsRedirectedNotGuessed(t *testing.T) {
	err := Validate(doc(`{"src":["10.42.0.0/24"],"dst":["*"],"proto":"tcp","ports":["22"]}`))
	if err == nil || !strings.Contains(err.Error(), "cidr:10.42.0.0/24") {
		t.Fatalf("want a redirect to the cidr: form, got %v", err)
	}
}

func TestCIDRWithHostBitsSet(t *testing.T) {
	err := Validate(doc(`{"src":["cidr:10.42.0.7/24"],"dst":["*"],"proto":"tcp","ports":["22"]}`))
	if err == nil || !strings.Contains(err.Error(), "10.42.0.0/24") {
		t.Fatalf("want the masked form suggested, got %v", err)
	}
}

func TestProtocols(t *testing.T) {
	ok := []string{"any", "tcp", "udp"}
	for _, p := range ok {
		if err := Validate(doc(`{"src":["*"],"dst":["*"],"proto":"` + p + `","ports":["22"]}`)); err != nil {
			t.Errorf("proto %s refused: %v", p, err)
		}
	}
	// Nebula matches four protocols. Anything else, including a protocol
	// number, has to be refused rather than passed through to a config nebula
	// will reject at boot on every host at once.
	for _, p := range []string{"sctp", "esp", "132", "gre", "ICMP"} {
		if err := Validate(doc(`{"src":["*"],"dst":["*"],"proto":"` + p + `","ports":["22"]}`)); err == nil {
			t.Errorf("proto %s accepted", p)
		}
	}
}

func TestICMPTakesNoPorts(t *testing.T) {
	if err := Validate(doc(`{"src":["*"],"dst":["*"],"proto":"icmp"}`)); err != nil {
		t.Fatalf("icmp without ports refused: %v", err)
	}
	// Nebula warns and throws the port away. A rule whose author believes it is
	// narrower than it is should not exist.
	err := Validate(doc(`{"src":["*"],"dst":["*"],"proto":"icmp","ports":["8"]}`))
	if err == nil || !strings.Contains(err.Error(), "ignores") {
		t.Fatalf("want a refusal explaining nebula ignores it, got %v", err)
	}
}

func TestPortsAreRequiredForPortedProtocols(t *testing.T) {
	for _, p := range []string{"tcp", "udp", "any"} {
		err := Validate(doc(`{"src":["*"],"dst":["*"],"proto":"` + p + `"}`))
		if err == nil {
			t.Errorf("proto %s with no ports accepted; nebula would match nothing", p)
		}
	}
}

// firewallPort.addRule materialises one map entry per port in a range. A range
// this wide is a cost the author almost certainly did not intend, and the error
// has to say what the cost is or it reads as arbitrary.
func TestWidePortRangeIsRefusedWithTheReason(t *testing.T) {
	err := Validate(doc(`{"src":["*"],"dst":["*"],"proto":"tcp","ports":["1024-40000"]}`))
	if err == nil {
		t.Fatal("a 39000-port range was accepted")
	}
	if !strings.Contains(err.Error(), "one firewall entry per port") {
		t.Errorf("the refusal does not name the cost: %v", err)
	}
	// And the boundary is usable rather than theoretical.
	if err := Validate(doc(`{"src":["*"],"dst":["*"],"proto":"tcp","ports":["9000-9100"]}`)); err != nil {
		t.Errorf("a 101-port range was refused: %v", err)
	}
}

// The full range is the one wide range that is not refused, because it has an
// exact one-entry equivalent. Compilation rewrites it; see TestFullPortRange.
func TestFullPortRangeValidates(t *testing.T) {
	for _, p := range []string{"1-65535", "0-65535"} {
		if err := Validate(doc(`{"src":["*"],"dst":["*"],"proto":"tcp","ports":["` + p + `"]}`)); err != nil {
			t.Errorf("the full range %s was refused: %v", p, err)
		}
	}
}

func TestPortsThatAreNotPorts(t *testing.T) {
	for _, p := range []string{"", "http", "70000", "-1", "80-", "443-80"} {
		if err := Validate(doc(`{"src":["*"],"dst":["*"],"proto":"tcp","ports":["` + p + `"]}`)); err == nil {
			t.Errorf("port %q accepted", p)
		}
	}
}

// "fragment" is a real nebula port keyword, and refusing it is a judgement:
// it says nothing about who may reach whom, so it does not belong in a
// reachability document. The message has to point somewhere.
func TestFragmentPortIsRedirected(t *testing.T) {
	err := Validate(doc(`{"src":["*"],"dst":["*"],"proto":"tcp","ports":["fragment"]}`))
	if err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("want a refusal pointing at role firewall rules, got %v", err)
	}
}

func TestSrcAndDstAreRequired(t *testing.T) {
	for _, raw := range []string{
		`{"dst":["*"],"proto":"tcp","ports":["22"]}`,
		`{"src":["*"],"proto":"tcp","ports":["22"]}`,
		`{"src":[],"dst":["*"],"proto":"tcp","ports":["22"]}`,
	} {
		if err := Validate(doc(raw)); err == nil {
			t.Errorf("entry with a missing side accepted: %s", raw)
		}
	}
}

// The document is stored, edited and shown back. A round trip that reorders or
// drops anything would mean an operator's document is not the one on file.
func TestDocumentRoundTrips(t *testing.T) {
	raw := doc(`
		{"src":["tag:web","host:edge"],"dst":["tag:db"],"proto":"tcp","ports":["5432","6432"],"note":"why"},
		{"src":["*"],"dst":["cidr:10.42.9.0/24"],"proto":"icmp"}`)

	first, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Parse(out)
	if err != nil {
		t.Fatalf("a document this package produced was refused by this package: %v\n%s", err, out)
	}
	again, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(again) {
		t.Errorf("round trip is not stable:\n%s\n%s", out, again)
	}
	if len(second.Allow) != 2 || second.Allow[0].Note != "why" {
		t.Errorf("round trip lost content: %+v", second)
	}
	// icmp carries no ports, and marshalling must not invent an empty list that
	// the next Parse would then refuse.
	if strings.Contains(string(out), `"ports":[]`) {
		t.Errorf("marshalling invented an empty ports list: %s", out)
	}
}

// An empty allow list is a real posture in authoritative mode, not an error,
// and nil must not be distinguishable from empty by any caller.
func TestEmptyDocument(t *testing.T) {
	d, err := Parse([]byte(`{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow == nil {
		t.Error("Allow is nil; callers should not have to check")
	}
	if len(d.Allow) != 0 {
		t.Errorf("want no entries, got %d", len(d.Allow))
	}
}
