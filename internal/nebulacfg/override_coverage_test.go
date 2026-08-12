package nebulacfg

import (
	"net/netip"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The deny-list is derived from what the renderer emits, or it drifts from it.
//
// protectedOverrides has now been outgrown twice by the render: `orbit` — the
// one section of the file that is definitionally Orbit's rather than nebula's —
// was reachable by an override for as long as it existed, and so were
// lighthouse.dns and listen.host. Each time, the list was correct for the keys
// that existed when it was written.
//
// So the invariant is stated against the renderer's actual output rather than
// against a second hand-maintained list: every top-level key Orbit renders is
// either protected, or named below with a reason why an operator may overwrite
// it. Adding a section to the render fails this test until somebody decides
// which it is. See docs/adr/0033-overrides-cannot-reach-what-orbit-owns.md.
func TestEveryRenderedSectionIsDecided(t *testing.T) {
	// Keys Orbit renders and deliberately leaves writable. Each needs a reason
	// that survives being read aloud.
	open := map[string]string{
		"logging": "log level and format are an operator's business and cannot " +
			"change what the mesh does; this is the shape of thing the escape " +
			"hatch exists for",

		// Deliberate, and it is the one place ADR-0033's "everything Orbit
		// renders is Orbit's" is knowingly not applied. Orbit renders punch and
		// respond — the booleans that turn hole punching ON — and ADR-0032 adds
		// considered defaults for the timings. But the timings are exactly what
		// a pathological NAT needs tuned, which is what the escape hatch is for,
		// and TestOverridesCannotReachOrbitOwnedKeys has asserted since before
		// either ADR that `punchy: {delay: 2s}` must keep working.
		"punchy": "the timings are the escape hatch's own use case: Orbit chooses " +
			"defaults, an operator with a difficult NAT overrides them",
	}

	out, err := Render(Input{
		Paths:      PathsFor("net"),
		Firewall:   DefaultFirewall(),
		ListenPort: 4242,
		Lighthouses: []Lighthouse{{
			VpnAddr:     netip.MustParseAddr("10.42.0.1"),
			StaticAddrs: []string{"198.51.100.1:4242"},
		}},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("the renderer produced something that is not a YAML mapping: %v", err)
	}
	if len(doc) < 5 {
		t.Fatalf("rendered only %d top-level keys; this test is not seeing the render", len(doc))
	}

	for key := range doc {
		if _, protected := protectedOverrides[key]; protected {
			continue
		}
		if _, allowed := open[key]; allowed {
			continue
		}
		// A dotted entry protects a subtree, so a top-level key is covered when
		// anything under it is protected.
		covered := false
		for p := range protectedOverrides {
			if len(p) > len(key) && p[:len(key)+1] == key+"." {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		t.Errorf("the renderer emits %q and nothing decides whether an override may reach it.\n"+
			"Add it to protectedOverrides with a reason, or to this test's `open` map with one.",
			key)
	}
}

// TestOrbitsOwnSectionIsProtected states the sharpest case on its own, because
// it is the one whose absence was least visible: an override here is signed by
// the control plane as if the control plane had rendered it.
func TestOrbitsOwnSectionIsProtected(t *testing.T) {
	for _, key := range []string{"orbit", "lighthouse.serve_dns", "lighthouse.dns", "listen.host"} {
		if _, ok := protectedOverrides[key]; !ok {
			t.Errorf("%q is not protected; see docs/adr/0033-overrides-cannot-reach-what-orbit-owns.md", key)
		}
	}
}
