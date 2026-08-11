package nebulacfg_test

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/griffithind/orbit/internal/nebulacfg"
)

func authoritativeInput() nebulacfg.Input {
	return nebulacfg.Input{
		Paths:      nebulacfg.PathsFor("prod"),
		ListenPort: 4242,
		TunDev:     "prod",
	}
}

func decodeDoc(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("rendered config is not valid YAML: %v\n%s", err, raw)
	}
	return out
}

// TestAuthoritativeRendersEverythingNebulaNeeds.
//
// In authoritative mode there is no second file, so a key Orbit does not emit is
// a key that falls back to nebula's built-in default with nothing on the host to
// say so. This asserts the sections an operator would previously have written
// into 00-base.yml are all present.
func TestAuthoritativeRendersEverythingNebulaNeeds(t *testing.T) {
	raw, err := nebulacfg.Render(authoritativeInput())
	if err != nil {
		t.Fatal(err)
	}
	doc := decodeDoc(t, raw)

	for _, section := range []string{
		"pki", "static_host_map", "lighthouse", "listen", "punchy", "relay", "tun",
		"firewall", "logging",
	} {
		if _, ok := doc[section]; !ok {
			t.Errorf("authoritative config omits %q; there is no other file to supply it", section)
		}
	}

	pki := doc["pki"].(map[string]any)
	if pki["ca"] != "/var/lib/orbit/prod/ca.crt" {
		t.Errorf("pki.ca = %v, want the per-network directory", pki["ca"])
	}
	// The key stays a separate file rather than inline PEM: every routine
	// firewall push rewrites this document, and a document containing the
	// private key would make the most frequent write on the box the most
	// dangerous one.
	if key, _ := pki["key"].(string); strings.Contains(key, "BEGIN") {
		t.Error("the private key was inlined into the config document")
	}
	if pki["disconnect_invalid"] != true {
		t.Error("disconnect_invalid is not set; certificate expiry would not tear down a live tunnel")
	}

	tun := doc["tun"].(map[string]any)
	if tun["dev"] != "prod" {
		t.Errorf("tun.dev = %v, want the allocated device", tun["dev"])
	}
	if tun["mtu"] == nil {
		t.Error("tun.mtu is absent in authoritative mode")
	}
	if doc["logging"].(map[string]any)["level"] == nil {
		t.Error("logging.level is absent in authoritative mode")
	}
	if doc["lighthouse"].(map[string]any)["interval"] == nil {
		t.Error("lighthouse.interval is absent in authoritative mode")
	}

	if !strings.Contains(string(raw), "COMPLETE nebula configuration") {
		t.Error("the header does not say the file is complete, which is the one thing a " +
			"reader needs to know about it")
	}
}

// TestOverridesMergeAndStayDeterministic.
//
// The agent decides whether anything changed by hashing the rendered bytes, so
// two renders of one input must be byte-identical — and an override arrives as a
// Go map, which has no order at all.
func TestOverridesMergeAndStayDeterministic(t *testing.T) {
	in := authoritativeInput()
	in.Overrides = map[string]any{
		"tun":     map[string]any{"mtu": 1200},
		"logging": map[string]any{"level": "debug"},
		"handshakes": map[string]any{
			"try_interval":   "100ms",
			"retries":        20,
			"trigger_buffer": 64,
		},
		"listen": map[string]any{"read_buffer": 10485760},
	}

	first, err := nebulacfg.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := nebulacfg.Render(in)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("two renders of one input differ, so every poll looks like a change:\n%s\n---\n%s",
				first, again)
		}
	}

	doc := decodeDoc(t, first)
	tun := doc["tun"].(map[string]any)
	if tun["mtu"] != 1200 {
		t.Errorf("tun.mtu = %v, want the override", tun["mtu"])
	}
	// A deep merge, not a replacement: overriding tun.mtu must not discard
	// tun.dev, which Orbit allocated.
	if tun["dev"] != "prod" {
		t.Errorf("overriding tun.mtu discarded tun.dev: %v", tun)
	}
	if doc["logging"].(map[string]any)["level"] != "debug" {
		t.Error("logging.level override was ignored")
	}
	if doc["handshakes"] == nil {
		t.Error("an override for a section Orbit does not model was dropped")
	}
	if doc["listen"].(map[string]any)["port"] != 4242 {
		t.Error("overriding listen.read_buffer discarded the allocated listen.port")
	}
}

// TestOverridesCannotReachOrbitOwnedKeys.
//
// This is the property authoritative mode exists for. If an override could
// rewrite firewall.inbound, the rendered file would still LOOK authoritative
// while carrying rules the control plane knows nothing about — worse than
// fragment mode, where at least the divergence is expected.
func TestOverridesCannotReachOrbitOwnedKeys(t *testing.T) {
	cases := map[string]map[string]any{
		"firewall wholesale": {"firewall": map[string]any{"inbound": []any{}}},
		"a firewall rule":    {"firewall": map[string]any{"inbound": []any{map[string]any{"port": "any"}}}},
		"pki paths":          {"pki": map[string]any{"ca": "/tmp/mine.crt"}},
		"the blocklist":      {"pki": map[string]any{"blocklist": []any{}}},
		"the topology":       {"static_host_map": map[string]any{"10.0.0.1": []any{"1.2.3.4:4242"}}},
		"lighthouse role":    {"lighthouse": map[string]any{"am_lighthouse": true}},
		"relay role":         {"relay": map[string]any{"am_relay": true}},
		"the listen port":    {"listen": map[string]any{"port": 5555}},
		"the tun device":     {"tun": map[string]any{"dev": "utun9"}},
	}

	for name, ov := range cases {
		if err := nebulacfg.ValidateOverrides(ov); err == nil {
			t.Errorf("%s: override accepted, so Orbit's view of this host is no longer the truth", name)
		}

		in := authoritativeInput()
		in.Overrides = ov
		if _, err := nebulacfg.Render(in); err == nil {
			t.Errorf("%s: rendered anyway; validating only at the API would let a value "+
				"that predates the rule through", name)
		}
	}

	// And the escape hatch still works for everything else.
	if err := nebulacfg.ValidateOverrides(map[string]any{
		"tun":        map[string]any{"mtu": 1200},
		"logging":    map[string]any{"level": "debug"},
		"punchy":     map[string]any{"delay": "2s"},
		"lighthouse": map[string]any{"interval": 30},
	}); err != nil {
		t.Errorf("a legitimate override was refused, which pushes operators back to fragment mode: %v", err)
	}
}

// TestTunDevSuggestionAvoidsTheSilentLinuxCollision.
//
// Linux copies tun.dev into a [16]byte with a bare copy() and no error, so two
// names sharing fifteen characters become ONE device — a failure that reports
// itself as two unreachable hosts and names nothing.
func TestTunDevSuggestionAvoidsTheSilentLinuxCollision(t *testing.T) {
	short := nebulacfg.TunDevSuggestion("prod")
	if short != "prod" {
		t.Errorf("a short slug was altered: %q", short)
	}

	a := nebulacfg.TunDevSuggestion("production-cluster-eu")
	b := nebulacfg.TunDevSuggestion("production-cluster-us")
	if len(a) > nebulacfg.TunDevMaxLen || len(b) > nebulacfg.TunDevMaxLen {
		t.Errorf("suggestions exceed %d characters and would be truncated in silence: %q %q",
			nebulacfg.TunDevMaxLen, a, b)
	}
	if a == b {
		t.Errorf("two slugs derived the same device name (%q); on Linux they would be one interface", a)
	}
	if a != nebulacfg.TunDevSuggestion("production-cluster-eu") {
		t.Error("the suggestion is not deterministic, so every render would look like a change")
	}
}
