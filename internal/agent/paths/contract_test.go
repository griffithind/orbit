package paths_test

import (
	"testing"

	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/nebulacfg"
)

// TestTheAgentWritesWhereTheRendererPoints.
//
// The control plane renders pki.ca, pki.cert and pki.key into a config it signs,
// from nebulacfg.PathsFor. The agent writes those files from paths.DefaultLayout.
// Nothing connects the two at the call site — one is on the server, one is on the
// host, and the config travels between them — so if they disagree nebula starts
// with a config naming files that are not there.
//
// It is a fleet-wide failure from a one-word change, and it reports itself as
// every host being down at once with nothing pointing at the cause. They were
// two independent sets of string literals until they were made one; this is what
// says they must stay one.
func TestTheAgentWritesWhereTheRendererPoints(t *testing.T) {
	for _, slug := range []string{"prod", "staging", "a"} {
		rendered := nebulacfg.PathsFor(slug)
		written := paths.DefaultLayout(paths.DirFor(slug)).Paths

		if written != rendered {
			t.Errorf("slug %q: the agent writes %+v but the signed config points at %+v",
				slug, written, rendered)
		}
	}

	// And the values themselves, so a change to BOTH sides at once still has to
	// be deliberate: these strings are also in deploy/ and in the docs.
	got := nebulacfg.PathsFor("prod")
	for _, w := range []struct{ got, want string }{
		{got.CA, "/var/lib/orbit/prod/ca.crt"},
		{got.Cert, "/var/lib/orbit/prod/host.crt"},
		{got.Key, "/var/lib/orbit/prod/host.key"},
		{paths.DefaultLayout(paths.DirFor("prod")).ConfigPath(), "/var/lib/orbit/prod/nebula.yml"},
	} {
		if w.got != w.want {
			t.Errorf("got %q, want %q", w.got, w.want)
		}
	}
}
