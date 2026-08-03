package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The engine must be given what nebula is meant to LOAD, which is not the same
// as the file the agent WRITES.
//
// Layout.ConfigPath is where the agent writes: nebula.yml in authoritative
// mode, config.d/50-orbit.yml in fragment mode. Layout.NebulaConfigArg is what
// nebula is pointed at: the same file in authoritative mode, but the DIRECTORY
// in fragment mode, because nebula loads a file verbatim and merges a
// directory.
//
// Handing the engine ConfigPath works perfectly in authoritative mode — which
// is the default, and every test — and on a fragment-mode host silently loads
// the Orbit fragment alone, dropping every operator-authored file the mode
// exists to include. A host would come up on a configuration nobody wrote.
func TestEngineIsPointedAtWhatNebulaLoads(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      ConfigMode
		wantIsDir bool
	}{
		{"authoritative", ConfigAuthoritative, false},
		{"fragment", ConfigFragment, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := DefaultLayout(t.TempDir())
			l.Mode = tc.mode

			arg := l.NebulaConfigArg()
			gotDir := arg == filepath.Join(l.Dir, ConfigDirName)
			if gotDir != tc.wantIsDir {
				t.Fatalf("NebulaConfigArg() = %q; want a directory: %v", arg, tc.wantIsDir)
			}
			if tc.mode == ConfigFragment && arg == l.ConfigPath() {
				t.Error("in fragment mode nebula must be given the directory, not the " +
					"fragment: loading the fragment alone drops every operator file")
			}
		})
	}
}

// TestAgentRunPointsTheEngineAtTheDirectory reads the call site, because the
// bug it guards is a field assignment and there is exactly one place it can be
// written wrong.
func TestAgentRunPointsTheEngineAtTheDirectory(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "orbit", "agent.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, "ConfigArg: layout.ConfigPath()") {
		t.Error("the engine is given Layout.ConfigPath. That is what the agent WRITES; " +
			"nebula must be given NebulaConfigArg, which is the config.d directory on a " +
			"fragment-mode host")
	}
	if !strings.Contains(text, "ConfigArg: layout.NebulaConfigArg()") {
		t.Error("cmd/orbit no longer points the engine at NebulaConfigArg; if the wiring " +
			"moved, update this test rather than deleting it")
	}
}
