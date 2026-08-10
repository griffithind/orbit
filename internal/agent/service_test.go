package agent

import (
	"strings"
	"testing"

	"github.com/griffithind/orbit/internal/agent/paths"
)

// ONE service, every network.
//
// The agent runs a nebula per joined network inside a single process, so the
// service definition must contain nothing network-specific. This is the second
// shape of this file: the first used a systemd TEMPLATE with one instance per
// network, and that was wrong in a way that looked right — a template is one
// shared file, so baking a directory into it meant installing a second network
// silently repointed the first network's instance at the second's directory.
// Two units, both active, both serving one network.
//
// The invariant that closes it is simply that the definition does not vary.

func execStartOf(t *testing.T, unit string) string {
	t.Helper()
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			return strings.TrimPrefix(line, "ExecStart=")
		}
	}
	t.Fatal("the unit has no ExecStart")
	return ""
}

func TestSystemdExecStartReconstructsTheCommand(t *testing.T) {
	p := systemdPlan("/usr/local/bin/orbit", []string{"agent", "run"}, paths.DefaultRoot)

	want := "/usr/local/bin/orbit agent run"
	if got := execStartOf(t, p.Contents); got != want {
		t.Errorf("ExecStart = %q\n           want %q", got, want)
	}
}

// TestSystemdExecStartSurvivesAnExtraArgument. The command was once built by
// slicing the argument list at a fixed index, which is correct until the shape
// changes and then silently drops or duplicates a flag.
func TestSystemdExecStartSurvivesAnExtraArgument(t *testing.T) {
	p := systemdPlan("/usr/local/bin/orbit",
		[]string{"agent", "run", "-verify-url", "http://10.42.0.1:8443/agent/v1/state"}, paths.DefaultRoot)

	exec := execStartOf(t, p.Contents)
	want := "/usr/local/bin/orbit agent run -verify-url http://10.42.0.1:8443/agent/v1/state"
	if exec != want {
		t.Errorf("ExecStart = %q\n           want %q", exec, want)
	}
	// Scoped to the ExecStart LINE, not the file: the unit's own prose says
	// "the agent runs a nebula inside itself", and counting across the whole
	// file matched that sentence rather than the command.
	if strings.Count(exec, "agent run") != 1 {
		t.Error("the subcommand appears more than once; the binary and the arguments overlap")
	}
}

// TestTheServiceDefinitionNamesNoNetwork is the regression that matters.
//
// Whatever a caller passes, the service must be the same file with the same
// name — otherwise installing a second network rewrites the first one's
// service, and the failure is two healthy-looking units serving one network.
func TestTheServiceDefinitionNamesNoNetwork(t *testing.T) {
	// systemdPlan directly, not PlanService: PlanService switches on GOOS and
	// would leave one renderer untested on any given machine — and a plist has
	// no ExecStart to assert about.
	args := []string{"agent", "run"}
	a := systemdPlan("/usr/local/bin/orbit", args, paths.DefaultRoot)
	b := systemdPlan("/usr/local/bin/orbit", args, paths.DefaultRoot)

	if a.Path != b.Path || a.Name != b.Name || a.Contents != b.Contents {
		t.Error("the service definition varies between installs, so one network's " +
			"install can rewrite another's")
	}
	for _, slug := range []string{"prod", "staging", "/var/lib/orbit/prod"} {
		if strings.Contains(a.Contents, slug) {
			t.Errorf("the service definition names %q; it serves every network", slug)
		}
	}
	if strings.Contains(a.Contents, "%i") {
		t.Error("the service uses %i, which belongs to a per-network template and " +
			"has nothing to expand to here")
	}
	if strings.Contains(execStartOf(t, a.Contents), "-dir") {
		t.Error("ExecStart names a directory, which pins one service to one network " +
			"while claiming to serve all of them")
	}
}

// TestLaunchdKeepsArgumentBoundaries. A plist is an argument ARRAY, and joining
// on spaces would hand launchd one long argument — which fails in a way that
// looks like the flag was not understood.
func TestLaunchdKeepsArgumentBoundaries(t *testing.T) {
	p := launchdPlan("/usr/local/bin/orbit", []string{"agent", "run", "-verify-url", "http://x/y"})

	for _, want := range []string{
		"<string>/usr/local/bin/orbit</string>",
		"<string>agent</string>",
		"<string>run</string>",
		"<string>-verify-url</string>",
		"<string>http://x/y</string>",
	} {
		if !strings.Contains(p.Contents, want) {
			t.Errorf("plist is missing %s", want)
		}
	}
	if strings.Contains(p.Contents, "<string>agent run</string>") {
		t.Error("arguments were joined; launchd needs one <string> per argument")
	}
}

// TestNonDefaultRootReachesTheService. A host with an unconventional layout has
// to be served too, and the root is the one path the service does carry —
// because it names the SET of networks, not one of them.
func TestNonDefaultRootReachesTheService(t *testing.T) {
	p := systemdPlan("/usr/local/bin/orbit", []string{"agent", "run", "-root", "/opt/orbit"}, "/opt/orbit")
	if !strings.Contains(execStartOf(t, p.Contents), "-root /opt/orbit") {
		t.Errorf("the custom root never reached the command: %q", execStartOf(t, p.Contents))
	}
	if !strings.Contains(p.Contents, "ReadWritePaths=/opt/orbit") {
		t.Error("the unit grants write access to the default root rather than the one in use")
	}
}

func TestPlanServiceNeedsABinary(t *testing.T) {
	if _, err := PlanService(paths.DefaultRoot, "", ""); err == nil {
		t.Error("an empty binary path produced a unit that could never start")
	}
}

// TestPlanServiceBuildsTheRootArgument covers the piece systemdPlan does not:
// PlanService is what decides -root belongs on the command line at all, and it
// omits it for the default so the common unit stays free of paths.
func TestPlanServiceBuildsTheRootArgument(t *testing.T) {
	def, err := PlanService(paths.DefaultRoot, "/usr/local/bin/orbit", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(def.Contents, "-root") {
		t.Error("the default root was written into the service; it is the default")
	}

	custom, err := PlanService("/opt/orbit", "/usr/local/bin/orbit", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(custom.Contents, "/opt/orbit") {
		t.Error("a custom root never reached the service definition")
	}
}
