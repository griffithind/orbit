package agent

import (
	"strings"
	"testing"
)

// Service definitions are rendered from resolved values, so the tests are about
// the two things a generator gets wrong: a command line that does not reconstruct
// the invocation, and arguments that lose their boundaries.

func TestSystemdExecStartReconstructsTheCommand(t *testing.T) {
	p := systemdPlan("prod", "/var/lib/orbit/prod", "/usr/local/bin/orbit",
		[]string{"agent", "run", "-dir", "/var/lib/orbit/prod"})

	exec := execStartOf(t, p.Contents)
	want := "/usr/local/bin/orbit agent run -dir /var/lib/orbit/prod"
	if exec != want {
		t.Errorf("ExecStart = %q\n           want %q", exec, want)
	}
}

// TestSystemdExecStartSurvivesAnExtraArgument. The command was once built by
// slicing the argument list at a fixed index, which is correct until the shape
// changes and then silently drops or duplicates a flag.
func TestSystemdExecStartSurvivesAnExtraArgument(t *testing.T) {
	p := systemdPlan("prod", "/d", "/usr/local/bin/orbit",
		[]string{"agent", "run", "-dir", "/d", "-verify-url", "http://10.42.0.1:8443/agent/v1/state"})

	exec := execStartOf(t, p.Contents)
	want := "/usr/local/bin/orbit agent run -dir /d -verify-url http://10.42.0.1:8443/agent/v1/state"
	if exec != want {
		t.Errorf("ExecStart = %q\n           want %q", exec, want)
	}
	// Scoped to the ExecStart LINE, not the file: the unit's own prose says
	// "the agent runs nebula in-process", and counting across the whole file
	// matched that sentence rather than the command.
	if strings.Count(exec, "agent run") != 1 {
		t.Error("the subcommand appears more than once; the binary and the arguments overlap")
	}
}

// TestLaunchdKeepsArgumentBoundaries. A plist is an argument ARRAY, and joining
// on spaces would hand launchd one long argument — which fails in a way that
// looks like the flag was not understood.
func TestLaunchdKeepsArgumentBoundaries(t *testing.T) {
	p := launchdPlan("prod", "/usr/local/bin/orbit",
		[]string{"agent", "run", "-dir", "/var/lib/orbit/prod"})

	for _, want := range []string{
		"<string>/usr/local/bin/orbit</string>",
		"<string>agent</string>",
		"<string>run</string>",
		"<string>-dir</string>",
		"<string>/var/lib/orbit/prod</string>",
	} {
		if !strings.Contains(p.Contents, want) {
			t.Errorf("plist is missing %s", want)
		}
	}
	if strings.Contains(p.Contents, "<string>agent run</string>") {
		t.Error("arguments were joined; launchd needs one <string> per argument")
	}
}

// TestServiceNamesAreInstanceScoped. A host on two networks runs two services
// over two directories with nothing shared, so neither the unit instance nor the
// launchd label may be the same for two slugs — a bare name would have the
// second install stop the first network's data plane.
func TestServiceNamesAreInstanceScoped(t *testing.T) {
	a := systemdPlan("prod", "/d1", "/b", []string{"agent", "run", "-dir", "/d1"})
	b := systemdPlan("staging", "/d2", "/b", []string{"agent", "run", "-dir", "/d2"})
	if a.Name == b.Name {
		t.Errorf("both networks map to the unit %q", a.Name)
	}

	c := launchdPlan("prod", "/b", []string{"agent", "run", "-dir", "/d1"})
	d := launchdPlan("staging", "/b", []string{"agent", "run", "-dir", "/d2"})
	if c.Name == d.Name || c.Path == d.Path {
		t.Errorf("both networks map to the label %q at %q", c.Name, c.Path)
	}
}

func TestPlanServiceRejectsABadSlug(t *testing.T) {
	if _, err := PlanService("", "/d", "/b", ""); err == nil {
		t.Error("an empty slug produced a service definition")
	}
	if _, err := PlanService("prod", "/d", "", ""); err == nil {
		t.Error("an empty binary path produced a unit that could never start")
	}
}

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
