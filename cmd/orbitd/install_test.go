package main

import (
	"strings"
	"testing"
)

// The unit and the env file are one artifact in two pieces, and the failure
// mode is that they disagree.
//
// A real deployment hit exactly that: the unit said
// `-mesh ${ORBIT_NETWORK}=10.42.0.1` and the env file set ORBIT_NETWORK to
// nothing, because it was assembled by hand from a shell where the variable was
// unset. systemd expands an unset variable to the empty string, so orbitd saw
// `-mesh =10.42.0.1`, and the report was sixty lines of flag help with no
// mention of the cause.
//
// Generating both from the same values is what closes that. These check the
// pair, not each file.
func TestUnitAndEnvAgreeOnTheNetwork(t *testing.T) {
	const netID = "fe0323f7-cc73-4d2c-aa3f-827eb8684fb3"
	p := planControlPlane(netID,
		"postgres://orbit_app:pw@127.0.0.1/orbit", "pepper",
		"https://orbit.example.com/enroll/v1/enroll",
		"10.42.0.1", "203.0.113.10:4242", "/var/lib/orbit/ca.key")

	if !strings.Contains(p.Env, "ORBIT_NETWORK="+netID+"\n") {
		t.Errorf("the env file does not set ORBIT_NETWORK to the id bootstrap just created:\n%s", p.Env)
	}
	if strings.Contains(p.Env, "ORBIT_NETWORK=\n") {
		t.Error("ORBIT_NETWORK is empty, which expands to `-mesh =<addr>` and fails to parse")
	}

	// The unit must read the file that defines it. A unit referring to
	// ${ORBIT_NETWORK} with an EnvironmentFile pointing somewhere else is the
	// same failure wearing a different cause.
	if !strings.Contains(p.Unit, "EnvironmentFile="+p.EnvPath+"\n") {
		t.Errorf("the unit does not load %s:\n%s", p.EnvPath, p.Unit)
	}
	if strings.Contains(p.Unit, "${ORBIT_NETWORK}") && !strings.Contains(p.Env, "ORBIT_NETWORK=") {
		t.Error("the unit expands ORBIT_NETWORK and the env file never sets it")
	}
}

// TestNoMeshWithoutAnOverlayAddress. Rendering `-mesh ${ORBIT_NETWORK}=` with
// an empty address is the same class of broken as an empty network id, so the
// flag is omitted entirely instead — which orbitd reports as "no -mesh
// configured", a state it names rather than a parse error.
func TestNoMeshWithoutAnOverlayAddress(t *testing.T) {
	p := planControlPlane("net-id", "dsn", "pepper", "https://x/enroll/v1/enroll",
		"", "", "/var/lib/orbit/ca.key")

	// Directives only. The unit's own header comment explains the -mesh failure
	// this guards against, and matching that sentence instead of the flag is a
	// mistake I have now made twice in this file's siblings.
	body := directives(p.Unit)
	if strings.Contains(body, "-mesh") {
		t.Errorf("a unit with no overlay address still renders -mesh:\n%s", body)
	}
	if strings.Contains(body, "-lighthouse") {
		t.Errorf("a unit with no lighthouse address still renders -lighthouse:\n%s", body)
	}
}

// directives drops comment and blank lines, so an assertion about what the unit
// DOES cannot be satisfied or defeated by what it SAYS.
func directives(unit string) string {
	var keep []string
	for _, line := range strings.Split(unit, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

// TestUnitNamesAResolvedBinary. A unit naming a path the binary is not at
// starts once, from the shell that ran bootstrap, and never again after a
// reboot.
func TestUnitNamesAResolvedBinary(t *testing.T) {
	p := planControlPlane("n", "dsn", "pepper", "https://x/e", "10.0.0.1", "", "/var/lib/orbit/ca.key")

	var exec string
	for _, line := range strings.Split(p.Unit, "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			exec = line
		}
	}
	if exec == "" {
		t.Fatal("the unit has no ExecStart")
	}
	if !strings.HasPrefix(exec, "ExecStart=/") {
		t.Errorf("ExecStart is not an absolute path: %q", exec)
	}
	if !strings.Contains(exec, " serve") {
		t.Errorf("ExecStart does not run `serve`: %q", exec)
	}
}

// TestSecretsAreNotInTheUnit. The unit is 0644 so an operator can read the
// flags; the DSN and the pepper must therefore not be in it.
func TestSecretsAreNotInTheUnit(t *testing.T) {
	const dsn = "postgres://orbit_app:hunter2@127.0.0.1/orbit"
	p := planControlPlane("n", dsn, "the-pepper", "https://x/e", "10.0.0.1", "", "/var/lib/orbit/ca.key")

	if strings.Contains(p.Unit, "hunter2") {
		t.Error("the database password is in the world-readable unit")
	}
	if strings.Contains(p.Unit, "the-pepper") {
		t.Error("the enrollment pepper is in the world-readable unit")
	}
	if !strings.Contains(p.Env, dsn) || !strings.Contains(p.Env, "the-pepper") {
		t.Error("the env file is missing what the unit expects it to provide")
	}
}
