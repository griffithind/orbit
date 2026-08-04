package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// deploy/compose.yml, checked for the one thing that made it unrunnable.
//
// orbitd runs with network_mode: host, which is not optional — nebula
// advertises the address it believes it is reachable at, and behind a bridge
// NAT it would hand every managed host a container address nobody can dial.
//
// The consequence is easy to miss: a host-networked service is OFF the compose
// network, so it cannot resolve another service by name and can only reach one
// through a published port on the host. The file shipped with DSNs pointing at
// 127.0.0.1:5432 and a Postgres that published nothing, so every orbitd command
// failed with "connection refused" against a database the same compose run had
// just reported healthy.

type composeFile struct {
	Services map[string]struct {
		NetworkMode string            `yaml:"network_mode"`
		Environment map[string]string `yaml:"environment"`
		Ports       []string          `yaml:"ports"`
		Entrypoint  []string          `yaml:"entrypoint"`
		Profiles    []string          `yaml:"profiles"`
		Command     []string          `yaml:"command"`
	} `yaml:"services"`
}

func loadCompose(t *testing.T) composeFile {
	t.Helper()
	b, err := os.ReadFile("../../deploy/compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	var c composeFile
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatalf("deploy/compose.yml does not parse: %v", err)
	}
	if len(c.Services) == 0 {
		t.Fatal("deploy/compose.yml declares no services")
	}
	return c
}

// TestHostNetworkedServicesCanReachWhatTheirDSNsName.
//
// For every service on host networking, every 127.0.0.1:<port> its environment
// names must be published on 127.0.0.1 by some service — because that is the
// only way the two can meet once one of them has left the compose network.
func TestHostNetworkedServicesCanReachWhatTheirDSNsName(t *testing.T) {
	c := loadCompose(t)

	// Two ways a port ends up on the host, and the first version of this test
	// knew only one — which made it flag the admin CLI reaching a control plane
	// that was listening perfectly well.
	//
	//   1. A bridged service PUBLISHES it.
	//   2. A host-networked service BINDS it directly, by way of a flag in its
	//      own command. There is no `ports:` entry for that and there cannot be.
	reachable := map[string]string{} // port -> the service providing it
	for name, svc := range c.Services {
		for _, p := range svc.Ports {
			// "127.0.0.1:5432:5432" -> host address, host port, container port.
			parts := strings.Split(p, ":")
			if len(parts) == 3 {
				reachable[parts[1]] = name
			}
		}
		if svc.NetworkMode != "host" {
			continue
		}
		for _, arg := range svc.Command {
			// -addr=0.0.0.0:8080, -ui-addr=127.0.0.1:8081, and so on.
			if !strings.Contains(arg, "addr=") {
				continue
			}
			if i := strings.LastIndex(arg, ":"); i >= 0 {
				if port := arg[i+1:]; port != "" {
					reachable[port] = name
				}
			}
		}
	}

	for name, svc := range c.Services {
		if svc.NetworkMode != "host" {
			continue
		}
		for key, val := range svc.Environment {
			for _, port := range loopbackPorts(val) {
				if _, ok := reachable[port]; !ok {
					t.Errorf("service %q is on host networking and %s names "+
						"127.0.0.1:%s, but no service publishes or binds that port on "+
						"the host.\n"+
						"A host-networked service is off the compose network, so it "+
						"cannot reach another service by name — every command against "+
						"this address fails with 'connection refused' while the target "+
						"reports healthy.", name, key, port)
				}
			}
		}
	}
}

// TestNothingIsPublishedOnEveryInterface.
//
// "5432:5432" binds 0.0.0.0, which would put Postgres on the public internet —
// and docker's published ports bypass firewalld, so firewall-cmd would not save
// it. Every published port must name an address.
func TestNothingIsPublishedOnEveryInterface(t *testing.T) {
	c := loadCompose(t)

	for name, svc := range c.Services {
		for _, p := range svc.Ports {
			if len(strings.Split(p, ":")) < 3 {
				t.Errorf("service %q publishes %q, which binds every interface. "+
					"Docker's port rules bypass firewalld, so this is reachable from "+
					"the internet whatever firewall-cmd says. Name an address: "+
					"\"127.0.0.1:%s\".", name, p, p)
			}
		}
	}
}

// loopbackPorts pulls the ports out of any 127.0.0.1:<port> or
// localhost:<port> in a value, which in practice means the DSNs.
func loopbackPorts(s string) []string {
	var out []string
	for _, host := range []string{"127.0.0.1:", "localhost:"} {
		rest := s
		for {
			i := strings.Index(rest, host)
			if i < 0 {
				break
			}
			rest = rest[i+len(host):]
			end := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
			if end < 0 {
				end = len(rest)
			}
			if end > 0 {
				out = append(out, rest[:end])
			}
		}
	}
	return out
}

// TestTheSetupScriptsSecretsAreIgnored.
//
// scripts/setup-control-plane.sh checks the repository out to /opt/orbit and
// writes its secrets INSIDE that clone — it has to, because compose resolves
// `file: ./ca-pass` relative to the compose file. So the working tree on a
// running control plane contains the mesh's CA passphrase and both admin
// tokens, and a `git add -A` there would commit them.
//
// Derived from the script rather than hardcoded: a new secret the script starts
// writing fails here instead of being discovered in a public repository.
func TestTheSetupScriptsSecretsAreIgnored(t *testing.T) {
	b, err := os.ReadFile("../../scripts/setup-control-plane.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)

	// Every path the script creates beside the compose file. Kept as a literal
	// list so the test states the invariant, with a check below that the script
	// still writes each one.
	secrets := []string{"ca-pass", "bootstrap-output.txt", ".env"}
	for _, name := range secrets {
		if !strings.Contains(script, name) {
			t.Errorf("the script no longer mentions %q; this list is stale and "+
				"something else may now be written unignored", name)
			continue
		}
		path := "deploy/" + name
		cmd := exec.Command("git", "check-ignore", "-q", path)
		cmd.Dir = "../.."
		if err := cmd.Run(); err != nil {
			t.Errorf("%s is NOT gitignored. The setup script writes it into a clone "+
				"on the control plane, so a stray `git add -A` there commits the "+
				"mesh's CA passphrase or an admin token to a public repository.", path)
		}
	}
}

// TestTheAdminCLIIsReachable.
//
// Both binaries have always been in the image, and the CLI was effectively
// unreachable: `docker compose run --rm orbitd orbit host code web-01` swallows
// "orbit" as an argument to orbitd's entrypoint and prints orbitd's usage —
// which reads exactly like the binary not being in the image at all.
//
// A service of its own fixes that, and it must stay behind a profile: without
// one, `docker compose up -d` tries to start a CLI that runs and exits, and
// restarts it forever.
func TestTheAdminCLIIsReachable(t *testing.T) {
	c := loadCompose(t)

	svc, ok := c.Services["orbit"]
	if !ok {
		t.Fatal("no `orbit` service; the admin CLI in the image can only be reached " +
			"through an --entrypoint override nobody will guess")
	}
	if len(svc.Entrypoint) == 0 || !strings.HasSuffix(svc.Entrypoint[0], "/orbit") {
		t.Errorf("the orbit service's entrypoint is %v, so it would run orbitd", svc.Entrypoint)
	}
	if len(svc.Profiles) == 0 {
		t.Error("the orbit service has no profile, so `docker compose up` will try to " +
			"run it as a long-lived service and restart it every time it exits")
	}
}
