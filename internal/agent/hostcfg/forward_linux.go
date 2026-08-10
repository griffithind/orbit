package hostcfg

import (
	"fmt"
	"os/exec"
	"strings"
)

// Getting forwarded packets past whatever owns this machine's FORWARD verdict.
//
// Orbit's nftables table masquerades, and masquerading a packet the filter path already
// dropped achieves nothing. On a machine with no firewall the kernel's FORWARD policy is
// ACCEPT and there is nothing to do; on Fedora, RHEL and anything else running firewalld
// there very much is, and the symptom is the worst kind — `orbit status` reports the
// gateway forwarding and NATing, because both instructions arrived and both were applied,
// while every forwarded packet is dropped somewhere Orbit never looked.
//
// WHY NOT AN accept RULE IN OUR OWN TABLE, which is the obvious answer and is wrong.
//
// nftables runs every base chain registered at a hook, in priority order, and `accept`
// only means "continue to the next chain". Only `drop` is terminal. So an accept in
// `inet orbit` does not stop firewalld's own forward chain dropping the packet a moment
// later, at any priority. Tailscale can insert into `filter FORWARD` and win because that
// is iptables semantics — one chain, first match wins. Under nftables the frontend owns
// the verdict and the only way past it is to ask the frontend.
//
// So this detects what is in charge and speaks its language, and each mechanism is still
// a single named object we can remove:
//
//   - firewalld: the tun goes in the `trusted` zone, which accepts forwarded traffic.
//     Removal is dropping the interface back out of it.
//   - ufw: a route rule for the interface, removed by the same expression.
//   - neither: our own forward chain, which works precisely because nothing else is
//     going to drop after us.
//
// Reconciled every cycle like the rest of host state, because a firewalld reload is
// exactly the kind of thing that discards an interface assignment.

// ensureForwardAllowed makes the filter path let forwarded traffic through.
func ensureForwardAllowed(h HostState) error {
	if h.TunDev == "" {
		return fmt.Errorf("no tun device to permit forwarding for")
	}
	switch {
	case firewalldRunning():
		return firewalldTrust(h.TunDev)
	case ufwActive():
		return ufwAllowRoute(h.TunDev)
	default:
		// Nothing owns the verdict, so the kernel policy decides and Orbit's own
		// table is enough. Reported rather than silent: an operator who later
		// installs firewalld needs to know this machine was relying on its
		// absence.
		return nil
	}
}

// removeForwardAllowed puts the machine back.
func removeForwardAllowed(tunDev string) error {
	if tunDev == "" {
		return nil
	}
	if firewalldRunning() {
		_ = fwcmd("--permanent", "--zone=trusted", "--remove-interface="+tunDev)
		return fwcmd("--reload")
	}
	if ufwActive() {
		_ = run("ufw", "route", "delete", "allow", "in", "on", tunDev)
	}
	return nil
}

// firewalldTrust puts the tun in the trusted zone.
//
// The whole interface rather than a rule, because that is the object firewalld exposes
// that means "traffic arriving here is not the traffic this firewall exists to filter" —
// which is exactly true of an overlay whose every packet nebula has already authenticated
// against a certificate. A per-service rule would have to enumerate what the routed
// network is for, and the answer is "whatever policy allows", decided a layer above.
func firewalldTrust(tunDev string) error {
	// Already there is the common case, and --add-interface on a member of
	// another zone is an error rather than a move.
	if out, err := fwcmdOut("--zone=trusted", "--list-interfaces"); err == nil {
		for _, f := range strings.Fields(out) {
			if f == tunDev {
				return nil
			}
		}
	}
	if err := fwcmd("--permanent", "--zone=trusted", "--add-interface="+tunDev); err != nil {
		return err
	}
	// Permanent plus reload rather than a runtime change: a runtime-only
	// assignment is lost on the next firewalld restart, and the gateway would
	// then stop forwarding for a reason nothing on the machine records.
	return fwcmd("--reload")
}

func ufwAllowRoute(tunDev string) error {
	// ufw is idempotent here — a duplicate rule is reported as a skip, not an
	// error — so there is nothing to check first.
	return run("ufw", "route", "allow", "in", "on", tunDev)
}

func firewalldRunning() bool {
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		return false
	}
	// --state is the question actually being asked. firewall-cmd exists on
	// plenty of machines where firewalld is installed and stopped, and there the
	// verdict is the kernel's, not firewalld's.
	return fwcmd("--state") == nil
}

func ufwActive() bool {
	if _, err := exec.LookPath("ufw"); err != nil {
		return false
	}
	out, err := exec.Command("ufw", "status").CombinedOutput()
	return err == nil && strings.Contains(string(out), "Status: active")
}

func fwcmd(args ...string) error { return run("firewall-cmd", args...) }

func fwcmdOut(args ...string) (string, error) {
	out, err := exec.Command("firewall-cmd", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("firewall-cmd %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
