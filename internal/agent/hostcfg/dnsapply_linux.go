package hostcfg

import (
	"fmt"
	"os/exec"
	"strings"
)

// Pointing Linux at the resolver, through systemd-resolved and nothing else.
//
// resolved keeps DNS settings per LINK, so everything Orbit sets hangs off the tun device
// and `resolvectl revert <dev>` takes all of it away by name — the ownership property
// every other object in this layer has, and needed for the same reason: removal must work
// with no record of what was set, even if somebody changed it in between.
//
// WHY THERE IS NO /etc/resolv.conf FALLBACK, having briefly had one.
//
// On most systemd and NetworkManager machines that path is a SYMLINK into /run. Writing
// it through rename(2) replaces the link with a regular file, which does not displace the
// system's DNS management so much as permanently break it — and restoring contents can
// never put a symlink back, so uninstalling would leave the machine worse than Orbit
// found it.
//
// It was also the only thing here not owned whole: a marker line inside a file the entire
// machine shares. A DHCP client rewriting it between reconciles takes the original
// resolvers with it, because the only copy lived inside the file that got overwritten.
//
// The honest alternative is no alternative. The resolver still runs and still answers
// anything that asks it; the machine just does not ask automatically, exactly as on
// Windows and the BSDs. If non-resolved Linux is ever worth supporting, the mechanism is
// resolvconf's `-a`/`-d` registration — an ownership protocol — and not editing the file.

// applyDNS points this machine's resolver at addr, for the mesh domain — and for
// everything, when global is set.
//
// SCOPE IS THE ARGUMENT, and it used to be discarded. This function took `global bool`,
// named it `_`, and issued `~.` plus `default-route yes` unconditionally. `~.` is
// resolved's routing-domain wildcard: it makes this link the resolver of last resort for
// every name. So a host that joined a network wanting SPLIT DNS — mesh names here,
// everything else as before — had its entire query stream sent to Orbit, corporate and
// personal lookups included, and nothing said so.
//
// The wildcard is right for a full-tunnel machine: it is what stops an exit-node host
// telling the local network what it looks up. It is wrong for everyone else, and
// "everyone else" is nearly every host.
// See docs/adr/0013-the-resolver-is-restored-not-just-set.md.
func applyDNS(dev, domain, addr string, global bool) error {
	if dev == "" {
		return fmt.Errorf("no tun device to attach DNS settings to")
	}
	if !hasResolved() {
		return ErrDNSUnsupported
	}
	if err := run("resolvectl", "dns", dev, addr); err != nil {
		return err
	}

	// The domain list, and then whether this link is also the last resort.
	//
	// Both commands are issued in both cases rather than skipped, because
	// resolved keeps the previous value otherwise: a host that was global and is
	// no longer would keep `~.` and keep capturing everything. Removal has to be
	// as explicit as installation, which is the same rule the nftables table and
	// the ip rule follow.
	domains := []string{"resolvectl", "domain", dev}
	if domain != "" {
		domains = append(domains, domain)
	}
	route := "no"
	if global {
		domains = append(domains, "~.")
		route = "yes"
	}
	if len(domains) == 3 && !global {
		// resolvectl needs at least one argument; the empty list is spelled "".
		domains = append(domains, "")
	}
	if err := run(domains[0], domains[1:]...); err != nil {
		return err
	}
	return run("resolvectl", "default-route", dev, route)
}

// removeDNS puts this machine's resolver back. One command, no memory of what was set,
// and not an error when nothing was.
func removeDNS(dev, _ string) error {
	if dev == "" || !hasResolved() {
		return nil
	}
	return run("resolvectl", "revert", dev)
}

func hasResolved() bool {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return false
	}
	// Present but not running is the case that matters: resolvectl exists on
	// plenty of machines where resolved is masked, and its commands fail there
	// in a way that reads as a bug rather than as "this machine cannot do it".
	return run("resolvectl", "status") == nil
}

// output runs a command and returns its stdout, for the few places that read a
// setting back rather than assert one.
func output(name string, args ...string) (string, error) {
	b, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(b), nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
