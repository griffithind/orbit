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

// applyDNS points this machine's resolver at addr.
//
// `~.` alongside the mesh domain is what closes the exit-node DNS leak: the first is the
// search suffix so `ssh laptop` works, the second routes every other lookup here too, so
// a full-tunnel machine stops telling the local network what it looks up.
func applyDNS(dev, domain, addr string, _ bool) error {
	if dev == "" {
		return fmt.Errorf("no tun device to attach DNS settings to")
	}
	if !hasResolved() {
		return ErrDNSUnsupported
	}
	if err := run("resolvectl", "dns", dev, addr); err != nil {
		return err
	}
	if err := run("resolvectl", "domain", dev, domain, "~."); err != nil {
		return err
	}
	return run("resolvectl", "default-route", dev, "yes")
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

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
