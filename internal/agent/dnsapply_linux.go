package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Pointing Linux at the resolver.
//
// TWO MECHANISMS, AND THE FIRST IS MUCH BETTER. systemd-resolved keeps DNS settings per
// LINK, so everything Orbit sets hangs off the tun device and `resolvectl revert` takes
// all of it away by name — the same ownership property the nftables table has, and for
// the same reason: removal must work without a record of what was set, even if somebody
// changed it in between.
//
// The fallback rewrites /etc/resolv.conf, which is a file the whole machine shares.
// Ownership there is a marker line and a copy of what was displaced, which is strictly
// weaker: a DHCP client that rewrites the file between our runs wins, and we find out on
// the next reconcile rather than at the moment it happens. Reconciling every cycle is
// what makes that survivable.
//
// `~.` is the part that closes the exit-node DNS leak. It makes this link the default
// route for ALL queries rather than only the mesh domain, so a full-tunnel machine stops
// asking the café's resolver what its employer's servers are called.

const resolvMarker = "# Managed by Orbit. Do not edit."

// resolvPath is a variable so the round trip can be tested without a container that
// resolves nothing for the rest of its life if the test fails halfway.
var resolvPath = "/etc/resolv.conf"

// applyDNS points this machine's resolver at addr.
func applyDNS(dev, domain, addr string, _ bool) error {
	if dev == "" {
		return fmt.Errorf("no tun device to attach DNS settings to")
	}
	if hasResolved() {
		if err := run("resolvectl", "dns", dev, addr); err != nil {
			return err
		}
		// The mesh domain AND `~.`: the first is the search suffix so `ssh
		// laptop` works, the second routes everything else here too, which is
		// what stops a full tunnel leaking lookups to the local network.
		if err := run("resolvectl", "domain", dev, domain, "~."); err != nil {
			return err
		}
		return run("resolvectl", "default-route", dev, "yes")
	}
	return writeResolvConf(domain, addr)
}

// removeDNS puts this machine's resolver back.
func removeDNS(dev, _ string) error {
	if hasResolved() && dev != "" {
		// One command, no memory of what was set, and not an error when nothing
		// was. Exactly what uninstall needs.
		return run("resolvectl", "revert", dev)
	}
	return restoreResolvConf()
}

func hasResolved() bool {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return false
	}
	// Present but not running is the case that matters: resolvectl exists on
	// plenty of machines where resolved is masked, and its commands fail in a
	// way that reads as a bug rather than as "use the other mechanism".
	return run("resolvectl", "status") == nil
}

// writeResolvConf takes over /etc/resolv.conf, keeping what it displaced.
//
// The previous contents are kept in the file itself, commented, rather than in a separate
// backup: a backup somewhere else is a thing that gets lost, and an operator looking at a
// resolv.conf they did not write should be able to see what was there from the file in
// front of them.
func writeResolvConf(domain, addr string) error {
	path := resolvPath
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	previous := saved(string(existing))
	if previous == "" {
		previous = string(existing)
	}

	host, _, _ := strings.Cut(addr, ":")
	var b strings.Builder
	b.WriteString(resolvMarker + "\n")
	b.WriteString("# Run `orbit agent uninstall` to restore what is preserved below.\n")
	fmt.Fprintf(&b, "nameserver %s\n", host)
	if domain != "" {
		fmt.Fprintf(&b, "search %s\n", domain)
	}
	b.WriteString("#--- previously ---\n")
	for _, line := range strings.Split(strings.TrimRight(previous, "\n"), "\n") {
		fmt.Fprintf(&b, "#|%s\n", line)
	}
	return replaceFile(path, b.String())
}

// restoreResolvConf puts back what writeResolvConf displaced.
//
// A file we did not write is left alone. Restoring over it would clobber whatever took
// over in the meantime, which on this file is usually the thing that actually knows what
// the resolvers should be.
func restoreResolvConf() error {
	path := resolvPath
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if !strings.HasPrefix(string(body), resolvMarker) {
		return nil
	}
	return replaceFile(path, saved(string(body)))
}

// saved extracts the commented-out original from a file we wrote.
func saved(body string) string {
	_, rest, ok := strings.Cut(body, "#--- previously ---\n")
	if !ok {
		return ""
	}
	var out strings.Builder
	for _, line := range strings.Split(rest, "\n") {
		if orig, ok := strings.CutPrefix(line, "#|"); ok {
			out.WriteString(orig + "\n")
		}
	}
	return out.String()
}

// replaceFile writes through a temporary file in the same directory.
//
// /etc/resolv.conf is read by everything on the machine, constantly. A partial write is a
// moment where the system has no resolvers at all, and rename(2) has no such moment.
func replaceFile(path, body string) error {
	tmp := path + ".orbit-tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
