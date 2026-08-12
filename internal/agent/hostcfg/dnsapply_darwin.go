package hostcfg

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Pointing macOS at the resolver.
//
// NOT /etc/resolv.conf. On macOS that file is a courtesy copy the system maintains; the
// resolver library does not consult it, so writing it changes nothing and looks like it
// worked. Every tool that gets this right uses the configuration store instead.
//
// TWO MECHANISMS, BOTH OWNED WHOLE:
//
//   - /etc/resolver/<domain>, a file per domain, which is how macOS has done split DNS
//     for twenty years. Ours is the only thing in it, removal is unlink, and it needs no
//     daemon and no privileged API. This is what makes `ssh laptop` work.
//
//   - A scutil State key, for the case where an exit node means EVERY lookup must come
//     here rather than only the mesh domain. That is the DNS leak: a full tunnel whose
//     resolver still points at the café's router tells that router every name the machine
//     looks up. Removal is removing the key.
//
// Both are separate objects Orbit created, neither is a line inside something else's
// file, and each is removed by name — the same rule the nftables table and the ip rule
// follow, because a half-removed DNS configuration is a machine that resolves nothing.

const resolverDir = "/etc/resolver"

// resolverMarker opens every file Orbit writes there, and is how the sweep
// recognises its own work when it has no record of what it wrote.
const resolverMarker = "# Managed by Orbit. Do not edit.\n"

// scutilKey is the store entry the global override lives under. Named, so removal needs
// no memory of what was in it.
const scutilKey = "State:/Network/Service/orbit/DNS"

// applyDNS points this machine at addr for the mesh domain, and for everything when
// global is set.
func applyDNS(_, domain, addr string, global bool) error {
	// AddrPort, not a string split. `strings.Cut(addr, ":")` took the first
	// colon, so an IPv6 listen address — "[fd42::5]:53" — became "[fd42", which
	// was then written into /etc/resolver and handed to scutil as a nameserver.
	// The renderer produces a v6 listen address whenever the network is v6, so
	// this was reachable, silent, and total.
	host := addr
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		host = ap.Addr().String()
	} else if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if domain != "" {
		if err := os.MkdirAll(resolverDir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", resolverDir, err)
		}
		body := fmt.Sprintf("%snameserver %s\n", resolverMarker, host)
		path := filepath.Join(resolverDir, domain)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	if !global {
		return removeGlobalDNS()
	}
	return setGlobalDNS(host, domain)
}

// removeDNS puts this machine's resolution back.
func removeDNS(_, domain string) error {
	if domain != "" {
		if err := os.Remove(filepath.Join(resolverDir, domain)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return removeGlobalDNS()
}

// setGlobalDNS makes this resolver the one every lookup goes to.
//
// scutil reads its commands from stdin, which is also the only way to set a multi-value
// array without quoting games.
func setGlobalDNS(host, domain string) error {
	var b strings.Builder
	b.WriteString("d.init\n")
	fmt.Fprintf(&b, "d.add ServerAddresses * %s\n", host)
	if domain != "" {
		fmt.Fprintf(&b, "d.add SearchDomains * %s\n", domain)
	}
	fmt.Fprintf(&b, "set %s\n", scutilKey)
	b.WriteString("quit\n")
	return scutil(b.String())
}

// removeGlobalDNS takes the key away. Not an error when it was never there, which is what
// makes uninstall safe to run twice and safe on a machine that never had an exit node.
func removeGlobalDNS() error {
	return scutil(fmt.Sprintf("remove %s\nquit\n", scutilKey))
}

func scutil(script string) error {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil: %w: %s\n--- script ---\n%s",
			err, strings.TrimSpace(string(out)), script)
	}
	return nil
}

// sweepResolverDir removes every /etc/resolver file Orbit wrote, without being
// told which domains it wrote them for.
//
// By CONTENT, because the filename is the mesh domain and the sweep runs before
// any network is configured — there is nothing to consult. Every file Orbit
// writes opens with the marker line below, and nothing else on the machine
// writes it, so matching on it removes ours and only ours.
func sweepResolverDir() error {
	entries, err := os.ReadDir(resolverDir)
	if err != nil {
		return nil // no such directory is the normal case
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(resolverDir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil || !strings.HasPrefix(string(b), resolverMarker) {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
