package hostcfg

import (
	"bufio"
	"os"
	"strings"
)

// systemResolvers reads what this machine resolved with before we touched anything.
//
// RESOLVED'S OWN LIST FIRST, and /etc/resolv.conf only as a fallback. The previous
// version read resolv.conf unconditionally, on the reasoning that resolved's stub writes
// 127.0.0.53 there and "forwarding to it is correct and needs no DBus", guarded by
// isOwnResolver against a loop.
//
// That guard could not fire. It compares against the address Orbit LISTENS on — an
// overlay address — and resolved never writes that to resolv.conf. The two sets are
// disjoint by construction. So on a host where Orbit is the last resort, a restart
// re-read 127.0.0.53, forwarded to resolved, and resolved routed straight back to Orbit.
//
// Reading resolved's per-link upstreams instead removes the stub from the answer
// entirely, which is a structural fix rather than a wider blocklist: there is no address
// to fail to recognise. Loopback is refused as a belt-and-braces second guard, because
// any resolver on this machine is a candidate for the same loop by a different route.
// See docs/adr/0013-the-resolver-is-restored-not-just-set.md.
func systemResolvers() []string {
	if up := resolvedUpstreams(); len(up) > 0 {
		return up
	}
	return resolvConfServers()
}

func isOwnDevice(dev string) bool {
	_, ok := ownDevices.Load(strings.TrimSpace(dev))
	return ok
}

// resolvedUpstreams asks resolved what it actually forwards to.
//
// `resolvectl dns` prints one line per link plus a Global line:
//
//	Global: 9.9.9.9
//	Link 2 (eth0): 192.168.1.1
//	Link 7 (orbit0): 10.42.0.9
//
// Our own link is skipped by name — that is the one whose answer is us.
func resolvedUpstreams() []string {
	if !hasResolved() {
		return nil
	}
	out, err := output("resolvectl", "dns")
	if err != nil {
		return nil
	}

	var servers []string
	seen := map[string]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		name, list, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		// "Link 7 (orbit0)" — the device Orbit configured answers with itself.
		if dev, found := strings.CutSuffix(strings.TrimSpace(name), ")"); found {
			if _, d, ok := strings.Cut(dev, "("); ok && isOwnDevice(d) {
				continue
			}
		}
		for _, f := range strings.Fields(list) {
			if !usableUpstream(f) {
				continue
			}
			if addr := hostPort53(f); !seen[addr] {
				seen[addr] = true
				servers = append(servers, addr)
			}
		}
	}
	return servers
}

func resolvConfServers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var servers []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		rest, ok := strings.CutPrefix(line, "nameserver")
		if !ok {
			continue
		}
		host := strings.TrimSpace(rest)
		if !usableUpstream(host) {
			continue
		}
		if addr := hostPort53(host); !seen[addr] {
			seen[addr] = true
			servers = append(servers, addr)
		}
	}
	return servers
}
