package agent

import (
	"bufio"
	"os"
	"strings"
)

// systemResolvers reads what this machine resolved with before we touched anything.
//
// /etc/resolv.conf even where systemd-resolved owns it: resolved's stub writes
// 127.0.0.53 there, which is a real resolver that forwards to the real upstreams, so
// forwarding to it is correct and needs no DBus. The exclusion below is what keeps that
// from becoming a loop once our own address is the one written.
func systemResolvers() []string {
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
		if host == "" || isOwnResolver(host) {
			continue
		}
		if addr := hostPort53(host); !seen[addr] {
			seen[addr] = true
			servers = append(servers, addr)
		}
	}
	return servers
}
