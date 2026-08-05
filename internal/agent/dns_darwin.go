package agent

import (
	"bufio"
	"os/exec"
	"strings"
)

// systemResolvers reads what this Mac resolved with before we touched anything.
//
// scutil rather than /etc/resolv.conf: on macOS that file is a courtesy copy maintained
// by the system, it is not what the resolver library actually consults, and it is empty
// or stale often enough that trusting it means forwarding to nothing.
func systemResolvers() []string {
	out, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	var servers []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// "nameserver[0] : 192.168.1.1"
		if len(f) != 3 || !strings.HasPrefix(f[0], "nameserver[") || f[1] != ":" {
			continue
		}
		addr := hostPort53(f[2])
		// Skip ourselves. Once the OS points here, scutil reports this resolver
		// among the system's, and forwarding to it is an infinite loop.
		if isOwnResolver(f[2]) || seen[addr] {
			continue
		}
		seen[addr] = true
		servers = append(servers, addr)
	}
	return servers
}
