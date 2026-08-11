//go:build linux || darwin

package hostcfg

import (
	"net"
	"strings"
)

// The helpers the platform resolver readers use, on the platforms that have one.
//
// They lived in dns.go, which every platform builds, while their only callers are
// dns_linux.go and dns_darwin.go. On any other GOOS they were unreachable — and
// invisible, because both deadcode gates only ever analysed the linux build. That
// is the third variant of a mistake this package has now made twice: an orphan
// that fails to type-check, an unbuilt platform breaking, and now an orphan that
// compiles perfectly and is called by nobody.
//
// The build tag is the fix and the gate change beside it is the guard.

// isOwnResolver reports whether an address is a resolver Orbit is running.
//
// Meant as the guard against the only way this design can fail catastrophically:
// once the OS is pointed at this resolver, the system's list of resolvers contains
// this resolver, and a restart that re-read it would forward every query to itself.
//
// It does not currently deliver that on linux, where the address the OS is left
// holding is systemd-resolved's stub rather than the address recorded here. See
// docs/adr/0013-the-resolver-is-restored-not-just-set.md.
//
// Package-level rather than a method because the platform readers call it while the
// resolver's lock is held by Apply.
func isOwnResolver(host string) bool {
	_, ok := ownResolvers.Load(strings.TrimSpace(host))
	return ok
}

// hostPort53 normalises a bare address into something dns.Client can dial.
func hostPort53(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}
