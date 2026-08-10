package agent

import (
	"strings"
	"syscall"

	"github.com/griffithind/orbit/internal/agent/dataplane"
)

// pinSocket scopes this socket to the physical default route's interface.
//
// Darwin has no mark to set and no rule to match it, so the mark argument is ignored and
// the socket is bound the way nebula's own is — the same lookup, which refuses to pin to
// a tunnel. A failure to find one returns the error rather than leaving the socket
// unpinned: the caller is the recovery path, and a recovery path silently routed into the
// tunnel is the failure this exists to prevent.
func pinSocket(network string, fd uintptr, _ int) error {
	idx, _, err := dataplane.PhysicalDefaultInterface()
	if err != nil {
		return err
	}
	if strings.HasSuffix(network, "6") {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, idx)
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, idx)
}
