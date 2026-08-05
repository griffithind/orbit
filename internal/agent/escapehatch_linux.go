package agent

import "golang.org/x/sys/unix"

// pinSocket marks this socket so the ip rule sends it out of the tunnel.
//
// The same mark nebula stamps its own UDP with, read from the same signed config, matched
// by the same rule in the same table. There is nothing Linux-specific to install here
// because the host-state layer already installed it — see policyroute_linux.go.
func pinSocket(_ string, fd uintptr, mark int) error {
	if mark == 0 {
		return nil
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
}
