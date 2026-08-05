package agent

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestPinSocketSetsTheMark proves the agent's own TCP carries the same mark nebula's UDP
// does. That the mark then diverts the packet is proven separately, by
// TestPolicyRouteDivertsMarkedTraffic — the ip rule does not care which protocol it is.
func TestPinSocketSetsTheMark(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)

	if err := pinSocket("tcp4", uintptr(fd), 0x4242); err != nil {
		if err == unix.EPERM {
			t.Skip("SO_MARK needs CAP_NET_ADMIN; run: make test-netns")
		}
		t.Fatalf("pinSocket: %v", err)
	}

	got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
	if err != nil {
		t.Fatalf("getsockopt: %v", err)
	}
	if got != 0x4242 {
		t.Errorf("SO_MARK = %#x, want 0x4242", got)
	}
}

// TestPinSocketZeroMarkIsANoop: a zero mark means the config set none, and stamping zero
// would be indistinguishable from stamping nothing while looking deliberate.
func TestPinSocketZeroMarkIsANoop(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)

	if err := pinSocket("tcp4", uintptr(fd), 0); err != nil {
		t.Fatalf("pinSocket: %v", err)
	}
}
