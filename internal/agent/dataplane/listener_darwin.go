package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/udp"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// ErrNoPhysicalDefault means every default route on this machine leads back into a
// tunnel. Pinning to one would be the loop, spelled differently, so we refuse instead.
var ErrNoPhysicalDefault = errors.New("no physical default route to pin the nebula socket to")

// newListenerFactory returns a udp.ListenerFactory that scopes nebula's socket to the
// physical default route's interface, or nil to let nebula open its own listener.
//
// Nil is the important half. Only a host the control plane has given an exit node needs
// pinning, and for every other Mac this returns nil and nothing about the datapath
// changes.
func newListenerFactory(l *slog.Logger, exitNode bool) udp.ListenerFactory {
	if !exitNode {
		return nil
	}
	return func(_ *slog.Logger, ip netip.Addr, port int, multi bool, batch int) (udp.Conn, error) {
		return newPinnedConn(l, ip, port, multi)
	}
}

// pinnedConn is a udp.Conn scoped to one physical interface.
//
// It is deliberately the simple darwin datapath — one packet per syscall — because that
// is what nebula's own darwin conn does. Nothing is given up by not using it.
type pinnedConn struct {
	*net.UDPConn

	l    *slog.Logger
	isV4 bool

	mu  sync.Mutex
	idx int // interface index currently pinned, 0 for none
}

var _ udp.Conn = (*pinnedConn)(nil)

func newPinnedConn(l *slog.Logger, ip netip.Addr, port int, multi bool) (udp.Conn, error) {
	idx, name, err := PhysicalDefaultInterface()
	if err != nil {
		return nil, err
	}

	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				if multi {
					if opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); opErr != nil {
						opErr = fmt.Errorf("SO_REUSEPORT: %w", opErr)
						return
					}
				}
				// Before the socket is usable, not after it has bound and sent. A
				// window where nebula's UDP follows the routing table is a window
				// where it goes into the tunnel it carries.
				opErr = bindFd(fd, ip.Is4() || !ip.IsValid(), idx)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	pc, err := lc.ListenPacket(context.TODO(), "udp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("unexpected PacketConn: %T", pc)
	}

	c := &pinnedConn{UDPConn: uc, l: l, idx: idx}
	la, err := c.LocalAddr()
	if err != nil {
		uc.Close()
		return nil, err
	}
	c.isV4 = la.Addr().Is4()

	l.Info("nebula socket pinned to the physical default route",
		"interface", name, "index", idx, "addr", la)
	return c, nil
}

func bindFd(fd uintptr, v4 bool, idx int) error {
	if v4 {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, idx)
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, idx)
}

// Rebind re-pins to whatever the physical default route is now.
//
// This is the method nebula calls when the network changes, and its own implementation
// clears the scope so sends follow the routing table again. For this host the routing
// table is the trap — it holds a default route into the tunnel. So the answer to a
// network change is a new pin, not no pin.
//
// A failure leaves the previous pin in place. That is the safe direction: a stale pin to
// a departed interface fails to send, which recovers on the next change, while an unpinned
// socket sends into the tunnel and takes the machine off the network entirely.
func (p *pinnedConn) Rebind() error {
	idx, name, err := PhysicalDefaultInterface()
	if err != nil {
		p.l.Warn("network changed but no physical default route to pin to; keeping the previous pin",
			"error", err)
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if idx == p.idx {
		return nil
	}

	rc, err := p.UDPConn.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if err := rc.Control(func(fd uintptr) { opErr = bindFd(fd, p.isV4, idx) }); err != nil {
		return err
	}
	if opErr != nil {
		return opErr
	}

	p.l.Info("nebula socket re-pinned after a network change",
		"interface", name, "index", idx, "was", p.idx)
	p.idx = idx
	return nil
}

func (p *pinnedConn) LocalAddr() (netip.AddrPort, error) {
	a, ok := p.UDPConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("LocalAddr returned %T", p.UDPConn.LocalAddr())
	}
	addr, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("LocalAddr returned invalid IP: %s", a.IP)
	}
	return netip.AddrPortFrom(addr, uint16(a.Port)), nil
}

func (p *pinnedConn) ListenOut(r udp.EncReader) error {
	buf := make([]byte, udp.MTU)
	for {
		n, rua, err := p.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			p.l.Error("unexpected udp socket receive error", "error", err)
			continue
		}
		r(netip.AddrPortFrom(rua.Addr().Unmap(), rua.Port()), buf[:n])
	}
}

func (p *pinnedConn) WriteTo(b []byte, addr netip.AddrPort) error {
	if p.isV4 && addr.Addr().Is6() {
		return udp.ErrInvalidIPv6RemoteForSocket
	}
	_, err := p.WriteToUDPAddrPort(b, addr)
	return err
}

func (p *pinnedConn) ReloadConfig(*config.C) {}

func (p *pinnedConn) SupportsMultipleReaders() bool { return false }

// PhysicalDefaultInterface finds the interface index of the default route that actually
// leaves this machine, skipping tunnels.
//
// The skip is the whole reason this is not one line. Once an exit node is in use there is
// a default route pointing at nebula's own utun, and it is more specific than nothing —
// pinning to it would send nebula's UDP into the tunnel that carries it, which is the
// failure this code exists to prevent. Tailscale's netns_darwin.go refuses the same way.
func PhysicalDefaultInterface() (int, string, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return 0, "", fmt.Errorf("read the routing table: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return 0, "", fmt.Errorf("parse the routing table: %w", err)
	}

	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_UP == 0 || rm.Flags&unix.RTF_GATEWAY == 0 {
			continue
		}
		if !isDefaultDst(rm.Addrs) {
			continue
		}
		iface, err := net.InterfaceByIndex(rm.Index)
		if err != nil || isTunnelInterface(iface.Name) {
			continue
		}
		return rm.Index, iface.Name, nil
	}
	return 0, "", ErrNoPhysicalDefault
}

func isDefaultDst(addrs []route.Addr) bool {
	if len(addrs) <= unix.RTAX_DST {
		return false
	}
	switch a := addrs[unix.RTAX_DST].(type) {
	case *route.Inet4Addr:
		return a.IP == [4]byte{}
	case *route.Inet6Addr:
		return a.IP == [16]byte{}
	}
	return false
}

// isTunnelInterface is a name test rather than an address test on purpose. The socket is
// opened before nebula has finished bringing its tun up, so asking "does this interface
// carry an overlay address" answers "not yet" at exactly the wrong moment. Every darwin
// tunnel — nebula's, and any other VPN on the machine — is a utun, and none of them is a
// route out of this computer.
func isTunnelInterface(name string) bool {
	return strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "ipsec")
}
