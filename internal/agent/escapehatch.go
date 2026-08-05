package agent

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// The escape hatch: keeping the recovery path outside the thing it recovers from.
//
// The agent has two ways to the control plane and they are meant to be independent.
// Steady-state traffic goes to AgentURLs, the control plane's OVERLAY addresses. When the
// overlay is down it falls back to BaseURL, the public endpoint it enrolled against —
// State calls that "the recovery path: if the overlay is unreachable the agent has
// nowhere else to go".
//
// An exit node collapses the two into one. The rendered default route captures everything
// this machine sends, and listen.so_mark and IP_BOUND_IF protect NEBULA's UDP socket, not
// the agent's own TCP — a different socket in a different part of the program. So the
// fallback would be routed into the tunnel, and a configuration that breaks the overlay
// would take the recovery path down with it. The unreachable-guard still reverts, but
// what was two independent paths becomes one path and a timer.
//
// So the agent's own connections to the public endpoint get the same treatment nebula's
// do. On Linux that is the mark, which the ip rule already diverts; on darwin it is the
// same interface scope. Every other platform has nothing to escape, because it has no
// exit node.
//
// SCOPED TO THE PUBLIC ENDPOINT, not to all agent traffic. Overlay addresses must keep
// going through the tun — that is how the agent talks to the control plane normally, and
// pinning those would send them out a physical interface that cannot route them at all.
// The test is the dialed host against the host this device enrolled against, which is
// exact and survives the replica rotation that rewrites Client.BaseURL underneath.
//
// It is a deliberate metadata trade. Somebody who chose an exit node for privacy has
// their control-plane connection skip it, so the local network can see they talk to the
// control plane. It applies only on the fallback path — the overlay is preferred and
// stays inside the tunnel — and a recovery path routed through the thing it recovers from
// is not a recovery path. Tailscale makes the same call with its escape-hatch route for
// the exit node's own address.

// SetEscapeHatch makes connections to publicURL bypass the tunnel.
//
// A zero mark or an unparseable URL disables it rather than failing: this is a safety
// net, and a safety net that prevents the agent from starting is worse than the hazard.
// Disabled is also the correct state for the overwhelming majority of hosts, which have
// no exit node and therefore nothing to escape.
func (c *Client) SetEscapeHatch(publicURL string, mark int) {
	host := ""
	if u, err := url.Parse(publicURL); err == nil {
		host = u.Hostname()
	}
	if host == "" {
		c.HTTP.Transport = nil
		return
	}

	d := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, rc syscall.RawConn) error {
			h, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil
			}
			// The address here is already resolved, so compare the name we
			// enrolled against too — a control plane behind a name resolves to
			// something that will not match it.
			if h != host && !sameHost(address, host) {
				return nil
			}
			var opErr error
			if err := rc.Control(func(fd uintptr) { opErr = pinSocket(network, fd, mark) }); err != nil {
				return err
			}
			return opErr
		},
	}

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
	c.HTTP.Transport = t
	c.escapeHost = host
}

// sameHost reports whether a dialled address belongs to the enrolled endpoint.
//
// Dialer.Control sees a resolved IP, while the enrolled endpoint is usually a name, so a
// string compare alone would silently never match and the hatch would be dead code that
// looks installed. Resolving here is cheap: it happens on connections to one host, and
// the OS resolver has just answered the same question.
func sameHost(address, enrolled string) bool {
	h, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ips, err := net.LookupHost(enrolled)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip == h {
			return true
		}
	}
	return false
}
