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
// Steady-state traffic goes to AgentURLs, the control plane's OVERLAY addresses. Recovery
// goes to BaseURL, the public endpoint it enrolled against — not automatically, because
// the public listener mounts no agent routes, but as `orbit agent enroll` with a fresh
// code. That is the path this file exists to keep reachable.
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
func (c *Client) SetEscapeHatch(publicURL string, mark int, known []string) {
	host := ""
	if u, err := url.Parse(publicURL); err == nil {
		host = u.Hostname()
	}
	if host == "" {
		c.HTTP.Transport = nil
		return
	}

	// The addresses this endpoint was last seen at, learned while the overlay
	// was healthy and persisted in agent state.
	//
	// THE POINT IS TO NOT RESOLVE HERE. Dialer.Control runs after Go has already
	// resolved the address, and the resolver's own packets carry no mark — so on
	// a host whose exit route is the broken thing, the lookup goes into the
	// tunnel and fails, sameHost returns false on the error, and the hatch never
	// fires. It was dead in exactly the situation it exists for.
	//
	// A cached answer can be stale. A recovery path that depends on the thing it
	// is recovering from cannot work at all. See ADR-0016.
	c.escapeAddrs = append([]string(nil), known...)

	d := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, rc syscall.RawConn) error {
			h, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil
			}
			// The address here is already resolved, so compare against the
			// addresses this endpoint was last seen at — a control plane behind
			// a name never matches the name itself.
			if h != host && !c.knownAddr(h) {
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

// knownAddr reports whether a dialled address is one the enrolled endpoint was
// last seen at.
//
// This replaced a net.LookupHost per dial. Because Dialer.Control receives an
// address that is ALREADY resolved while the enrolled endpoint is usually a
// name, the old comparison never matched on the first term and fell through to
// a resolver call on every connection this transport made — including every
// steady-state overlay poll, whose destination is not the escape host at all.
// The comment defending it said "it happens on connections to one host"; it
// happened on connections to all of them, blocking, inside the connect path.
func (c *Client) knownAddr(h string) bool {
	for _, a := range c.escapeAddrs {
		if a == h {
			return true
		}
	}
	return false
}
