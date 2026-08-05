package agent

// The UDP socket nebula sends from, when this host has to be told which way is out.
//
// A host using an exit node installs a default route pointing at the tun. Nebula's own
// UDP then matches that route, goes into the tunnel, is read back as inside traffic,
// matches the same route again and leaves re-encapsulated. The machine loses the mesh and
// the control plane together, so nothing can tell it to stop — it needs somebody at the
// keyboard. Every VPN solves this; they just solve it differently per platform.
//
// LINUX does not use any of this. listen.so_mark plus an ip rule is nebula's own answer
// and it keeps nebula's batched recvmmsg datapath, which is what a gateway pushing real
// traffic wants. The rule lives in the host-state layer beside the nftables table, because
// it is host state: something Orbit installs, owns and removes. See hoststate_linux.go.
//
// DARWIN has neither SO_MARK nor policy routing. Its equivalent is IP_BOUND_IF, a socket
// option, which is why this file exists at all and why nebula.Main needed a
// udp.ListenerFactory before Orbit could reach the socket. Reimplementing the conn costs
// nothing there: nebula's darwin conn already reads one packet at a time and reports
// SupportsMultipleReaders false, so there is no batching to lose.
//
// WHY OWNING THE CONN IS THE POINT, and not just reaching the fd. nebula's Rebind clears
// the interface scope so sends follow the routing table again after a network change —
// correct for an ordinary host, and exactly backwards for one holding a default route,
// which must re-pin to the NEW interface rather than unpin. Rebind is a method on the
// Conn. Supplying the Conn is what lets it mean the right thing.
//
// Pinning is opt-in through the signed config (orbit.exit_node), never inferred locally.
// A host with no exit node gets nebula's own listener and today's behaviour exactly, so
// the blast radius of this file is the set of machines that asked for it.
