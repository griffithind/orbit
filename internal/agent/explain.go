package agent

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/griffithind/orbit/internal/fwmatch"
)

// Explaining whether this host may reach a peer.
//
// The matching itself lives in internal/fwmatch, shared with the control plane
// so that `orbit why <peer>` on a host and `orbit why <src> <dst>` against the
// server cannot give contradictory answers. What is here is everything that
// needs the running agent: our certificate, the hostmap, and the configuration
// nebula is actually loaded with.
//
// # What a local answer cannot know
//
// Our outbound rules are half the story: the peer enforces its own inbound
// rules against our certificate, and nothing on this host can read them. And
// without a tunnel there is no peer certificate here, so any rule selecting by
// group, host or CA cannot be evaluated at all. Both are reported as such
// rather than guessed.

// ExplainRequest is what the caller asked.
type ExplainRequest struct {
	// Peer is an overlay address, or the name of a peer this host currently has
	// a tunnel with. A name is only resolvable through the hostmap, so a peer
	// that has never connected must be named by address — which is exactly the
	// case somebody is usually asking about.
	Peer  string
	Proto string
	Port  string
}

// Explanation is the whole answer, in the three layers that fail independently.
type Explanation struct {
	Network string `json:"network"`
	Peer    string `json:"peer"`
	Proto   string `json:"proto"`
	Port    string `json:"port"`

	// Identity.
	Certificate  *CertStatus `json:"certificate,omitempty"`
	CertExpired  bool        `json:"cert_expired,omitempty"`
	PeerResolved string      `json:"peer_resolved,omitempty"`
	PeerName     string      `json:"peer_name,omitempty"`
	PeerGroups   []string    `json:"peer_groups,omitempty"`
	PeerKnown    bool        `json:"peer_known"`

	// Path.
	Running       bool     `json:"running"`
	Detail        string   `json:"detail,omitempty"`
	TunnelUp      bool     `json:"tunnel_up"`
	Handshaking   bool     `json:"handshaking,omitempty"`
	CurrentRemote string   `json:"current_remote,omitempty"`
	RelaysToMe    []string `json:"relays_to_me,omitempty"`

	// Policy, for the two directions this host can actually answer for.
	Outbound fwmatch.Decision `json:"outbound"`
	Inbound  fwmatch.Decision `json:"inbound"`
}

// Explain answers whether this host may reach a peer, and whether it would
// accept the reply.
//
// It deliberately does NOT return an error for a peer with no tunnel, an
// expired certificate, or a stopped nebula. Every one of those is the answer,
// and failing would deny the caller the diagnosis they asked for.
func Explain(eng *Embedded, layout Layout, req ExplainRequest) (Explanation, error) {
	proto, err := fwmatch.ParseProto(req.Proto)
	if err != nil {
		return Explanation{}, err
	}
	port, err := fwmatch.ParsePort(req.Port)
	if err != nil {
		return Explanation{}, err
	}

	ex := Explanation{
		Network: layout.Network,
		Peer:    req.Peer,
		Proto:   fwmatch.ProtoName(proto),
		Port:    fwmatch.PortRange(port, port),
	}

	// Identity: ours, from disk, because an expired certificate explains
	// everything downstream of it and is invisible from a connectivity test.
	var local netip.Addr
	if cs, err := ReadCertStatus(layout.Paths.Cert); err == nil {
		ex.Certificate = cs
		ex.CertExpired = cs.Expired(nowFunc())
		if len(cs.Networks) > 0 {
			if p, err := netip.ParsePrefix(cs.Networks[0]); err == nil {
				local = p.Addr()
			}
		}
	}

	// Path.
	established, pending, peersErr := eng.Peers()
	if peersErr == nil {
		ex.Running = true
	} else if st, err := eng.Status(context.Background()); err == nil {
		ex.Detail = st.Detail
		if ex.Detail == "" {
			ex.Detail = peersErr.Error()
		}
	}

	peerAddr, matched := resolvePeer(req.Peer, established, pending)
	if !peerAddr.IsValid() {
		return ex, fmt.Errorf("%q is neither an overlay address nor a peer with a tunnel; "+
			"name it by address", req.Peer)
	}
	ex.PeerResolved = peerAddr.String()

	if matched != nil {
		ex.PeerName, ex.PeerGroups = matched.Name, matched.Groups
		ex.CurrentRemote, ex.RelaysToMe = matched.CurrentRemote, matched.RelaysToMe
		ex.PeerKnown = matched.Name != ""
		ex.TunnelUp = containsPeer(established, peerAddr)
		ex.Handshaking = !ex.TunnelUp
	}

	// Policy, from the configuration nebula is loaded with rather than from
	// anything Orbit believes it sent.
	inbound, outbound, err := fwmatch.LoadRules(eng.ConfigArg)
	if err != nil {
		return ex, err
	}
	q := fwmatch.Query{
		PeerAddr:      peerAddr,
		LocalAddr:     local,
		Proto:         proto,
		Port:          port,
		PeerCertKnown: ex.PeerKnown,
		PeerName:      ex.PeerName,
		PeerGroups:    ex.PeerGroups,
	}
	ex.Outbound = fwmatch.Decide(outbound, q)
	ex.Inbound = fwmatch.Decide(inbound, q)
	return ex, nil
}

// nowFunc is a seam for tests that need a certificate to be expired.
var nowFunc = time.Now

// resolvePeer accepts an address or a name, preferring established tunnels.
func resolvePeer(want string, established, pending []Peer) (netip.Addr, *Peer) {
	if addr, err := netip.ParseAddr(want); err == nil {
		for _, set := range [][]Peer{established, pending} {
			for i, p := range set {
				if slices.Contains(p.VpnAddrs, want) {
					return addr, &set[i]
				}
			}
		}
		// A valid address with no tunnel is the ordinary case for the question
		// "why can I not reach this", so it is answerable, not an error.
		return addr, nil
	}

	for _, set := range [][]Peer{established, pending} {
		for i, p := range set {
			if p.Name == want && len(p.VpnAddrs) > 0 {
				addr, err := netip.ParseAddr(p.VpnAddrs[0])
				if err == nil {
					return addr, &set[i]
				}
			}
		}
	}
	return netip.Addr{}, nil
}

func containsPeer(peers []Peer, addr netip.Addr) bool {
	for _, p := range peers {
		if slices.Contains(p.VpnAddrs, addr.String()) {
			return true
		}
	}
	return false
}
