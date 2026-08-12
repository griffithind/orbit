package agent

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/griffithind/orbit/internal/agent/dataplane"
	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/agent/status"
	"github.com/griffithind/orbit/internal/fwmatch"
	fwparse "github.com/griffithind/orbit/internal/fwmatch/parse"
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

// Explain answers whether this host may reach a peer, and whether it would
// accept the reply.
//
// It deliberately does NOT return an error for a peer with no tunnel, an
// expired certificate, or a stopped nebula. Every one of those is the answer,
// and failing would deny the caller the diagnosis they asked for.
func Explain(eng *dataplane.Embedded, layout paths.Layout, req status.ExplainRequest) (status.Explanation, error) {
	proto, err := fwmatch.ParseProto(req.Proto)
	if err != nil {
		return status.Explanation{}, err
	}
	port, err := fwmatch.ParsePort(req.Port)
	if err != nil {
		return status.Explanation{}, err
	}

	ex := status.Explanation{
		Network: layout.Network,
		Peer:    req.Peer,
		Proto:   fwmatch.ProtoName(proto),
		Port:    fwmatch.PortRange(port, port),
	}

	// Identity: ours, from disk, because an expired certificate explains
	// everything downstream of it and is invisible from a connectivity test.
	var local netip.Addr
	var ownNets, unsafeNets []netip.Prefix
	if cs, err := status.ReadCertStatus(layout.Paths.Cert); err == nil {
		ex.Certificate = cs
		ex.CertExpired = cs.Expired(nowFunc())
		if len(cs.Networks) > 0 {
			if p, err := netip.ParsePrefix(cs.Networks[0]); err == nil {
				local = p.Addr()
			}
		}
		ownNets = parsePrefixes(cs.Networks)
		// The routed subnets, because their presence is what decides whether an
		// omitted local_cidr means "any" or "my own addresses" — see
		// fwmatch.localCIDRMatches.
		unsafeNets = parsePrefixes(cs.UnsafeNetworks)
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

	// Policy, from the configuration nebula is actually loaded with rather than
	// from anything Orbit believes it sent — and from the same verified source
	// nebula got, not from the file on disk, or `orbit why` would explain a
	// config that is not running.
	yamlCfg, err := eng.Config()
	if err != nil {
		return ex, err
	}
	inbound, outbound, err := fwparse.LoadRulesFromString(yamlCfg)
	if err != nil {
		return ex, err
	}
	// PeerCAName and PeerCASha are deliberately left empty: the peer table
	// carries a verified certificate's name and groups but not its issuer, so a
	// rule scoped with ca_name or ca_sha is genuinely unevaluable here and
	// fwmatch reports Unknown rather than guessing.
	//
	// That is the honest answer, not a gap to be closed by filling these in with
	// whatever is to hand. Conflating "certificate known" with "issuer known" is
	// exactly what made a ca_sha rule report a false allow.
	q := fwmatch.Query{
		PeerAddr:            peerAddr,
		LocalAddr:           local,
		LocalNetworks:       ownNets,
		LocalUnsafeNetworks: unsafeNets,
		Proto:               proto,
		Port:                port,
		PeerCertKnown:       ex.PeerKnown,
		PeerName:            ex.PeerName,
		PeerGroups:          ex.PeerGroups,
	}
	ex.Outbound = fwmatch.Decide(outbound, q)
	ex.Inbound = fwmatch.Decide(inbound, q)
	return ex, nil
}

// nowFunc is a seam for tests that need a certificate to be expired.
var nowFunc = time.Now

// resolvePeer accepts an address or a name, preferring established tunnels.
func resolvePeer(want string, established, pending []status.Peer) (netip.Addr, *status.Peer) {
	if addr, err := netip.ParseAddr(want); err == nil {
		for _, set := range [][]status.Peer{established, pending} {
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

	for _, set := range [][]status.Peer{established, pending} {
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

func containsPeer(peers []status.Peer, addr netip.Addr) bool {
	for _, p := range peers {
		if slices.Contains(p.VpnAddrs, addr.String()) {
			return true
		}
	}
	return false
}

// parsePrefixes converts a certificate's string prefixes, dropping anything
// unparseable rather than failing the whole explanation: a diagnostic that
// refuses to run because one field is odd is a diagnostic nobody can use.
func parsePrefixes(ss []string) []netip.Prefix {
	if len(ss) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}
