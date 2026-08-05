package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/griffithind/orbit/internal/fwmatch"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/policy"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The bidirectional half of `orbit why`.
//
// A host can answer for its own rules and cannot read its peer's, so
// `orbit why <peer>` on a machine is necessarily one direction of two. The
// control plane holds both compiled rulesets, so it can answer the whole
// question — and nebula enforces outbound on the sender and inbound on the
// receiver, which means a flow passes only if BOTH tables agree.
//
// It says nothing about whether a tunnel is up. That is deliberate: this is
// what the CONFIGURATION means, and the node-local command is what the machine
// is actually doing. Conflating them would produce an answer that is wrong
// whenever a host has not converged, and neither command could be trusted.
//
// The rulesets go back through nebula's own parser (nebulacfg.FirewallYAML into
// fwmatch.LoadRulesFromString) rather than being converted field by field, so
// this and the agent share one matcher and cannot contradict each other.

func (s *Server) handleReachability(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	srcRef, dstRef := q.Get("src"), q.Get("dst")
	if srcRef == "" || dstRef == "" {
		writeErr(w, http.StatusBadRequest, "src and dst are both required")
		return
	}

	proto, err := fwmatch.ParseProto(q.Get("proto"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	port, err := fwmatch.ParsePort(q.Get("port"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	var out wire.ReachabilityResponse
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		net, err := s.resolveNetwork(ctx, tx, r)
		if err != nil {
			return err
		}
		out.Network = net.Slug
		out.Proto = fwmatch.ProtoName(proto)
		out.Port = fwmatch.PortRange(port, port)
		out.FirewallSource = net.FirewallSource

		src, err := resolveCheckHost(ctx, tx, net.ID, srcRef)
		if err != nil {
			return err
		}
		dst, err := resolveCheckHost(ctx, tx, net.ID, dstRef)
		if err != nil {
			return err
		}
		out.Src, out.Dst = *src, *dst

		// A network still on per-role rules has no document to compile. Saying
		// so beats reporting an empty ruleset, which would render as a denial
		// and send an operator to edit a policy that is not in force.
		if net.FirewallSource != store.FirewallSourcePolicy {
			out.Note = "this network's firewall comes from each host's role, not from a " +
				"policy document; there is nothing to compile. `orbit role show` has the rules."
			return nil
		}

		stored, err := tx.GetPolicy(ctx, net.ID)
		switch {
		case errors.Is(err, store.ErrNoPolicy):
			out.Note = "this network has no policy document stored yet"
			return nil
		case err != nil:
			return err
		}
		out.PolicyVersion = stored.Version

		// Parse rather than trust: a stored document that no longer parses is
		// a real state — the schema changed under it — and it must not surface
		// as a denial.
		doc, err := policy.Parse(stored.Document)
		if err != nil {
			return fmt.Errorf("the stored policy document does not parse: %w", err)
		}

		// The same compiler, fleet and management floor as the render path. A
		// verdict computed from anything else is a verdict about a system that
		// does not exist.
		fleet, err := tx.PolicyFleet(ctx, net.ID)
		if err != nil {
			return err
		}
		c := policy.Compiler{
			Fleet:      policy.Snapshot{Members: fleet, CIDRs: net.CIDRs},
			Management: s.managementFloor(ctx, tx, net.ID),
		}

		srcRules, err := compiledRules(c, doc, src.ID)
		if err != nil {
			return err
		}
		dstRules, err := compiledRules(c, doc, dst.ID)
		if err != nil {
			return err
		}

		srcAddr, dstAddr := firstAddr(src.OverlayAddrs), firstAddr(dst.OverlayAddrs)
		if !srcAddr.IsValid() || !dstAddr.IsValid() {
			out.Note = "one of these hosts has no overlay address yet, so no rule can name it"
			return nil
		}

		// src's OUTBOUND judged against dst, and dst's INBOUND judged against
		// src. Both certificates are known here — the control plane issued them
		// — so unlike the node-local command nothing is undecidable.
		out.Outbound = fwmatch.Decide(srcRules.outbound, fwmatch.Query{
			PeerAddr: dstAddr, LocalAddr: srcAddr, Proto: proto, Port: port,
			PeerCertKnown: true, PeerName: dst.Name, PeerGroups: dst.Groups,
		})
		out.Inbound = fwmatch.Decide(dstRules.inbound, fwmatch.Query{
			PeerAddr: srcAddr, LocalAddr: dstAddr, Proto: proto, Port: port,
			PeerCertKnown: true, PeerName: src.Name, PeerGroups: src.Groups,
		})
		out.Allowed = out.Outbound.Allowed && out.Inbound.Allowed

		return nil
	})
	if err != nil {
		if errors.Is(err, errPolicyCheckHostNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, errPolicyWouldNotCompile) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.notFoundOr(w, err, "network")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// tables is one host's rules, as nebula would parse them.
type tables struct{ inbound, outbound []fwmatch.Rule }

// compiledRules compiles one host and hands the result back through nebula's
// parser, so the server matches with exactly the code the agent matches with.
func compiledRules(c policy.Compiler, doc policy.Document, membershipID string) (tables, error) {
	rs, err := c.Membership(doc, membershipID)
	if err != nil {
		return tables{}, fmt.Errorf("%w: %s", errPolicyWouldNotCompile, err.Error())
	}
	yamlDoc, err := nebulacfg.FirewallYAML(nebulacfg.FirewallFromPolicy(rs))
	if err != nil {
		return tables{}, err
	}
	in, out, err := fwmatch.LoadRulesFromString(yamlDoc)
	if err != nil {
		// The compiler produced something nebula will not read. That is a bug
		// worth surfacing loudly here rather than at four hundred hosts.
		return tables{}, fmt.Errorf("compiled rules did not parse: %w", err)
	}
	return tables{inbound: in, outbound: out}, nil
}

func firstAddr(addrs []string) netip.Addr {
	for _, a := range addrs {
		if parsed, err := netip.ParseAddr(a); err == nil {
			return parsed
		}
	}
	return netip.Addr{}
}
