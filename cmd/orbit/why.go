package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/fwmatch"
	"github.com/griffithind/orbit/internal/wire"
)

// `orbit why <peer>` — why this host can or cannot reach another.
//
// Reachability fails in three independent layers, and collapsing them into one
// verdict is what makes the usual answer useless. A certificate that expired an
// hour ago explains everything downstream of it and is invisible to `ping`; a
// missing tunnel and a denying rule look identical from the same test. So all
// three are reported separately, each with a definite answer:
//
//	identity  is our certificate valid, and do we know the peer's
//	path      is there a tunnel, and is it direct or relayed
//	policy    do our rules permit this traffic, and would we accept the reply
//
// What this command CANNOT know is the peer's inbound rules: it enforces them
// against our certificate and nothing on this host can read them. That is
// stated in the output rather than left for an operator to discover by
// experiment. There is no bidirectional command yet — see docs/diagnostics.md
// step 4 — so the output points at the closest thing that exists rather than
// inventing one.

// whyCmd dispatches on the number of operands.
//
//	orbit why <peer>        this host, live: identity, path and our own rules
//	orbit why <src> <dst>   the control plane, authoritative on policy, both ways
//
// One command rather than two because it is one question — "may these two
// talk" — asked from the two places that can answer parts of it. What they
// answer differs and neither substitutes for the other: a host knows whether a
// tunnel is up and cannot read its peer's rules; the server knows both rulesets
// and nothing about whether anybody has converged on them.
func whyCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("why", flag.ExitOnError)
	// The admin options are bound unconditionally so the two-operand form works
	// without a mode flag. -network and -json mean the same thing either way,
	// which is why they can be shared rather than duplicated.
	var o options
	o.bind(fs)
	var (
		root  = fs.String("root", agent.DefaultRoot, "directory holding one subdirectory per joined network (local form)")
		proto = fs.String("proto", "any", "any, tcp, udp or icmp")
		port  = fs.String("port", "any", "destination port, or any")
	)
	// parseFlags, not fs.Parse: this is the only diagnostic command that takes
	// operands, and Go's flag package stops at the first non-flag — so
	// `orbit why 10.42.0.9 -port 443` would silently ignore -port and answer a
	// different question from the one asked.
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	switch fs.NArg() {
	case 1:
		return whyLocal(ctx, fs.Arg(0), *root, o.network, *proto, *port, o.json)
	case 2:
		return whyBetween(ctx, &o, fs.Arg(0), fs.Arg(1), *proto, *port)
	}
	return usageErrorf("usage: orbit why <peer>            [-proto tcp] [-port 443]\n" +
		"       orbit why <src> <dst>      [-proto tcp] [-port 443]\n\n" +
		"With one host, this host answers about itself: its certificate, whether a\n" +
		"tunnel is up, and its own rules. With two, the control plane answers about\n" +
		"both directions from the stored policy.")
}

// whyLocal asks the agent on this machine.
func whyLocal(ctx context.Context, peer, root, network, proto, port string, asJSON bool) error {
	path := agent.SocketPath(root)
	slug, err := resolveNetwork(ctx, path, network)
	if err != nil {
		return err
	}

	ex, err := agent.FetchExplain(ctx, path, slug, agent.ExplainRequest{
		Peer: peer, Proto: proto, Port: port,
	})
	if err != nil {
		if errors.Is(err, agent.ErrBadQuestion) {
			return usageErrorf("%s", strings.TrimPrefix(err.Error(),
				agent.ErrBadQuestion.Error()+": "))
		}
		return agentError(err, path)
	}

	if asJSON {
		b, err := json.MarshalIndent(ex, "", "  ")
		if err != nil {
			return err
		}
		return emitJSON(b)
	}

	printWhy(ex)
	return nil
}

// whyBetween asks the control plane about two hosts.
func whyBetween(ctx context.Context, o *options, src, dst, proto, port string) error {
	if err := o.load(); err != nil {
		return err
	}
	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}
	res, err := o.client.Reachability(ctx, network.Slug, src, dst, proto, port)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}
	printReachability(o.r, res.Value)
	return nil
}

func printReachability(r renderer, v wire.ReachabilityResponse) {
	verdict := r.ansi("31", "DENIED")
	if v.Allowed {
		verdict = r.ansi("32", "ALLOWED")
	}
	fmt.Fprintf(out, "%s → %s   %s/%s   %s\n\n",
		r.bold(v.Src.Name), r.bold(v.Dst.Name), v.Proto, v.Port, verdict)

	// Both halves, always, even when one settles it. Which END denies a flow
	// decides which host's policy an operator has to change, and a single
	// "denied" hides that.
	printDecision(r, "outbound", v.Outbound, "to")
	printDecision(r, "inbound", v.Inbound, "from")

	if v.PolicyVersion > 0 {
		fmt.Fprintf(out, "\n  %s  policy version %d, %s\n",
			pad("source", whyWidth, true), v.PolicyVersion, v.FirewallSource)
	}
	if v.Note != "" {
		fmt.Fprintf(out, "\n%s\n", v.Note)
	}

	// The half the SERVER cannot see, which is the mirror of the local
	// command's caveat and just as important: this is what the configuration
	// means, not what any host is currently running.
	fmt.Fprintf(out, "\nThis is what the stored policy means. Whether either host has applied it,\n"+
		"and whether a tunnel is up, is `orbit status` and `orbit why` on the hosts.\n")
}

func printWhy(ex agent.Explanation) {
	r := newRenderer()

	target := ex.PeerResolved
	if ex.PeerName != "" {
		target += " (" + ex.PeerName + ")"
	}
	fmt.Fprintf(out, "%s → %s   %s/%s\n\n",
		r.bold(ex.Network), r.bold(target), ex.Proto, ex.Port)

	printIdentity(r, ex)
	printPath(r, ex)
	printPolicy(r, ex)

	// The half this host cannot see, stated every time. Saying "allowed" and
	// leaving the other direction to be discovered by experiment is how a
	// diagnostic becomes a source of wrong conclusions.
	//
	// It points at what exists rather than at a bidirectional command, because
	// there is not one: `orbit policy check <file> -host <peer>` compiles a
	// DOCUMENT for one host, so it needs the policy file and an admin token and
	// it answers about that host's rules, not about this pair.
	fmt.Fprintf(out, "\n%s\n",
		"This is one direction of two. The peer enforces its own inbound rules\n"+
			"against this host's certificate and they cannot be read from here; to see\n"+
			"them, run `orbit policy check <file> -host "+peerLabel(ex)+"` where an admin\n"+
			"token is available.")
}

func printIdentity(r renderer, ex agent.Explanation) {
	if c := ex.Certificate; c == nil {
		layer(r, "identity", bad, "no certificate on disk")
	} else if ex.CertExpired {
		layer(r, "identity", bad, fmt.Sprintf("%s — certificate EXPIRED %s", c.Name, until(c.NotAfter)))
	} else {
		id := c.Name
		if len(c.Groups) > 0 {
			id += ", groups [" + strings.Join(c.Groups, " ") + "]"
		}
		layer(r, "identity", good, id+", expires "+until(c.NotAfter))
	}

	if ex.PeerKnown {
		peer := ex.PeerName
		if len(ex.PeerGroups) > 0 {
			peer += ", groups [" + strings.Join(ex.PeerGroups, " ") + "]"
		}
		layer(r, "peer", good, peer)
	} else {
		// Not a failure on its own — it is the normal state for a peer that has
		// never connected — but it bounds what the policy layer can decide.
		layer(r, "peer", warn, "no certificate here; rules selecting by group, "+
			"host or CA cannot be evaluated")
	}
}

func printPath(r renderer, ex agent.Explanation) {
	switch {
	case !ex.Running:
		detail := ex.Detail
		if detail == "" {
			detail = "nebula is not running"
		}
		layer(r, "path", bad, "nebula is not running — "+detail)
	case ex.TunnelUp:
		via := "direct"
		if len(ex.RelaysToMe) > 0 {
			via = "relayed via " + strings.Join(ex.RelaysToMe, ",")
		}
		if ex.CurrentRemote != "" {
			via += " (" + ex.CurrentRemote + ")"
		}
		layer(r, "path", good, "tunnel up, "+via)
	case ex.Handshaking:
		layer(r, "path", warn, "handshaking — no tunnel yet")
	default:
		layer(r, "path", warn, "no tunnel; nebula establishes one on the first packet, "+
			"so this alone does not mean unreachable")
	}
}

func printPolicy(r renderer, ex agent.Explanation) {
	printDecision(r, "outbound", ex.Outbound, "to")
	printDecision(r, "inbound", ex.Inbound, "from")
}

func printDecision(r renderer, label string, d fwmatch.Decision, prep string) {
	switch {
	case d.Allowed:
		layer(r, label, good, "allowed by "+d.Matched[0].Rule.String())
		for _, m := range d.Matched[1:] {
			layer(r, "", good, "also "+m.Rule.String())
		}
	case d.Undecidable:
		layer(r, label, warn, "cannot be decided without the peer's certificate")
	case d.Considered == 0:
		layer(r, label, bad, "no "+label+" rules at all")
	default:
		layer(r, label, bad, fmt.Sprintf("no rule permits this traffic %s this peer", prep))
	}

	// The near misses, which are the useful part of a denial: a rule that
	// reaches this peer on the wrong port is one edit from the answer, and a
	// table with none says the peer is not named anywhere.
	if !d.Allowed && len(d.Near) > 0 {
		fmt.Fprintf(out, "  %s  %s\n", pad("", whyWidth, true),
			fmt.Sprintf("%d rule(s) reach this peer but not this traffic:", len(d.Near)))
		for _, n := range d.Near {
			reason := n.Reason
			if reason != "" {
				reason = "  (" + reason + ")"
			}
			fmt.Fprintf(out, "  %s    %s%s\n", pad("", whyWidth, true), n.Rule, reason)
		}
	}
}

// Verdict markers. Words rather than symbols: a red dot is not something an
// operator can grep a support ticket for.
type mark struct {
	text  string
	color string
}

var (
	good = mark{"OK", "32"}
	warn = mark{"??", "33"}
	bad  = mark{"NO", "31"}
)

const whyWidth = 9

func layer(r renderer, label string, m mark, text string) {
	if label == "" {
		fmt.Fprintf(out, "  %s     %s\n", pad("", whyWidth, true), text)
		return
	}
	fmt.Fprintf(out, "  %s  %s  %s\n", pad(label, whyWidth, true), r.ansi(m.color, m.text), text)
}

// peerLabel is what to call the peer in advice: its name when there is one,
// since that is what the control plane knows it by, and its address otherwise.
func peerLabel(ex agent.Explanation) string {
	if ex.PeerName != "" {
		return ex.PeerName
	}
	return "<peer>"
}
