package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/agent/status"
)

// `orbit peers` — who this host actually has a tunnel with.
//
// The distinction from anything the control plane can tell you is the whole
// point. The control plane knows which hosts SHOULD be able to reach each
// other; only the running data plane knows which ones do. A peer that policy
// permits, that holds a valid certificate, and that this host has never
// completed a handshake with is invisible from the server and obvious here.

func peersCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("peers", flag.ContinueOnError)
	fl := bindPeersCmd(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}

	path := status.SocketPath(*fl.root)
	slug, err := resolveNetwork(ctx, path, *fl.network)
	if err != nil {
		return err
	}

	rep, err := status.FetchPeers(ctx, path, slug)
	if err != nil {
		return agentError(err, path)
	}

	if *fl.asJSON {
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		return emitJSON(b)
	}

	printPeers(rep)
	return nil
}

// resolveNetwork picks the network to report on.
//
// One joined network needs no flag, which is the common host. More than one
// needs the flag and gets told what the choices are, rather than an arbitrary
// pick that would be right half the time and silently wrong the rest.
func resolveNetwork(ctx context.Context, path, want string) (string, error) {
	if want != "" {
		return want, nil
	}

	rep, err := status.Fetch(ctx, path)
	if err != nil {
		return "", agentError(err, path)
	}
	switch len(rep.Networks) {
	case 0:
		return "", fail(exitUsage, "this host has joined no networks")
	case 1:
		return rep.Networks[0].Network, nil
	}

	names := make([]string, 0, len(rep.Networks))
	for _, n := range rep.Networks {
		names = append(names, n.Network)
	}
	return "", fail(exitUsage,
		"this host has joined %d networks; name one with -network: %s",
		len(names), strings.Join(names, ", "))
}

// agentError turns the socket's failures into the message and exit class each
// one deserves.
func agentError(err error, path string) error {
	switch {
	case errors.Is(err, status.ErrNoAgent):
		return fail(exitUnreachable,
			"the orbit agent is not running (nothing is listening on %s)", path)
	case errors.Is(err, status.ErrUnknownNetwork):
		return fail(exitNotFound, "%s\n\nRun `orbit status` for the networks this host has joined.", err)
	}
	return err
}

func printPeers(rep status.PeerReport) {
	r := newRenderer()

	// A stopped data plane is the headline, not a footnote under an empty
	// table: an empty peer list reads as an isolated host, which is a different
	// problem from one whose nebula never started.
	if !rep.Running {
		fmt.Fprintf(out, "%s  %s\n", r.bold(rep.Network), r.ansi("31", "nebula is not running"))
		if rep.Detail != "" {
			fmt.Fprintf(out, "\n  %s\n", rep.Detail)
		}
		fmt.Fprintln(out, "\nThere are no tunnels to report. `orbit status` has the rest.")
		return
	}

	fmt.Fprintf(out, "%s  %s\n\n", r.bold(rep.Network), summarise(rep))

	if len(rep.Established) == 0 {
		fmt.Fprintln(out, "No tunnels. This host has not completed a handshake with anybody.")
	} else {
		t := newTable(r,
			column{name: "NAME", elastic: true},
			column{name: "ADDRESS"},
			column{name: "REMOTE"},
			column{name: "PATH"},
			column{name: "MSGS", right: true, optional: true},
			// EXPIRES, not CERT: the value reads "in 29d", and a column called
			// CERT holding "in 29d" makes a reader work out which it means.
			column{name: "EXPIRES", optional: true},
		)
		for _, p := range rep.Established {
			t.add(
				nameOf(p),
				strings.Join(p.VpnAddrs, " "),
				dash(p.CurrentRemote),
				pathOf(p),
				fmt.Sprint(p.Messages),
				certAge(p),
			)
		}
		t.render(out)
	}

	// Pending is a separate block because it answers a different question, and
	// a peer that is permanently here is a peer that cannot finish a handshake
	// — usually a firewall, a lighthouse that does not know it, or a clock.
	if len(rep.Pending) > 0 {
		fmt.Fprintf(out, "\n%s\n", r.bold("handshaking"))
		for _, p := range rep.Pending {
			// nameOf falls back to the address, so printing both would repeat
			// it — which is the normal case here, since a peer mid-handshake
			// has no verified certificate and therefore no name yet.
			line := nameOf(p)
			if addrs := strings.Join(p.VpnAddrs, " "); p.Name != "" && addrs != "" {
				line = fmt.Sprintf("%-20s %s", p.Name, addrs)
			}
			fmt.Fprintf(out, "  %s\n", line)
		}
	}
}

func summarise(rep status.PeerReport) string {
	s := plural(len(rep.Established), "tunnel")
	var relayed int
	for _, p := range rep.Established {
		if p.Relayed() {
			relayed++
		}
	}
	if relayed > 0 {
		s += fmt.Sprintf(", %d relayed", relayed)
	}
	if n := len(rep.Pending); n > 0 {
		s += fmt.Sprintf(", %d handshaking", n)
	}
	return s
}

// nameOf falls back to the address. A pending entry has no verified
// certificate yet, so it has no name, and a blank first column would make the
// row unreadable.
func nameOf(p status.Peer) string {
	if p.Name != "" {
		return p.Name
	}
	if len(p.VpnAddrs) > 0 {
		return p.VpnAddrs[0]
	}
	return "?"
}

// pathOf says whether traffic is direct or carried by somebody else, which is
// the answer to "why is this link slow".
func pathOf(p status.Peer) string {
	if !p.Relayed() {
		return "direct"
	}
	// Relayed is "no direct remote", which does not guarantee we recorded WHICH
	// relay is carrying it — the two come from different nebula fields. Naming
	// the relay when we know it and saying "relay" when we do not beats printing
	// a trailing space.
	if len(p.RelaysToMe) == 0 {
		return "relay"
	}
	return "relay " + strings.Join(p.RelaysToMe, ",")
}

func certAge(p status.Peer) string {
	if p.CertNotAfter.IsZero() {
		return "—"
	}
	return until(p.CertNotAfter)
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// peersCmdFlags are the flags of `orbit peersCmd`, declared here so the
// command tree can register them: completion offers exactly the set the
// command parses, because there is only one declaration of it.
type peersCmdFlags struct {
	root    *string
	network *string
	asJSON  *bool
}

func bindPeersCmd(fs *flag.FlagSet) peersCmdFlags {
	return peersCmdFlags{
		root:    fs.String("root", paths.DefaultRoot, "directory holding one subdirectory per joined network"),
		network: fs.String("network", "", "which joined network; required only when this host has joined more than one"),
		asJSON:  fs.Bool("json", false, "emit the raw report"),
	}
}
