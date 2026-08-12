package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/agent/status"
)

// `orbit status` — what this host is doing, on every network it has joined.
//
// The first diagnostic command. Until it existed the answer to "why is nothing
// working" was "read the logs", which is a poor answer on a host whose problem
// is that it cannot reach the thing that would tell it what is wrong.
//
// It reads a socket the running agent serves rather than the files on disk. The
// distinction is the point: the state file says what was last persisted, and
// the interesting failures — nebula died, the control plane is unreachable,
// this generation was never confirmed — are things only the running process
// knows.

func statusCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fl := bindStatusCmd(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}

	path := status.SocketPath(*fl.root)
	rep, err := status.Fetch(ctx, path)
	if err != nil {
		// The command exists to diagnose a broken host, so its own failure has
		// to be legible: a dial error naming a socket path is not an answer to
		// "is the agent running". This one adds the next step, which the shared
		// handler cannot, because only this command is the one an operator
		// reaches for first.
		if errors.Is(err, status.ErrNoAgent) {
			return fail(exitUnreachable,
				"the orbit agent is not running (nothing is listening on %s)\n\n"+
					"  systemctl status orbit-agent                         # linux\n"+
					"  launchctl print system/com.griffithind.orbit.agent   # macos", path)
		}
		return agentError(err, path)
	}

	if *fl.asJSON {
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		return emitJSON(b)
	}

	printStatus(rep)
	return nil
}

func printStatus(rep status.Report) {
	r := newRenderer()

	started := ""
	if !rep.Started.IsZero() {
		started = ", up " + shortDuration(time.Since(rep.Started))
	}
	fmt.Fprintf(out, "%s %s — %s%s\n",
		r.bold("orbit agent"), rep.Version, plural(len(rep.Networks), "network"), started)

	if len(rep.Networks) == 0 {
		fmt.Fprintf(out, "\nNo joined networks under %s.\n", rep.Root)
		fmt.Fprintln(out, "Join one with `orbit agent install -url … -code … -network …`.")
		return
	}

	for _, n := range rep.Networks {
		fmt.Fprintln(out)
		printNetwork(r, n)
	}
}

func printNetwork(r renderer, n status.NetworkStatus) {
	// A network that never came up is the most important thing on the screen,
	// so it is loud and it carries the reason rather than a status word that
	// sends the reader to the logs for it.
	if !n.Ready {
		fmt.Fprintf(out, "%s  %s\n", r.bold(n.Network), r.ansi("31", "NOT READY"))
		field("error", n.Error)
		field("directory", n.Dir)
		return
	}

	fmt.Fprintf(out, "%s  %s\n", r.bold(n.Network), dataPlane(r, n))

	if c := n.Certificate; c != nil {
		field("address", strings.Join(c.Networks, ", "))
		id := c.Name
		if len(c.Groups) > 0 {
			id += "  groups [" + strings.Join(c.Groups, " ") + "]"
		}
		field("identity", id)
		expiry := "expires " + until(c.NotAfter)
		if c.Expired(time.Now()) {
			expiry = r.ansi("31", "EXPIRED "+until(c.NotAfter))
		}
		field("certificate", expiry)
	} else {
		field("certificate", r.ansi("31", "missing"))
	}

	control := n.ControlURL
	if n.Replicas > 1 {
		control += fmt.Sprintf("  (%d replicas)", n.Replicas)
	}
	field("control", control)
	field("epochs", fmt.Sprintf("config %d, blocklist %d", n.ConfigEpoch, n.BlocklistEpoch))

	poll := ago(&n.LastPoll)
	if n.LastPollError != "" {
		poll = r.ansi("31", poll+" — "+n.LastPollError)
	}
	field("last poll", poll)

	// Only when it is wrong. A clock within tolerance is the normal state and
	// printing it every time would be a line nobody reads — but a clock that is
	// out breaks certificate validation and reports itself as a config problem,
	// so it belongs beside the poll rather than in a command somebody runs after
	// already suspecting it. See ADR-0031.
	if n.ClockSkewed {
		dir := "ahead of"
		if n.ClockSkew < 0 {
			dir = "behind"
		}
		abs := n.ClockSkew
		if abs < 0 {
			abs = -abs
		}
		field("clock", r.ansi("31", fmt.Sprintf(
			"%s %s the control plane — certificates will be refused and it will "+
				"look like a certificate problem; fix NTP", abs, dir)))
	}

	// What the control plane told this machine to do to itself. Printed only
	// when it was told something, so an ordinary member's status is unchanged.
	//
	// These are the instructions most likely to be believed and not true: a
	// route the certificate does not permit, a gateway that is not forwarding, a
	// resolver nothing points at. Showing what ARRIVED, beside the reconcile
	// errors above, is what separates "never sent" from "sent and failed".
	if h := n.Host; h != nil {
		if len(h.Routes) > 0 {
			label := "routes"
			if h.ExitNode {
				label = "routes (exit node)"
			}
			field(label, strings.Join(h.Routes, ", "))
		}
		if h.Forwarding {
			gw := "forwarding"
			if len(h.Masquerade) > 0 {
				gw += ", NAT for " + strings.Join(h.Masquerade, ", ")
			}
			field("gateway", gw)
		}
		if h.Resolver != "" {
			field("resolver", fmt.Sprintf("%s  %s  (%d names)", h.Resolver, h.Domain, h.Names))
		}
	}

	// The stuck states, printed only when true. Each one is a specific
	// condition with a specific remedy, and none is visible from the epochs.
	if !n.DataPlaneDownSince.IsZero() {
		field("data plane", r.ansi("31", "down since "+ago(&n.DataPlaneDownSince)))
		// Named for THIS platform. A dead data plane is the moment somebody
		// reaches for the service manager, and telling a Mac to run systemctl
		// sends them looking for a command that does not exist.
		if restart, statusCmd := agent.ServiceCommands(); restart != "" {
			field("", "restart with: "+restart)
			field("", "logs with:    "+statusCmd)
		}
	}
	if !n.UnconfirmedSince.IsZero() {
		field("unconfirmed", "applied "+ago(&n.UnconfirmedSince)+
			" and the control plane has not been reached since; will revert")
	}
	if n.QuarantinedEpoch != 0 {
		field("quarantined", fmt.Sprintf("config epoch %d broke this host and will not be re-applied",
			n.QuarantinedEpoch))
	}
}

// dataPlane is the headline: is nebula up.
func dataPlane(r renderer, n status.NetworkStatus) string {
	switch {
	case !n.Nebula.Known:
		// Not the same as down. Saying "down" here would report every host
		// with an unobservable supervisor as broken.
		return "nebula state unknown"
	case n.Nebula.Running:
		return r.ansi("32", "nebula running") + "  " + n.Nebula.Instance
	case n.Nebula.Detail != "":
		// Why it stopped, on the same line as the fact that it did. A bound
		// port or a refused configuration is the entire answer, and leaving it
		// in a log line is what made this command necessary.
		return r.ansi("31", "nebula NOT running") + "  " + n.Nebula.Detail
	default:
		return r.ansi("31", "nebula NOT running")
	}
}

// fieldWidth fits the longest label, so the values line up in one column and
// the eye can run down them.
const fieldWidth = 11

func field(label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(out, "  %s  %s\n", pad(label, fieldWidth, true), value)
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// statusCmdFlags are the flags of `orbit statusCmd`, declared here so the
// command tree can register them: completion offers exactly the set the
// command parses, because there is only one declaration of it.
type statusCmdFlags struct {
	root   *string
	asJSON *bool
}

func bindStatusCmd(fs *flag.FlagSet) statusCmdFlags {
	return statusCmdFlags{
		root:   fs.String("root", paths.DefaultRoot, "directory holding one subdirectory per joined network"),
		asJSON: fs.Bool("json", false, "emit the raw report"),
	}
}
