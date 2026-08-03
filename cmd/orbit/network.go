package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/griffithind/orbit/internal/wire"
)

func networkCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return subUsage("network", "ls   list networks")
	}
	switch args[0] {
	case "ls":
		return networkLs(ctx, args[1:])
	default:
		return unknownSub("network", args[0], "ls")
	}
}

func networkLs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("network ls", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	res, err := o.client.ListNetworks(ctx)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	t := newTable(o.r,
		column{name: "NAME", elastic: true},
		column{name: "CIDRS"},
		column{name: "CURVE", optional: true},
		column{name: "CERT TTL"},
		column{name: "CONFIG", right: true},
		column{name: "BLOCK", right: true},
		column{name: "ID", optional: true},
	)
	for _, n := range res.Value {
		t.add(n.Name, strings.Join(n.CIDRs, ","), n.Curve, n.CertTTL,
			strconv.FormatInt(n.ConfigEpoch, 10),
			strconv.FormatInt(n.BlocklistEpoch, 10), n.ID)
	}
	if t.empty() {
		fmt.Fprintln(errOut, "no networks; run `orbitd bootstrap` on the control plane host")
		return nil
	}
	t.render(out)
	return nil
}

//------------------------------------------------------------------------------
// converge
//------------------------------------------------------------------------------

// convergeCmd reports how much of a network has applied the current epochs.
//
// Top level rather than under `network`, because it is not a property of a
// network the way its CIDRs are: it is the check that gates a CA rotation and
// the thing an operator watches after a block or a decommission. It is typed far
// more often than everything under `network` combined.
func convergeCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("converge", flag.ExitOnError)
	var o options
	o.bind(fs)
	var (
		wait  = fs.Duration("wait", 0, "poll until every host has converged, or give up after this long")
		every = fs.Duration("interval", 5*time.Second, "poll interval while waiting")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}
	networkID, err := o.networkID(ctx)
	if err != nil {
		return err
	}

	res, err := o.client.Convergence(ctx, networkID)
	if err != nil {
		return err
	}

	// One shot: report and stop, exit 0 either way. "Not yet converged" is an
	// observation, not a failure — a fleet is behind for a minute after every
	// change — and a non-zero status here would make `orbit converge` unusable
	// under `set -e` for the reporting it exists to do. -wait is where waiting is
	// asked for, and only that can time out.
	if *wait <= 0 {
		if o.json {
			return emitJSON(res.Raw)
		}
		renderConvergence(o.r, network, res.Value)
		return nil
	}

	deadline := time.Now().Add(*wait)
	ticker := time.NewTicker(*every)
	defer ticker.Stop()

	// progress rewrites one line on a terminal and prints one line per poll
	// otherwise, so a CI log gets a readable history instead of a single line of
	// superimposed carriage returns.
	tty := stderrIsTTY()
	clearProgress := func() {
		if tty {
			fmt.Fprint(errOut, "\r\033[K")
		}
	}

	for {
		if converged(res.Value) {
			clearProgress()
			if o.json {
				return emitJSON(res.Raw)
			}
			renderConvergence(o.r, network, res.Value)
			return nil
		}
		if time.Now().After(deadline) {
			clearProgress()
			if !o.json {
				renderConvergence(o.r, network, res.Value)
			}
			// Non-zero, and not a server error: the request succeeded every
			// time and the fleet simply has not caught up. Exit 1 rather than a
			// class of its own, because the remedy is to look at the hosts named
			// above, which is a local judgement rather than another API call.
			return fail(exitFailure,
				"gave up after %s: %d of %d hosts have applied config epoch %d",
				*wait, res.Value.ConfigApplied, res.Value.HostsTotal, res.Value.ConfigEpoch)
		}

		if !o.json {
			lead, trail := "", "\n"
			if tty {
				lead, trail = "\r\033[K", ""
			}
			fmt.Fprintf(errOut, "%sconfig %d/%d, blocklist %d/%d — waiting (%s left)%s",
				lead,
				res.Value.ConfigApplied, res.Value.HostsTotal,
				res.Value.BlockApplied, res.Value.HostsTotal,
				shortDuration(time.Until(deadline).Round(time.Second)), trail)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		res, err = o.client.Convergence(ctx, networkID)
		if err != nil {
			return err
		}
	}
}

func converged(c wire.ConvergenceResponse) bool {
	return c.HostsTotal > 0 && c.ConfigApplied >= c.HostsTotal && c.BlockApplied >= c.HostsTotal
}

// renderConvergence lays out the same facts internal/api's renderer does, and
// deliberately not by calling it: that one is parsed by
// scripts/check-break-glass.sh's sibling checks and is a compatibility surface.
// The one thing copied outright is "never" for a host that has not reported —
// printing 0001-01-01 makes "never checked in" and "checked in an hour ago" look
// like the same kind of fact, and they are opposite diagnoses.
func renderConvergence(r renderer, network *wire.NetworkResponse, c wire.ConvergenceResponse) {
	pct := func(n int) string {
		if c.HostsTotal == 0 {
			return "  n/a"
		}
		return fmt.Sprintf("%5.1f%%", 100*float64(n)/float64(c.HostsTotal))
	}

	fmt.Fprintf(out, "network    %s\n", network.Name)
	fmt.Fprintf(out, "config     epoch %-8d %4d/%-4d %s\n",
		c.ConfigEpoch, c.ConfigApplied, c.HostsTotal, pct(c.ConfigApplied))
	fmt.Fprintf(out, "blocklist  epoch %-8d %4d/%-4d %s\n",
		c.BlocklistEpoch, c.BlockApplied, c.HostsTotal, pct(c.BlockApplied))

	if len(c.Lagging) == 0 {
		if c.HostsTotal > 0 {
			fmt.Fprintln(out, "\nall hosts converged")
		}
		return
	}

	fmt.Fprintf(out, "\n%d host(s) behind:\n", len(c.Lagging))
	t := newTable(r,
		column{name: "HOST", elastic: true},
		column{name: "CONFIG", right: true},
		column{name: "BLOCKLIST", right: true},
		column{name: "LAST SEEN"},
	)
	for _, l := range c.Lagging {
		t.add(l.Name,
			strconv.FormatInt(l.AppliedConfigEpoch, 10),
			strconv.FormatInt(l.AppliedBlocklistEpoch, 10),
			ago(l.LastSeenAt))
	}
	t.render(out)

	// The operational consequence, not left to be inferred from two numbers.
	// This is the check that gates CA rotation and the cost of skipping it is
	// partitioning hosts off the mesh.
	fmt.Fprintln(out, "\nrotating a CA past these hosts will cut them off")
}
