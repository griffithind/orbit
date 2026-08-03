package api

import (
	"fmt"
	"strings"
	"time"

	"github.com/griffithind/orbit/internal/wire"
)

// renderConvergence formats convergence for a terminal.
//
// Convergence is the number an operator checks before a CA rotation and while
// watching a revocation land. Both happen at a terminal far more often than in
// a browser, and requiring jq for it is a small tax paid constantly.
//
// The lagging list is shown by default rather than behind a flag: "1198/1204"
// says something is wrong, and only the names say what.
func renderConvergence(c *wire.ConvergenceResponse) string {
	var b strings.Builder

	pct := func(n int) string {
		if c.HostsTotal == 0 {
			return "  n/a"
		}
		return fmt.Sprintf("%5.1f%%", 100*float64(n)/float64(c.HostsTotal))
	}

	fmt.Fprintf(&b, "config     epoch %-8d %4d/%-4d %s\n",
		c.ConfigEpoch, c.ConfigApplied, c.HostsTotal, pct(c.ConfigApplied))
	fmt.Fprintf(&b, "blocklist  epoch %-8d %4d/%-4d %s\n",
		c.BlocklistEpoch, c.BlockApplied, c.HostsTotal, pct(c.BlockApplied))

	if len(c.Lagging) == 0 {
		if c.HostsTotal > 0 {
			b.WriteString("\nall hosts converged\n")
		}
		return b.String()
	}

	fmt.Fprintf(&b, "\n%d host(s) behind:\n", len(c.Lagging))
	fmt.Fprintf(&b, "  %-28s %-8s %-10s %s\n", "HOST", "CONFIG", "BLOCKLIST", "LAST SEEN")

	for _, l := range c.Lagging {
		// "never" rather than a zero timestamp: a host that has never reported
		// has a different problem from one that reported an hour ago, and
		// printing 0001-01-01 makes them look the same.
		seen := "never"
		if l.LastSeenAt != nil {
			seen = time.Since(*l.LastSeenAt).Round(time.Second).String() + " ago"
		}
		fmt.Fprintf(&b, "  %-28s %-8d %-10d %s\n",
			truncate(l.Name, 28), l.AppliedConfigEpoch, l.AppliedBlocklistEpoch, seen)
	}

	// State the operational consequence rather than leaving it to be inferred
	// from two numbers. This is the check that gates CA rotation, and the
	// failure mode of skipping it is partitioning hosts off the mesh.
	b.WriteString("\nrotating a CA past these hosts will cut them off\n")
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
