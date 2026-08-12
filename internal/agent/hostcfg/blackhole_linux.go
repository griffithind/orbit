package hostcfg

import (
	"os/exec"
	"strconv"
)

// blackholePrefixes are the two halves of the default route, matching what
// nebulacfg.splitDefault renders.
//
// The halves rather than 0.0.0.0/0, for the same reason the renderer uses them:
// they are more specific than the real default, so longest-prefix match picks
// them without touching it — and removing them puts the machine back exactly,
// with no need to remember what the default was.
var blackholePrefixes = map[string][]string{
	"-4": {"0.0.0.0/1", "128.0.0.0/1"},
	"-6": {"::/1", "8000::/1"},
}

// applyBlackhole makes this host's default traffic fail rather than leave in
// the clear.
//
// The case: the host selected an exit node and the control plane could not
// render a route to it — the gateway is suspended, blocked, or has no usable
// address. Rendering nothing meant the consumer fell back to its own physical
// default, so a machine that chose an exit node for PRIVACY sent its traffic
// out the local network with no signal anywhere.
//
// Installed in the main table, because it is ordinary unmarked traffic that has
// to fail; nebula's own marked traffic still finds table 4242. Removed by name
// like every other host object (ADR-0015), which is what makes the sweep able
// to undo it without knowing it was ever installed.
func applyBlackhole(h HostState) error {
	if _, err := exec.LookPath("ip"); err != nil {
		return nil
	}
	for fam, prefixes := range blackholePrefixes {
		for _, p := range prefixes {
			if !h.ExitNodeBlackhole {
				// `replace` on the way in and `del` on the way out, both
				// tolerant: this runs every reconcile and the common case is
				// that there is nothing here.
				_ = ip(fam, "route", "del", "unreachable", p, "metric",
					strconv.Itoa(blackholeMetric))
				continue
			}
			if err := ip(fam, "route", "replace", "unreachable", p,
				"metric", strconv.Itoa(blackholeMetric)); err != nil {
				return err
			}
		}
	}
	return nil
}

// blackholeMetric keeps these behind anything a real exit route installs.
//
// nebula's unsafe routes go in at the default metric, so a gateway that comes
// back wins on the next reconcile even in the window before these are removed.
// Failing closed must not mean failing stuck.
const blackholeMetric = 4242
