package hostcfg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Policy routing: the half of listen.so_mark that nebula does not do.
//
// so_mark stamps nebula's own UDP and stops there — nebula's own documentation says the
// mark "enables IP rule-based filtering", and the rule is left to whoever deployed it.
// Nothing in Orbit installed one, so on a host using an exit node the mark was set and
// unread, which is indistinguishable from not setting it. Nebula puts unsafe routes in
// RT_TABLE_MAIN (overlay/tun_linux.go), the same table its own sends are routed by, so its
// UDP matched the exit route and the tunnel carried the packets that carry the tunnel.
//
// The fix is two objects: a table holding the way out, and a rule sending marked packets
// to it. Both are ours, both are named by constants below, and both are removed by name —
// the same ownership rule as the nftables table, for the same reason. Nothing is added to
// a table or a priority anything else writes to.
//
// WHY NOT wg-quick's TRICK. wg-quick needs no copy of the physical default: it puts the
// TUNNEL default in its own table and adds `ip rule not fwmark X lookup <that table>`,
// leaving main untouched as the escape hatch. That needs control over which table the
// tunnel route lands in, and nebula hardcodes main. So the shape has to be inverted —
// our table holds the physical default and the rule is `fwmark X lookup <ours>`.
//
// The cost of the inversion is that our copy goes stale when the machine roams. That is
// what the reconcile loop is for: `ip route replace` is atomic, so refreshing it never
// opens a window where the rule points at nothing.
const (
	// routeTable and rulePriority are the two objects Orbit owns here. Both are
	// removed by name, so removal needs no memory of what was put in them.
	routeTable   = 4242
	rulePriority = 4242
)

// applyPolicyRoute makes the marked-traffic escape hatch true, or removes it.
//
// A zero mark removes rather than errors. That is the config saying this host has no exit
// node, and the rule would then divert nothing while still being a thing on the machine.
func applyPolicyRoute(h HostState) error {
	if !h.ExitNode || h.SoMark == 0 {
		return removePolicyRoute()
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("this host uses an exit node but has no ip binary "+
			"(iproute2), so nebula's own traffic cannot be kept out of the tunnel: %w", err)
	}

	var installed int
	for _, fam := range []string{"-4", "-6"} {
		gw, dev, err := physicalDefault(fam, h.TunDev)
		if err != nil {
			return err
		}
		if dev == "" {
			// No physical default in this family. Not an error: a v4-only
			// machine has no v6 way out, and inventing one would be worse.
			continue
		}

		// replace, not add: atomic, idempotent, and it never leaves the table
		// empty in between, which is when the loop would happen.
		if err := ip(fam, "route", "replace", "default", "via", gw, "dev", dev,
			"table", strconv.Itoa(routeTable)); err != nil {
			return err
		}

		mark := fmt.Sprintf("%#x", h.SoMark)
		want := fmt.Sprintf("fwmark %s lookup %d", mark, routeTable)
		have, err := ipOut(fam, "rule", "show", "priority", strconv.Itoa(rulePriority))
		if err != nil {
			return err
		}
		if strings.Contains(have, want) {
			installed++
			continue // already correct; do not churn the rule every cycle
		}
		// Only when it is wrong or missing. Deleting first would open a window
		// with no rule, and a window with no rule is a window where nebula's
		// own UDP goes into the tunnel.
		if strings.TrimSpace(have) != "" {
			if err := ip(fam, "rule", "del", "priority", strconv.Itoa(rulePriority)); err != nil {
				return err
			}
		}
		if err := ip(fam, "rule", "add", "fwmark", mark,
			"lookup", strconv.Itoa(routeTable), "priority", strconv.Itoa(rulePriority)); err != nil {
			return err
		}
		installed++
	}

	if installed == 0 {
		return fmt.Errorf("this host uses an exit node but has no physical default route " +
			"to send nebula's own traffic out of; every default route leads back into a tunnel")
	}
	return nil
}

// removePolicyRoute takes both objects away, in both families.
//
// Errors are ignored on purpose: `ip rule del` on a rule that is not there and `ip route
// flush` on an empty table both fail, and both mean the desired state. This is the
// uninstall path, where refusing to finish because something was already gone is the
// wrong answer.
func removePolicyRoute() error {
	if _, err := exec.LookPath("ip"); err != nil {
		return nil
	}
	for _, fam := range []string{"-4", "-6"} {
		// A loop, because a previous crash between del and add could have left
		// more than one rule at this priority. Bounded so a kernel that never
		// stops reporting them cannot hang the agent.
		for i := 0; i < 4; i++ {
			if err := ip(fam, "rule", "del", "priority", strconv.Itoa(rulePriority)); err != nil {
				break
			}
		}
		_ = ip(fam, "route", "flush", "table", strconv.Itoa(routeTable))
	}
	return nil
}

// physicalDefault finds the way out of this machine that is not a tunnel.
//
// The rendered exit route is 0.0.0.0/1 + 128.0.0.0/1 rather than 0.0.0.0/0 (see
// nebulacfg.splitDefault), which has a useful consequence here: `ip route show default`
// still shows only the real default, because the halves are not default routes. The tun
// check is belt and braces for a machine running some other VPN that was less careful.
func physicalDefault(family, tunDev string) (gw string, dev string, err error) {
	out, err := ipOut(family, "-j", "route", "show", "default")
	if err != nil {
		return "", "", err
	}
	var routes []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if err := json.Unmarshal([]byte(out), &routes); err != nil {
		return "", "", fmt.Errorf("read the default route: %w", err)
	}
	for _, r := range routes {
		if r.Dev == "" || r.Dev == tunDev || r.Gateway == "" {
			continue
		}
		return r.Gateway, r.Dev, nil
	}
	return "", "", nil
}

func ip(args ...string) error {
	_, err := ipOut(args...)
	return err
}

func ipOut(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ip %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
