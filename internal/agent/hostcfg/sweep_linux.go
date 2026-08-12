package hostcfg

import (
	"log/slog"
	"strings"
)

func sweepHost(log *slog.Logger) {
	// The route rules go before the table: the backstop is fail-CLOSED, so
	// leaving it while removing everything else would drop this host's own
	// marked traffic with nothing left to catch it.
	if err := removePolicyRoute(); err != nil && log != nil {
		log.Debug("sweep: policy route", "error", err)
	}
	if err := sweepForwardAllowed(isOrbitTunName); err != nil && log != nil {
		log.Debug("sweep: forward permission", "error", err)
	}
	if err := (&nftConfigurer{}).removeTable(); err != nil && log != nil {
		log.Debug("sweep: nftables table", "error", err)
	}
	sweepDNS(log)
}

// sweepDNS reverts resolved on any link Orbit could have configured.
//
// Linux mostly self-heals here — resolved keeps settings per LINK and the tun
// device dies with the process — but "mostly" is doing work in that sentence:
// a device that outlives the agent, or a second agent that created it, keeps
// the settings. Reverting by name costs one command per matching link.
func sweepDNS(log *slog.Logger) {
	if !hasResolved() {
		return
	}
	out, err := output("resolvectl", "dns")
	if err != nil {
		return
	}
	for line := range strings.SplitSeq(out, "\n") {
		name, _, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		dev, found := strings.CutSuffix(strings.TrimSpace(name), ")")
		if !found {
			continue
		}
		_, d, ok := strings.Cut(dev, "(")
		if !ok || !isOrbitTunName(d) {
			continue
		}
		if err := run("resolvectl", "revert", d); err != nil && log != nil {
			log.Debug("sweep: resolvectl revert", "dev", d, "error", err)
		}
	}
}

// isOrbitTunName reports whether a device name is one Orbit renders.
//
// The pattern, not a remembered value. nebulacfg.TunDevSuggestion derives a
// device from the network slug, and Linux truncates it into a [16]byte, so what
// is on the machine is a prefix of what was asked for. Matching a prefix is
// wider than matching an exact name and narrower than matching everything,
// which is the trade ADR-0015 records: this can in principle remove an
// assignment for a device somebody else named the way Orbit names its own.
func isOrbitTunName(dev string) bool {
	dev = strings.TrimSpace(dev)
	return strings.HasPrefix(dev, "orbit") || strings.HasPrefix(dev, "nebula")
}
