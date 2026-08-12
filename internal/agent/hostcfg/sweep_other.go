//go:build !linux && !darwin

package hostcfg

import "log/slog"

// Nothing to sweep where nothing can be applied: applyDNS returns
// ErrDNSUnsupported and the host configurer refuses any non-empty state, so no
// object of Orbit's outlives the process here.
func sweepHost(*slog.Logger) {}
