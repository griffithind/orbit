package hostcfg

import "log/slog"

// On macOS the DNS interception is the whole of it: there is no nftables table
// and no policy route, because hoststate_other.go refuses gateway state here.
//
// And it is the platform where the sweep matters most. /etc/resolver/<domain>
// and the scutil key survive any termination, graceful or not, and on an
// exit-node host that key is the GLOBAL resolver — pointing at an overlay
// address that no longer exists. A hard-killed agent left a Mac unable to
// resolve anything at all, which is precisely the case Tailscale's comment
// names when it says cleanup "would for example restore system DNS
// configuration".
func sweepHost(log *slog.Logger) {
	if err := removeGlobalDNS(); err != nil && log != nil {
		log.Debug("sweep: global resolver", "error", err)
	}
	if err := sweepResolverDir(); err != nil && log != nil {
		log.Debug("sweep: /etc/resolver", "error", err)
	}
}
