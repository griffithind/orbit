package hostcfg

import "log/slog"

// Sweep removes every host object Orbit owns, by name, without being told what
// this machine previously had.
//
// Called unconditionally at agent start, BEFORE any network is configured — and
// that placement is the whole decision. A stop hook cannot run for a process
// that was killed, and SIGKILL is the case: the OOM killer, `systemctl kill -s
// KILL`, a panic, power loss. What such a host kept was an `nft table inet
// orbit` still forwarding and NAT-ing for a mesh it is no longer on — which
// cmd/orbit/agent.go already calls "the one uninstall failure with a security
// consequence" and then handled only where the operator asked politely — and,
// on a Mac, a scutil key naming an overlay resolver that no longer exists,
// which leaves the machine unable to resolve anything at all.
//
// It consults no record of what was installed, because a crash is precisely
// what destroys such a record — and because the correct action after a crash on
// a host that is NO LONGER a gateway is removal, which only a record written
// while it still was would have told us to do.
//
// Tailscale reaches the same conclusion in one line: router.CleanUp and
// dns.CleanUp run at every daemon start, before the state file is opened,
// "because a system was rebooted without shutting down, or tailscaled crashed".
// See docs/adr/0015-host-state-is-removed-by-whoever-finds-it.md.
//
// Errors are logged at debug and never returned. Every step is "remove this if
// it is there", and on the overwhelming majority of hosts none of it is.
func Sweep(log *slog.Logger) { sweepHost(log) }
