# ADR-0013: The machine's resolver configuration is ours to restore, not only to set

**Status:** Accepted
**Date:** 2026-08-12

## Context

The agent runs a DNS server on the overlay address. It answers mesh names from the rendered
generation and forwards everything else to the machine's real resolvers. A platform applier
then points the OS at it: `resolvectl` on Linux, a `scutil` key plus `/etc/resolver/<domain>`
on macOS. Every other platform gets `ErrDNSUnsupported` and a one-time warning.

Three things are true about the code as written, and each was verified against the source
rather than inferred.

**The Linux applier discards the only argument that decides scope.** `applyDNS` in
`internal/agent/hostcfg/dnsapply_linux.go` takes a `global bool` and names it `_`. It then
issues `resolvectl domain <dev> <domain> ~.` and `resolvectl default-route <dev> yes`
unconditionally. `~.` is systemd-resolved's routing-domain wildcard: it makes this link the
resolver of last resort for every name. So a host that joined a network wanting *split* DNS —
mesh names here, everything else as before — gets its entire query stream sent to Orbit.

**The loop guard cannot fire.** Once resolved is pointed at Orbit, `/etc/resolv.conf` under
resolved contains `127.0.0.53`, resolved's own stub. `systemResolvers()` reads that file. If
the agent restarts and re-reads its upstreams, it adopts the stub, and every forwarded query
goes back to resolved, which routes it to Orbit. The guard against exactly this is
`isOwnResolver`, which consults a `sync.Map` populated at `dns.go:208` with
`d.Listen.Addr().String()` — Orbit's **overlay** address. Resolved never writes that address
into `resolv.conf`. The two sets are disjoint by construction, so the guard has never rejected
anything and cannot. The comment at `dns_linux.go:11-14` asserting that "the exclusion below
is what keeps that from becoming a loop" is false.

**Interception outlives the process on macOS.** `/etc/resolver/<domain>` and the scutil key
`State:/Network/Service/orbit/DNS` (`dnsapply_darwin.go:32-36`) are written to the system and
removed by nothing an operator can invoke. `orbit uninstall` does not remove them: it disables
the service, calls `hostcfg.NewHostConfigurer(...).Remove()` — which is the policy route, the
forward permission and the nftables table, and touches no DNS
(`hostcfg/hoststate_linux.go:132-141`) — and deletes the directory. The only call site of the
resolver's `remove` in the whole tree is the `Empty()` branch of `Apply` (`dns.go:200`), which a
host being uninstalled never reaches. So the interception survives a clean, deliberate,
successful uninstall as well as a crash. A SIGKILL — OOM killer, `systemctl kill -s KILL`, power
loss — leaves them. On an exit-node host that scutil key is the *global* resolver, pointing at
an overlay address that no longer exists, so a hard-killed agent leaves a Mac unable to resolve
anything at all. Linux self-heals here only by accident: `resolvectl` settings hang off the tun
device, and the device dies with the process.

Prior art. Tailscale hit the same class of failure and answered it structurally.
`cmd/tailscaled/tailscaled.go:514-522` runs `dns.CleanUp` and `router.CleanUp`
**unconditionally at every daemon start**, before the state file is opened, with the comment
that this "covers cases such as when a system was rebooted without shutting down, or tailscaled
crashed, and would for example restore system DNS configuration." Their Windows NRPT layer says
it more bluntly (`net/dns/nrpt_windows.go:67-73`): the rules "survive the unclean termination
of the Tailscale process, and depending on the rule, it may prevent us from reaching
login.tailscale.com to boot up" — so the constructor deletes every rule it owns before doing
anything else.

## Decision

Three properties, and each replaces a mechanism that does not currently work.

**Scope is honoured.** `applyDNS` uses its `global` argument. `~.` and `default-route yes` are
issued only when the network actually asked for global DNS; otherwise the link gets the mesh
domain and nothing else, which is the split-DNS behaviour resolved was chosen for.

**The upstream guard tests what the upstream is, not whose address it is.** An upstream is
rejected when it is a loopback address, when it is any address this process is listening on,
or when the platform reports it as belonging to the link Orbit configured. The current
address-identity check is kept as one of the three, not as the whole guard, because it is the
one that can never fire on the platform that needs it most.

**Teardown runs at startup, unconditionally, before anything is applied — and on uninstall.** The agent removes
the resolver settings it knows how to write — `/etc/resolver` entries, the scutil key, the
resolved link configuration — by name, whether or not it believes it installed them, and
whether or not this run intends to reinstall them. A stop hook (`ExecStopPost`) is added too,
but the startup sweep is the part that matters: a stop hook cannot run for a process that was
killed, and that is the case producing the unresolvable Mac. `orbit uninstall` calls the same
sweep, which it does not do today at all — an omission worth naming separately, because it is
the one path where the operator explicitly asked for the machine to be put back.

## Alternatives considered

**Keep the address-identity guard and fix it by recording the stub address too.** Rejected: it
requires the agent to know every address every platform's resolver stack might forward through,
which is a list that grows per platform and per version. Rejecting loopback rejects the whole
class without enumerating it.

**Never point the OS at Orbit; publish mesh names only over the overlay and let operators
configure their own resolvers.** This is what every unsupported platform already gets, and it
is coherent. Rejected because the feature people want from a mesh is that mesh names resolve
without ceremony, and an instruction to edit `resolv.conf` on every host is the ceremony.

**Snapshot the previous resolver configuration to disk and restore from the snapshot.**
Rejected: the snapshot is state that can itself be stale or lost, and restoring a stale
snapshot is worse than removing our own settings and letting the OS fall back to its own
defaults — which is what `resolvectl revert` and deleting `/etc/resolver/<domain>` already do.

**Do the teardown in a signal handler.** Rejected for the reason the whole ADR exists: it does
not run for SIGKILL, and SIGKILL is the case.

## Consequences

Split DNS starts working, which means a host that joins a network stops sending its
unrelated queries — corporate, personal, everything — to the agent. That is a privacy
improvement and a blast-radius reduction, and it is also a behaviour change: any host that
was relying on Orbit resolving public names because `~.` was set unconditionally will
stop, and will need `global` set on its network.

The startup sweep means the agent briefly removes DNS settings it is about to reinstall, so
there is a window on every start where the machine resolves without Orbit. That window is
already there whenever the process restarts; making it explicit makes it bounded and
testable rather than incidental.

We are committed to a teardown implementation per platform that is correct without any
in-memory state — removal by name, tolerating "it was not there". That is the same discipline
`ServicePlan.Disable` already follows, and the same one ADR-0015 applies to host state.

What would make us revisit this: a platform whose resolver settings cannot be removed without
knowing what they replaced. Windows NRPT is close to that, which is one reason ADR-0018 puts
Windows DNS out of the first release.

## References

- `internal/agent/hostcfg/dnsapply_linux.go` — the discarded `global`, the unconditional `~.`
- `internal/agent/hostcfg/dns.go:208` — the guard's write site; `dns_unix.go` — `isOwnResolver`
- `internal/agent/hostcfg/dns_linux.go:11-14` — the comment this ADR contradicts
- `internal/agent/hostcfg/dnsapply_darwin.go:32-36` — the scutil key that survives a kill
- Tailscale `cmd/tailscaled/tailscaled.go:514-522` — unconditional cleanup at daemon start
- Tailscale `net/dns/nrpt_windows.go:67-73` — interception outliving the process, stated plainly
- ADR-0015 (host state is removed by whoever finds it) — the same argument for nftables and routes
