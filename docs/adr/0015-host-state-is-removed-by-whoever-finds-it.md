# ADR-0015: Host state is removed by whoever finds it, not by whoever installed it

**Status:** Accepted
**Date:** 2026-08-12

## Context

A managed host that forwards, masquerades or consumes an exit route acquires state the agent
did not create in its own directory: an `nft table inet orbit`, `net.ipv4.ip_forward=1`, an
`ip rule` and route table at 4242, an interface added to firewalld's `trusted` zone
`--permanent`, a `ufw route allow`. On macOS, a scutil key and `/etc/resolver` entries
(ADR-0013). None of it lives in `/var/lib/orbit`, and all of it outlives the process.

Today the only thing that removes any of it is `orbit uninstall`, on the graceful path. Three
consequences were verified.

**A hard kill leaves the machine forwarding for a mesh it is no longer on.** SIGKILL — OOM
killer, `systemctl kill -s KILL`, power loss, panic — leaves the nftables table and the policy
route in place. `cmd/orbit/agent.go:918-919` already calls this out as "the one uninstall
failure with a security consequence" and then handles it only where the operator asked
politely.

**The firewalld assignment leaks in a way nothing can recover from.** `nftConfigurer.tunDev`
is remembered in memory from the last `Apply` (`hoststate_linux.go:42`). After a crash and
restart on a host that is no longer a gateway, `Remove()` calls `removeForwardAllowed("")`,
which returns `nil` at `forward_linux.go:60-62` without doing anything. The interface stays in
firewalld's `trusted` zone, and because the assignment was written `--permanent`, it survives
reboots. The file's own comment names this as the hole it exists to close.

**`orbit uninstall -network X` is not network-scoped.** Since the move to one shared unit, the
command takes a `-network` and then: calls `plan.Disable()` (`agent.go:908`), which is
`systemctl disable --now orbit-agent` — stopping *every* network's overlay; calls
`hostcfg.NewHostConfigurer(...).Remove()` (`:920`), destroying the shared nftables table and
with it the other networks' forwarding and NAT; and calls `plan.RemoveUnit(len(others) > 0)`,
whose guard is `strings.Contains(filepath.Base(p.Path), "@")` (`service.go:268`). The unit is
`orbit-agent.service` — `const name = "orbit-agent"` at `service.go:95`. There is no `@`. The
guard is dead code, the unit is removed regardless, and it is removed immediately after the
command printed that it "will be left in place" (`:894-895`). The `EnabledInstances` /
`RemoveUnit` machinery is a leftover from the template-unit era, and the messages it drives
are now false. There are no tests for any of it.

One smaller instance of the same shape: `ensureForwardAllowed`'s default branch
(`forward_linux.go:47-56`) carries the comment "Reported rather than silent: an operator who
later installs firewalld needs to know this machine was relying on its absence." The body is
`return nil`. Nothing is reported.

Prior art. Tailscale's answer is one line of control flow:
`cmd/tailscaled/tailscaled.go:517-518` calls `router.CleanUp` and `dns.CleanUp`
**unconditionally at daemon start**, before the `--cleanup` flag is even examined, and
`router_linux.go:1938-1948` cleans *both* iptables and nftables regardless of which backend
this run will use, then sweeps orphaned addresses off the interface. The same cleanup is wired
to `ExecStopPost=` in their unit and to `start_pre()` *and* `stop_post()` in their OpenRC
script. The startup call is the one that matters, because it is the only one that runs after a
kill.

## Decision

**Host state is removed by name, unconditionally, at agent start, before anything is applied.**
The sweep destroys `nft table inet orbit`, deletes the ip rule at priority 4242 and flushes
route table 4242, removes the tun device from firewalld's `trusted` zone and the matching ufw
route rule, and removes the resolver settings of ADR-0013. It tolerates "it was not there" at
every step, and it does not consult any in-memory or on-disk record of what this host
previously installed — that record is exactly what a crash destroys.

Removal by name requires knowing the names, and the names are constants: `TableName`,
`routeTable`, `rulePriority`. The one input the sweep cannot derive is the tun device for the
firewalld and ufw rules; it enumerates the zone's interfaces and removes any that match the
device-name pattern Orbit renders, rather than remembering which one it added.

`ExecStopPost=` is added as well, because a graceful stop should not have to wait for the next
start to tidy up. It is the secondary mechanism, not the primary one.

**`orbit uninstall` splits in two.** A network-scoped form removes one directory and leaves
the service and every shared host resource alone. A host-scoped form stops the service,
performs the sweep above, and removes the unit. The dead `@` guard and the `EnabledInstances`
messaging built on it are deleted rather than repaired, and both paths acquire tests — there
are none today.

**`ensureForwardAllowed` either logs what its comment promises or the comment goes.** The
package has no logger on that path, which is presumably how the divergence happened; that is a
plumbing problem, not a reason to leave a comment asserting behaviour that does not exist.

## Alternatives considered

**Record installed host state in a file and undo it from the record.** Rejected. The file is
state that a crash can leave stale or truncated, and undoing a stale record is worse than
removing a known set of named objects. It also does not help the case that motivated this:
after a crash on a host that is no longer a gateway, the correct action is removal, and a
record written when it *was* a gateway is the only thing that would tell us to — which is
precisely the coupling this decision removes.

**Sweep only when the current configuration says the host is not a gateway.** Rejected: on a
host that is still a gateway the sweep is followed immediately by the reconcile that reinstalls
everything, so the conditional buys nothing and adds a branch that can be wrong.

**Rely on `Restart=always` re-running `reconcileHost`, which replaces the table wholesale.**
This is what happens today and it is why the nftables leak is bounded when the agent comes
back. It does not cover the case the agent comes back *not* being a gateway, does not cover
firewalld or ufw at all, and does not cover the host being decommissioned. Partial coverage
that looks total is how this went unnoticed.

**Leave uninstall as it is and document that it is host-wide.** Rejected because the command
takes a `-network` flag and prints a sentence saying the other networks are unaffected. A flag
that does not scope and a message that is false are not fixed by a note in the manual.

## Consequences

Every agent start now performs a short teardown of state it is usually about to reinstall,
which means a visible gap on restart for gateway hosts: forwarding stops and resumes within
the same reconcile pass. That is a real regression in restart smoothness, taken deliberately in
exchange for the guarantee that a crashed or decommissioned host does not keep forwarding.

Removal by pattern rather than by remembered device name is less precise than what `Remove()`
does today on the graceful path, and it can in principle remove a firewalld assignment for a
device Orbit did not add if someone names an unrelated interface the way Orbit names its own.
The device-name pattern is ours and is rendered by us, so this is narrow, but it is a real
widening of what the agent will delete.

We become committed to every host resource having a name that is a constant in this repository.
That is already true and this makes it load-bearing: adding a host resource whose identity is
derived at runtime from something we do not persist would reintroduce exactly this class of
leak.

What would trigger revisiting: multiple networks configuring host state on one machine. The
resources above are host-global singletons named by constants, so two networks already
overwrite each other once per reconcile; a per-network namespacing scheme would change what
"by name" means and this ADR with it.

## References

- `internal/agent/hostcfg/hoststate_linux.go:42` — `tunDev`, remembered only in memory
- `internal/agent/hostcfg/forward_linux.go:59-62` — `removeForwardAllowed("")` returning `nil`
- `internal/agent/hostcfg/forward_linux.go:47-56` — the report that is not made
- `cmd/orbit/agent.go:894-895, 908, 920` — the message, the shared `Disable`, the shared `Remove`
- `internal/agent/service.go:95, 268` — the fixed unit name and the dead `@` guard
- Tailscale `cmd/tailscaled/tailscaled.go:517-518`, `wgengine/router/osrouter/router_linux.go:1938-1948`
- ADR-0013 (the resolver is restored, not only set) — the DNS half of the same sweep
