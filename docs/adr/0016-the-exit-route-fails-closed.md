# ADR-0016: The exit route fails closed

**Status:** Accepted
**Date:** 2026-08-12

## Context

A host with an exit route sends its default traffic through another member of the mesh. The
mechanism is deliberately thin: the control plane renders the gateway's `0.0.0.0/0` into the
consumer's `tun.unsafe_routes`, split into `0.0.0.0/1` and `128.0.0.0/1`
(`internal/nebulacfg/render.go:877-886`) so longest-prefix match wins without touching the real
default; nebula installs it. Orbit's own kernel footprint for this is one `ip rule` and one
route table (`internal/agent/hostcfg/policyroute_linux.go`), holding a copy of the physical
default so nebula's own UDP can get out.

The inversion is forced. wg-quick puts the *tunnel* route in its own table and adds
`ip rule not fwmark X lookup <that table>`. Nebula hardcodes `Table: unix.RT_TABLE_MAIN`
(`third_party/nebula/overlay/tun_linux.go:613`), so Orbit cannot put the tunnel route
anywhere else and must invert: mark our own traffic and divert *it* instead.

Four places where the feature currently fails open were verified.

**There is no backstop rule.** Orbit installs exactly one rule, at priority 4242
(`policyroute_linux.go:94-95`), which sends marked packets to table 4242. A marked packet that
finds nothing there falls through to `main` at priority 32766, where `0.0.0.0/1` sits on the
tun — and loops. That is the exact failure the file's header exists to prevent. Tailscale
spends a whole extra rule on this: their pref-5250 rule is `RTN_UNREACHABLE`
(`wgengine/router/osrouter/router_linux.go`, `baseIPRules`), with the comment that packets from
us "should be aborted rather than falling through to the tailscale routes, because that would
create routing loops." Any window in which table 4242 is empty, stale, or points at a
disappeared interface is a window in which the recovery path loops.

**Choosing an exit node leaks the other address family.** `membership.exit_route_id` is a
single `uuid` (`internal/db/migrations/0001_initial.sql:377`), `SetExitRoute` takes one route
id, and `routesFor` renders only that one (`internal/enroll/service.go:942`). A gateway
offering both `0.0.0.0/0` and `::/0` produces two route rows, and the consumer selects exactly
one. On any dual-stack host, "use this exit node" silently means *v4 through the tunnel, v6 in
the clear*. Tailscale refuses the half-advertisement outright — you cannot advertise
`0.0.0.0/0` without `::/0` (`net/netutil/routes.go:70-74`).

**An unrenderable exit route vanishes instead of blocking.** `renderRoutes`
(`render.go:766-769`) does `if len(via) == 0 { continue }`, and `NetworkRoutes` filters
gateways to `state IN ('enrolled','active')`. Suspend the gateway and every consumer quietly
reverts to its local internet, in the clear, with no signal anywhere. Tailscale made the
opposite choice twice and said why both times: they install the `/0` and let it blackhole,
because "we want to avoid leaking traffic at the expense of functionality"
(`ipn/ipnlocal/local.go:6547-6570`), and their auto-mode uses a sentinel node ID specifically
"to install a blackhole route".

**The escape hatch does not cover its own name resolution.**
`internal/agent/escapehatch.go` marks connections to the enrolled public endpoint so the
recovery path stays outside the tunnel. But `Dialer.Control` runs *after* Go has resolved the
address, and the resolver's packets are not marked — so when the exit route is the broken
thing, the lookup goes into the tunnel, fails, and the hatch never fires. `sameHost` even
returns `false` on lookup error, so the failure is silent. Separately, because `Control`
receives a resolved IP while `host` is usually a name, the condition
`h != host && !sameHost(address, host)` calls `net.LookupHost` on **every** dial this
transport makes, including every overlay poll — a blocking lookup in the connect path, over
the tunnel that may be the broken thing. The comment defending it says "it happens on
connections to one host"; it happens on connections to all of them. Tailscale's answer is a
control-supplied dial plan with cached bootstrap addresses
(`control/controlclient/direct.go:367-369`), so the control transport never depends on a
resolver at all.

## Decision

The exit route fails closed at four points.

**A backstop rule.** A second `ip rule` at priority 4243, `type unreachable`, matching the same
fwmark. Marked traffic that table 4242 cannot route is dropped rather than handed to `main`.
Installed and removed with the first rule, and covered by the existing netns test harness.

**Exit routes are a family pair.** Selecting an exit node selects both families from that
gateway, or the control plane refuses the selection and says which family is missing. Whichever
form we take, the invariant is that no host ends up with one family tunnelled and the other
direct without an operator having asked for exactly that.

**An exit route with no renderable gateway blackholes.** When a membership has an
`exit_route_id` whose gateways are all unrenderable, the generation carries an unreachable
default rather than no default, and `orbit status` says so. Losing internet access is a
support call; losing it silently to the clear is an incident nobody opens.

**The recovery path does not depend on the resolver it is recovering around.** The addresses
of the enrolled public endpoint are resolved once — at enrolment, and refreshed on a timer
while the overlay is healthy — and persisted in agent state. The hatch dials those addresses
directly. This removes the per-dial `net.LookupHost` as a side effect, and it is the same
mechanism, not two.

## Alternatives considered

**Make the whole agent HTTP client bypass the tunnel, as Tailscale's `netns` does for every
outbound socket.** Structurally simpler — one choke point, no per-destination test. Rejected
because Orbit's steady-state path is the *overlay* addresses (ADR-0010), and pinning those to a
physical interface would break them outright. Tailscale can be unconditional because their
control plane is never inside the tunnel; ours normally is.

**Drop the escape hatch entirely and rely on the unreachable-guard reverting the generation.**
The guard does work, and it is the backstop of last resort. Rejected because it converts two
independent recovery paths into one path and a timer, which is what
`escapehatch.go:22-25` already argues against.

**Reject `0.0.0.0/0` route rows unless `::/0` exists on the same gateway, at `route add`
time.** This is Tailscale's rule and it is the cheapest version of the family-pair decision.
Kept as the likely implementation, but recorded as an implementation choice rather than the
decision, because it does not help gateways that legitimately have no v6 at all — those need
the consumer to blackhole v6, not to be refused.

**Blackhole by rendering `::/0` and `0.0.0.0/0` to a nonexistent overlay address.** Rejected:
it produces a config nebula will try to use and a peer that never answers, which looks like a
broken gateway rather than a deliberate block. An explicit unreachable route says what it is.

## Consequences

An exit-node host acquires a state it does not have today: reachable-but-blocked. Operators
will see traffic stop with a clear cause instead of silently changing egress, and that is a
support burden we are choosing on purpose.

Persisting the resolved control-plane addresses means the agent holds a cached answer that can
go stale — a control plane that moves while an agent is partitioned will have a stale bootstrap
address until the refresh succeeds. That is the trade ADR-0010 already makes for the replica
list, and the same staleness bound applies.

The backstop rule is a second object in the kernel that Orbit owns and must remove, which
extends ADR-0015's sweep by one line. It also means a bug in Orbit's route table maintenance
now takes the host's internet down instead of looping — a louder failure, deliberately.

What would trigger revisiting: nebula gaining a configurable route table. The whole inversion —
mark our own traffic, divert it, and now block it when diversion fails — exists because
`RT_TABLE_MAIN` is hardcoded. If that becomes a setting, wg-quick's shape becomes available and
this decision is replaced rather than amended.

## References

- `internal/agent/hostcfg/policyroute_linux.go:41, 94-95` — the single rule at priority 4242
- `third_party/nebula/overlay/tun_linux.go:613` — the hardcoded `RT_TABLE_MAIN`
- `internal/nebulacfg/render.go:766-769` — the silent drop; `:877-886` — the `/1` split
- `internal/db/migrations/0001_initial.sql:377` — `exit_route_id`, one row
- `internal/enroll/service.go:942` — only the selected default is rendered
- `internal/agent/escapehatch.go:65-112` — `Control`, and `sameHost`'s per-dial lookup
- Tailscale `wgengine/router/osrouter/router_linux.go` `baseIPRules` — the `RTN_UNREACHABLE` rule
- Tailscale `ipn/ipnlocal/local.go:6547-6570` — blackhole rather than leak
- Tailscale `net/netutil/routes.go:70-74` — refusing a half-advertised default
- ADR-0010 (replica discovery), ADR-0015 (host state removal)
