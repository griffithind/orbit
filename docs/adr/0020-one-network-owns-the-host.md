# ADR-0020: Host-global resources have exactly one owner

**Status:** Proposed
**Date:** 2026-08-12

## Context

A host can join more than one network. `orbit join` creates a per-network directory under
`/var/lib/orbit`, and `cmd/orbit/agent.go` runs one `Loop` per joined network, each with its
own nebula process, its own tun device and its own UDP port.

The per-network isolation stops at the process boundary. Each loop is given its own host
configurer and its own resolver:

```go
Host:    hostcfg.NewHostConfigurer(nlog),
DNS:     hostcfg.NewResolver(nlog),
```

(`cmd/orbit/agent.go:721-722`) — but the *resources* those objects manage are host-global
singletons, named by package constants:

| Resource | Name | Where |
|---|---|---|
| nftables table | `orbit` | `hostcfg/hoststate.go:45` |
| route table and ip rule | `4242` | `hostcfg/policyroute_linux.go:41` |
| macOS global resolver | `State:/Network/Service/orbit/DNS` | `hostcfg/dnsapply_darwin.go:36` |
| macOS per-domain resolver | `/etc/resolver/<domain>` | `hostcfg/dnsapply_darwin.go:32` |

`reconcileHost` runs once per loop per cycle (`internal/agent/loop.go:669`), and `Apply` does
not merge — it opens with `destroy table inet orbit` and rebuilds the table entirely from *this*
network's `HostState` (`hostcfg/hoststate_linux.go:103-105`). So on a host where two networks
both configure host state, each reconcile pass destroys the other's rules and installs its own.
They do not converge. They alternate, once per interval, forever, and nothing reports it: each
`Apply` succeeds, because from where it stands it did exactly what it was asked.

The same holds for the policy route on Linux — one table and one rule priority, rewritten by
whichever network reconciled last — and for the macOS global resolver key, which is a single
store entry that one network's `global` setting will hold and the other will overwrite. The
per-domain `/etc/resolver/<domain>` entries are the one case that is naturally safe, because
the domain differs per network.

There is already a preflight for this class of problem. `WarnInstanceCollisions`
(`internal/agent/preflight.go:30-62`) reads every sibling network's config and warns when two
share a `listen.port` or a `tun.dev`. Those are precisely the two resources that **cannot**
silently thrash — a second nebula fails to bind the port or create the device, loudly. The
resources that do thrash silently are not checked.

This is not hypothetical severity. A host that is a gateway for network A and an ordinary
member of network B loses A's forwarding and NAT rules every time B reconciles. If B later
becomes a gateway too, the two alternate: traffic for A works for one interval, then traffic
for B, indefinitely.

## Decision

**Host-global resources have exactly one owning network, and the agent enforces it.**

At startup, the agent elects an owner among the joined networks whose configuration is
non-empty for host state — deterministically, by network slug, so the choice is stable across
restarts and identical on every run. Only the owner's loop calls `Apply` on the host
configurer, and only the owner's `global` DNS setting reaches the macOS store key.

Every non-owning loop whose configuration *wants* host state logs that it is not applying it,
naming the network that holds ownership. This is the part that matters: the current failure is
invisible, and the replacement must be visible even though it is also a refusal. A silent
correct answer and a silent wrong answer look the same to an operator.

`WarnInstanceCollisions` is extended to cover the resources that actually collide — a second
network wanting forwarding, masquerade, an exit route, or global DNS — rather than only the two
that fail loudly on their own.

## Alternatives considered

**Namespace the resources per network: `orbit-<slug>` tables, a route table and rule priority
derived from the slug, a per-network scutil key.** This is the design that makes two gateways on
one host actually work, and it is the right answer if that is a case we intend to support.
Rejected for now because it is a larger change with a real cost — route table numbers and rule
priorities are a small, shared, host-global number space, and deriving them from a slug means
either a hash with collisions to handle or an allocation record that ADR-0015 has just finished
arguing we should not keep. Ownership is the cheaper decision that removes the silent failure,
and it does not foreclose namespacing later.

**Merge the states: union the forwarding and masquerade rules from every network into one
table.** Rejected. The rules are derived from per-network policy, and a union is a policy nobody
wrote — network A's operator would be granting forwarding they did not configure. It also makes
`Apply` non-idempotent with respect to a single network's intent, which is what makes the
current code easy to reason about.

**Refuse to join a second network on a host that configures host state.** Rejected as too
strong: the common case is one gateway network plus one or more ordinary memberships, and that
case works correctly today and should keep working.

**Leave it and document it.** Rejected. The failure is silent, continuous, and produces a host
that intermittently forwards for the wrong network — which is a security-relevant outcome, not
just a correctness one.

## Consequences

A host that is a gateway for two networks stops being a gateway for one of them, and says so.
That is a functional regression against what the code claims to do today and an improvement
against what it actually does, which is to be a gateway for each of them roughly half the time.

Election by slug means adding a network whose slug sorts earlier can move ownership on the next
restart. Deterministic is not the same as stable under configuration change, and an operator
who joins a new network and finds host state has moved will need the log line to explain it.
This is the sharpest cost of the cheap option and it is the main reason namespacing remains on
the table.

We are committed to every host-global resource being enumerable — the table above is the list,
and adding a resource to it means adding it to the election and to the preflight. That is the
same commitment ADR-0015 makes for removal by name, and the two lists must stay the same list.

What would trigger revisiting: a real deployment that needs two gateway networks on one host.
At that point the ownership model is the wrong answer and per-network namespacing is the right
one, and this ADR is superseded rather than amended.

## References

- `cmd/orbit/agent.go:721-722` — a configurer and resolver per network loop
- `internal/agent/loop.go:669` — `reconcileHost` per loop per cycle
- `internal/agent/hostcfg/hoststate_linux.go:103-105` — `destroy table` then rebuild from one network
- `internal/agent/hostcfg/hoststate.go:45`, `policyroute_linux.go:41`, `dnsapply_darwin.go:32,36` — the constants
- `internal/agent/preflight.go:30-62` — the preflight that checks the two safe resources
- ADR-0013 (the resolver is restored, not only set), ADR-0015 (removal by name), ADR-0016
