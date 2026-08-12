# ADR-0022: Anything that changes what a host renders bumps the config epoch

**Status:** Accepted
**Date:** 2026-08-12

## Context

An agent re-renders only when an epoch has advanced (`internal/enroll/service.go:542-544`).
That makes the epoch bump the single mechanism by which any change reaches the fleet, and it
makes a missing bump indistinguishable from no change at all — silently, fleet-wide, until
something unrelated happens to bump.

The codebase reasons about this coupling carefully in several places and then leaves three
holes, each on a transition whose entire purpose is to change what other hosts render.

**Entering the topology does not bump.** `NetworkTopology` selects on
`state IN ('enrolled','active')` (`internal/store/network.go:965-970`), and `SetHostState` is a
bare `UPDATE orbit.membership SET state = $2` with no bump (`internal/store/host.go:349-357`).
Its `created → enrolled` callers bump nothing. So a newly enrolled lighthouse is absent from
every existing host's `static_host_map` and `lighthouse.hosts` until that host's next renewal —
up to a full `cert_ttl`, 24 hours by default. "Add a second lighthouse for redundancy" appears
to succeed and does nothing for a day.

The asymmetry is stark, because *leaving* the topology is handled and commented:
`DeleteHost` bumps `EpochConfig` with the note that this is "most visibly a lighthouse leaving
`static_host_map`. Without this the fleet keeps dialling a machine that is gone"
(`internal/store/revocation.go:120-122`). `MarkAddressChanged` skips the bump for non-enrolled
hosts on the explicit reasoning that "a host outside those states does not appear in
NetworkTopology" (`internal/store/address.go:388-392`). Both arguments are correct. Neither
covers the entry.

**Blocking does not bump the config epoch.** `BlockHost` calls `nextBlocklistEpoch`
(`revocation.go:37`), which is `BumpEpoch(EpochBlocklist)`, and `SetHostState(...Suspended)`
(`:70`) — never `EpochConfig`. `UnblockHost` likewise (`:177`). `NetworkRoutes` filters
`state IN ('enrolled','active')` (`internal/store/route.go:119`) and so does the name table
(`internal/store/host.go:1073`), so a suspended gateway *would* leave every consumer's
`unsafe_routes` and a suspended host *would* leave the mesh name table — if anything told them
to fetch. Today it propagates only because `State` re-renders when *either* epoch moved
(`enroll/service.go:542-553`). That is a coincidence of the current gate, not a guarantee:
decouple the epochs, or cache the render per config epoch, and suspension silently stops
withdrawing routes and names.

**Blocking a device does not touch the topology at all.** `BlockDevice` sets `blocked_at` and
nothing else (`internal/store/device.go:357-370`), and `NetworkTopology` joins `orbit.device`
with no `blocked_at` predicate. A blocked lighthouse device keeps a valid certificate and stays
in every peer's `static_host_map` — it is not merely still connected, it is still the
authoritative discovery point the control plane is telling every host to dial.
`docs/design-device-identity.md:206` says `orbit device block` "refuses a device everywhere
immediately".

There is a fourth instance, in the reserved-lighthouse flow, where the bump exists but fires at
the wrong moment: `CreateReservedMembership` creates the row in state `created`
(`internal/store/host.go:838`) and then calls `SetDevicePublicAddrs`, which *does* bump
`EpochConfig` (`internal/store/device.go:606-612`) — at the instant the new lighthouse is still
excluded from `NetworkTopology`. Peers fetch that generation, get a config without it, and are
pinned until renewal. A bump at the wrong time is worse than no bump, because it consumes the
one signal that would otherwise arrive later.

## Decision

**Every write that changes any input to `renderFor` bumps the config epoch, in the same
transaction.**

Concretely: `SetHostState` bumps when the transition crosses the
`enrolled|active` boundary in either direction, using the same predicate `MarkAddressChanged`
already tests. `BlockHost` and `UnblockHost` bump `EpochConfig` in addition to the blocklist
epoch. `NetworkTopology` filters `device.blocked_at`, and `BlockDevice`/`UnblockDevice` bump.
The reserved-lighthouse flow bumps on the state transition rather than on the address write, or
in addition to it.

**The rule is stated where it can be enforced, not only where it can be read.** The render's
inputs are enumerable — topology, routes, names, policy, addresses — and each has a store
function that is its only writer. A test asserts that each of those writers bumps
`EpochConfig`, in the same shape as the existing structural tests: read the store package's
AST, find the functions that write the render-input tables, and require a `BumpEpoch` call in
each. That converts "remember to bump" from a review convention into a gate.

## Alternatives considered

**Have the agent re-render on every poll regardless of epoch.** Correct by construction, and it
is what a system without an epoch would do. Rejected: ADR-0011's whole cost model rests on the
epoch gating full-generation renders, and re-rendering N hosts every poll interval is the load
the epoch exists to avoid.

**Compare the rendered generation against the last one served and skip if identical.** This
makes a missing bump harmless rather than requiring every bump to be right. Rejected as the
primary mechanism because it moves the cost from "one query per epoch change" to "a full render
per host per poll" — the same objection — though it is a reasonable *additional* safety net if
render cost ever drops.

**Bump the epoch on every write to any table.** Rejected: audit rows, session touches and
heartbeats are writes that change nothing a host renders, and bumping on them would make the
epoch advance continuously, which is the same as having no epoch.

**Document the transitions that require a manual bump.** Rejected. Three of the four instances
here are in code whose comments already reason correctly about the coupling; the reasoning was
present and the call was still missed. A convention that careful comments did not hold is not
going to be held by a paragraph in a doc.

## Consequences

Enrolling a host now re-renders the fleet, which was not previously true. On a network of any
size that is a real load increase at exactly the moment a new machine joins — the epoch bump
fans out to every host per ADR-0011. Enrollment is rare relative to polling, so this is
acceptable, but it makes "add a hundred hosts" a hundred fleet-wide re-renders unless
enrollment is batched. That is worth knowing before someone scripts a bulk import.

Blocking becomes more expensive and more correct: it already bumps the blocklist epoch, and it
will now also bump the config epoch, so a block is two fan-outs rather than one.

We are committed to the set of render inputs being enumerable and to a test that enumerates
them. Adding a new input to `renderFor` without adding its writer to that test is the failure
this decision is designed to make impossible, and the test is the only part of the decision that
survives contact with a future contributor who has not read this ADR.

What would trigger revisiting: the render becoming cheap enough that content comparison beats
epoch gating. At that point the epoch stops being load-bearing and this ADR is superseded by one
that deletes it.

## References

- `internal/enroll/service.go:542-553` — the poll gate that makes the bump load-bearing
- `internal/store/host.go:349-357` — `SetHostState`, no bump; `:838` — reserved membership in `created`
- `internal/store/network.go:965-970` — the topology predicate, and no `blocked_at` filter
- `internal/store/revocation.go:37, 70, 120-122, 177` — the bump that exists and the three that do not
- `internal/store/address.go:388-392` — the reasoning that is correct for leaving and silent on entering
- `internal/store/device.go:357-370, 606-612` — `BlockDevice`, and the bump at the wrong moment
- `internal/store/route.go:119`, `internal/store/host.go:1073` — the two other state-filtered inputs
- ADR-0003 (revocation terminates live sessions), ADR-0011 (full generations, not deltas)
