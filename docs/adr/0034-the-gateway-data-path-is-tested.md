# ADR-0034: The gateway data path is tested, not just rendered

**Status:** Proposed
**Date:** 2026-08-12

## Context

Orbit's e2e suite covers gateways thoroughly at the level of *intent*: `e2e/route_test.go` and
`e2e/exitnode_test.go` assert rendered YAML and stored state. **No packet crosses a gateway
anywhere in the suite.** That boundary is exactly where three defects live, and it is why none of
them has been caught.

**Masquerade defaults to off, including for a default route.** `-masquerade` is
`fs.Bool("masquerade", false, …)` (`cmd/orbit/route.go:250`), and the help says it is "usually
wanted for 0.0.0.0/0". So `orbit route add lab-gw 0.0.0.0/0` with no flag produces an exit node
that cannot work — the internet has no route back to an overlay address — with no warning at add
time. Every e2e test passes `Masquerade: true` explicitly, so the default-off path is never
exercised. Tailscale's equivalent defaults to **true** and prints an explicit warning when SNAT
is disabled alongside `--advertise-exit-node` (`cmd/tailscale/cli/up.go:128, 366-370`).

**Per-route NAT is not per-route once a default route exists.** The rule is
`iifname "<tun>" ip daddr <prefix> counter masquerade`
(`internal/agent/hostcfg/hoststate_linux.go:122-123`), matching on destination. A gateway serving
both `0.0.0.0/0` (with NAT) and `192.168.88.0/24` (without) emits `ip daddr 0.0.0.0/0 masquerade`,
which matches the LAN destination too. Every forwarded packet is NATed regardless of the LAN
route's `masquerade: false`. `e2e/exitnode_test.go:83-137` constructs precisely that
configuration and asserts the desired *state* — `state.Masquerade == ["0.0.0.0/0"]` — rather than
the resulting kernel behaviour.

**Nothing clamps TCP MSS, and the per-route MTU knob can raise the device MTU fleet-wide.** Orbit
always renders `tun.mtu: 1300`; `Input.TunMTU` has no caller outside the renderer. A grep of
`internal/` and `cmd/` for `mss` or `clamp` returns only certificate-validity matches, and the
nft script contains one NAT chain and no mangle chain. Nebula sets `AdvMSS` only when a route's
MTU differs from the device MTU, which with Orbit's defaults it never does — so no `advmss` on
the unsafe route either. Forwarded traffic therefore depends entirely on the kernel generating
ICMP Frag Needed on the tun, which Orbit neither installs nor blocks: classic subnet-router
breakage, unmitigated, whenever that ICMP is filtered upstream. And the knob that looks like the
fix is worse than absent: the schema allows 576–9000, and nebula's reload does
`if r.MTU > t.MaxMTU { newMaxMTU = r.MTU }` then `setMTU()`
(`third_party/nebula/overlay/tun_linux.go:360-382`), so `orbit route add -mtu 9000` raises the
whole **tun device** MTU to 9000 on every consumer of that prefix. Route MTU is also honoured on
Linux only — every other platform passes `allowMTU = false` and logs "route MTU is not supported
on this platform" — and `orbit route add -mtu`'s help says only "per-route MTU; 0 uses the tun's".

Tailscale clamps, in a dedicated `ts-clamp` base chain, to `tun MTU - 40`, in **both**
directions, with the reasoning spelled out: clamping only the output direction black-holes large
segments when PMTUD is broken (`util/linuxfw/nftables_runner.go:249-300`).

Two rendered knobs have no test at all. `-no-install` renders `install: false`, whose real effect
is that nebula skips the system route but still inserts the prefix in `routeTree` — so the host
forwards packets that arrive for it but never sends any there, an inert route unless an operator
installs one by hand. Nothing in Orbit documents that, and no test covers it. Under ADR-0006's
rule these are two CLI flags whose effects nothing in the repository demonstrates.

## Decision

**A netns two-host forwarding test exists, and it is the gate.** The harness already exists for
`policyroute_linux_test.go`. One test that pushes a packet from a consumer through a gateway to a
destination catches all three defects above at once, and it is the only thing that would have
caught any of them — every one of them renders correctly.

**The gateway clamps MSS on forwarded TCP**, in Orbit's own nft table, in both directions. Orbit
already owns a whole table, so this costs one chain and introduces no new ownership question
(ADR-0015's removal-by-name rule already covers the table).

**Masquerade defaults to true for a default route**, or `route add` refuses `0.0.0.0/0` without
it and says why. And the NAT rule for a default route is scoped so it cannot swallow a sibling
prefix that asked for no NAT — an ordered `return` ahead of it, or an explicit destination
exclusion.

**The per-route MTU is bounded by the tun MTU at `route add`**, and `-mtu` warns or refuses for a
network whose consumers are not all Linux — per ADR-0017's rule that a platform we tag for is a
platform we check, a flag that silently does nothing on three of four platforms is the same class
of problem.

**Each remaining rendered knob gets a test that shows what it does, or it leaves the CLI.**
`-no-install` is the immediate case.

## Alternatives considered

**Assert the generated nft ruleset as a string rather than running packets.** Cheaper, and it
would catch the `daddr 0.0.0.0/0` overlap. Rejected as the primary mechanism: it would not have
caught the MSS gap, which is an absence rather than a wrong rule, and it pins the implementation
rather than the behaviour — the existing tests already assert intent and that is exactly what let
these through.

**Set `AdvMSS` on the unsafe route instead of clamping.** Cleaner in principle, and nebula
supports it. Rejected because it only advises the *local* stack's route, so it does nothing for
traffic the gateway forwards on behalf of someone else — which is the case that breaks.

**Leave masquerade defaulting to false and document it harder.** Rejected: the help text already
says "usually wanted for 0.0.0.0/0", and a default that is wrong for the usual case with a note
saying so is a default chosen against its own documentation.

**Raise `tun.mtu` from 1300 instead of clamping.** Rejected as orthogonal — a higher tun MTU
moves the threshold, and PMTUD is still what has to work at the new one.

## Consequences

A netns forwarding test is Linux-only and root-requiring, like `policyroute_linux_test.go`. It
runs in CI and is skipped on a developer Mac, which means the platform where most development
happens does not run the test that guards the platform where gateways exist. That is already true
of the existing netns test and is worth stating rather than discovering.

Defaulting masquerade to true for `/0` changes behaviour for any existing default route created
without the flag — from broken to working, but a change nonetheless, and one that starts
rewriting source addresses on a machine where it previously did not.

Clamping MSS makes Orbit modify forwarded packets, which it has not done before. It is a
well-understood transformation and it is what every subnet router does, and it is still a new
class of thing for the agent to do.

We are committed to no rendered knob shipping without a test that demonstrates it. That is
ADR-0006's rule applied one level up: reachable code that nothing exercises is a weaker version
of the same problem.

## References

- `cmd/orbit/route.go:250` — masquerade defaulting false; `:253-255` — `-no-install`, `-mtu`
- `internal/agent/hostcfg/hoststate_linux.go:118-123` — the destination-matched NAT rule
- `internal/nebulacfg/render.go:581, 599-601, 771-777` — `tun.mtu` 1300, route MTU, `install`
- `third_party/nebula/overlay/tun_linux.go:360-382, 718-728` — MTU escalation, and `AdvMSS`
- `third_party/nebula/overlay/route.go:54-58` — "route MTU is not supported on this platform"
- `e2e/exitnode_test.go:83-137` — the configuration that exhibits the NAT overlap, asserted as state
- Tailscale `util/linuxfw/nftables_runner.go:249-300` — `ClampMSSToPMTU`, both directions
- Tailscale `cmd/tailscale/cli/up.go:128, 366-370` — SNAT on by default, with a warning
- ADR-0006 (code must be reachable), ADR-0015, ADR-0016, ADR-0017
