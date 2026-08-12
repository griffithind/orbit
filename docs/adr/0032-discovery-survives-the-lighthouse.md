# ADR-0032: Discovery survives the lighthouse

**Status:** Accepted
**Date:** 2026-08-12

## Context

Every host is told its lighthouses and relays by the control plane and measures nothing about
them. `NetworkTopology` hands every host every lighthouse and relay in the network, filtered on
membership state, with no limit and no ordering. That is a defensible design for a fleet you own.
It has three consequences that are not.

**There is no endpoint cache, so a lighthouse outage plus any restart is a total discovery
outage.** Nebula persists nothing outside `cmd/nebula-cert`; the hostmap and `hostinfo.remotes`
are memory-only. The only persisted underlay knowledge is `static_host_map`, populated
exclusively from lighthouses. Three cases follow: control plane down with the lighthouse
elsewhere is fine and ADR-0002 covers it; control plane down with the lighthouse co-located — the
documented default — means established tunnels survive but no new pair can find each other; and
the same outage *plus a restart on any host* means that host loses every learned remote and can
reach exactly one thing, the lighthouse that is down. `docs/deployment.md:337-341` covers the
first half honestly and is silent on the restart case, which is the one that turns a blip into an
outage.

Tailscale's `ipn/ipnlocal/netmapcache` exists for exactly this, and says so: start up "using
stale but previously-valid state even if a connection to the control plane is not immediately
available". It persists peers, the DERP map, DNS config and the packet filter, and smuggles the
home relay into the cached self node so it survives restart.

**`punchy.respond` was turned on and the delay that governs it was left at a default that races
nebula's own give-up.** Orbit renders `punch: true` and `respond: true` unconditionally
(`internal/nebulacfg/render.go:671-672`, against nebula's defaults of false for both), and
renders neither `delay`, `respond_delay` nor `target_all_remotes`. `hsTimeout(10, 100ms)` is
`10/2 * (2·100ms + 9·100ms)` = **5500 ms** (`third_party/nebula/handshake_manager.go:645-646`
with the defaults at `:23-24`), and `respond_delay` defaults to **5000 ms**
(`third_party/nebula/punchy.go:131`) — with the responder's clock starting strictly later, since
it is scheduled only on receiving a punch notification via the lighthouse. Under 500 ms, minus
scheduler wakeup and one RTT, for the mechanism to land. The symptom is "slow to connect, works
on the second try", which is precisely the class of complaint nothing in Orbit can diagnose.

Leaving those three keys unrendered also breaks the authoritative-mode contract on exactly the
keys that decide whether a difficult-NAT host connects. `render.go:565-578` argues the rendered
file "is the documentation of what the host is running, and a key that is absent forces a reader
to know nebula's source".

**`orbit netcheck` is not a network check.** It tests the agent socket, DNS resolution of the
control-plane host, a TCP dial, a TLS handshake and clock skew. It sends zero UDP packets,
touches no lighthouse, and knows nothing about the overlay. An operator debugging "these two
hosts never connect" has `orbit peers`, `orbit why` (policy plus a tunnel-up boolean), and
nebula's log. Nebula exposes `CreateTunnel`, `PrintTunnel` and `SetRemoteForTunnel` — the
primitives for forcing a handshake or pinning a remote — and Orbit calls none of them.

Two smaller ones: `is_lighthouse` has a precondition check that the host has a public address and
`is_relay` has none at all; and `ListenHost` is unreachable from the control plane — `renderFor`
never sets it, so every host gets `"::"`, and `listen.host` is not in `protectedOverrides` while
`listen.port` and `tun.dev` are.

## Decision

**Last-known peer endpoints are persisted, and seed `static_host_map` on restart.**
`ControlHostInfo.RemoteAddrs` is already available in-process; writing it to the per-network
directory and reading it back at start is Tailscale's `netmapcache` at a fraction of the scope.
This is the difference between "discovery pauses" and "the mesh cannot rebuild", and it is the
one change here that alters a failure mode rather than a diagnosis.

> **AMENDED 2026-08-13, on attempting it: this cannot be built as written.**
>
> `static_host_map` lives in the SIGNED configuration, and
> `generation/verifyconfig.go:83` compares the installed file to the signed one byte for byte.
> An agent that appends cached endpoints to it has edited a config the control plane vouched
> for, which is the property ADR-0002 and the whole config-integrity path rest on. The key is
> also a protected override (ADR-0033), so it cannot be injected from the other side either.
>
> The in-process route is closed too, in this nebula. `Control.SetRemoteForTunnel` looks the
> peer up in `f.hostMap`, which only holds hosts with an ESTABLISHED tunnel — precisely what a
> cold start does not have — and `Control.CreateTunnel` starts a handshake that asks the
> lighthouse for the remote, which is the thing that is down. There is no primitive for "try
> this peer at this address" before a tunnel exists.
>
> The viable path stays inside the model and is a larger decision than this ADR made: **agents
> report the endpoints they have learned, and the control plane renders them into
> `static_host_map` alongside the lighthouses.** The reporting channel and the render both
> already exist. What is new is what every host is then told — today `static_host_map` carries
> lighthouse addresses, and this would widen it to every peer's underlay address, which is a
> real change in what a compromised host learns about the fleet. That trade belongs in its own
> ADR rather than smuggled in under this one.
>
> Until then the failure stands, and `docs/deployment.md`'s outage section owes the restart case
> the ADR describes: control plane down, lighthouse co-located, and any host restarting loses
> every learned remote.

**`punchy.respond_delay`, `punchy.delay` and `punchy.target_all_remotes` are rendered
explicitly**, with `respond_delay` chosen against `hsTimeout` rather than left to race it, and a
comment naming `handshake_manager.go:645` as the line the value is chosen against — the same
"name the nebula line you mirror" discipline ADR-0014 adopts for predicates.
`target_all_remotes` is decided deliberately for a fleet Orbit makes dual-stack by default.

**`orbit netcheck` grows a UDP leg, or it is renamed for what it checks.** The minimal version —
dial each `static_host_map` entry and report the source address the lighthouse observed —
distinguishes "firewall drops UDP", "wrong advertised port" and "symmetric NAT", which today are
one indistinguishable symptom.

**`is_relay` acquires the precondition `is_lighthouse` already has**, and `listen.host` becomes
either a first-class field or a protected override, since it is currently the only Orbit-owned
listen key an override can reach.

## Alternatives considered

**Measure and choose lighthouses client-side, as Tailscale chooses a DERP region.** The right
long-term shape — latency scoring with hysteresis, per-lighthouse health. Rejected as far larger
than the problem: nebula's lighthouse list is config, not a menu, and the fleet Orbit is built
for has one or two lighthouses that an operator chose deliberately.

**Persist the whole hostmap rather than endpoints.** Rejected: the hostmap holds live
cryptographic session state that must not survive a restart. Endpoints are the durable part and
the only part `static_host_map` can consume.

**Leave punchy at nebula's defaults entirely, including `respond`.** Coherent — it would remove
the race by removing the mechanism. Rejected because `respond` is the setting that rescues
symmetric-NAT hosts, and nebula's own example config says so. Turning it on was right; leaving
its delay unconsidered was not.

**Do nothing about the lighthouse outage and document the restart case.** This is the cheap
option and it should happen regardless — `docs/deployment.md:337-341` needs the sentence either
way. Rejected as sufficient, because the recommended default co-locates the lighthouse with the
control plane, which makes the combined failure the *likely* one rather than a corner.

## Consequences

Persisted endpoints are stale state that can be wrong, and a host seeded with an address a peer
no longer holds will attempt and fail before falling back to the lighthouse. That is a slower
first handshake in exchange for any handshake at all during an outage.

Persisting them also writes peer underlay addresses to disk, which is a small increase in what an
attacker with filesystem access learns — bounded by the fact that the same file already holds
`static_host_map` and the signed generation.

Rendering the punchy keys makes the file longer, against the argument in `render.go:574-578` for
keeping it short and reviewable. These three earn it: they are the keys whose absence changes
whether a host connects.

We are committed to a rendered value for anything that materially changes NAT traversal, which is
a narrower rule than "restate every default" and a wider one than today's.

What would trigger revisiting: nebula gaining endpoint persistence of its own, which would make
the cache redundant and is the natural place for it to live.

## References

- `internal/nebulacfg/render.go:671-672` — `punch` and `respond` on; `:565-578` — the authoritative-mode argument
- `third_party/nebula/handshake_manager.go:23-24, 645-646` — the 5500 ms give-up
- `third_party/nebula/punchy.go:131` — the 5000 ms respond delay
- `internal/store/network.go:953-975` — every lighthouse and relay to every host, unlimited
- `cmd/orbit/netcheck.go:63-196` — what `netcheck` actually checks
- `third_party/nebula/control.go:251, 256, 276, 295` — the diagnostic primitives nothing calls
- Tailscale `ipn/ipnlocal/netmapcache.go:4-6` — the stale-but-valid startup argument
- ADR-0002 (fail static), ADR-0014 (diagnostics report what nebula decided), ADR-0022
