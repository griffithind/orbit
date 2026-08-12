# ADR-0010: Every agent response carries the replica list

**Status:** Accepted
**Date:** 2026-08-11

## Context

ADR-0009 records the gap and leaves it open: "adding a replica reaches existing agents only at
renewal, because `StateResponse` carries no endpoint list." This ADR closes it.

**The mechanics, precisely.** `EnrollResponse.AgentEndpoints` (`internal/wire/wire.go:55-62`) is
populated on enrol, join and renew (`internal/enroll/service.go:280,422`,
`internal/enroll/join.go:445`) from `agentEndpoints`, which reads the live registry with a
3-minute staleness window (`internal/enroll/service.go:352,378-394`). The agent adopts it in
`doRenew` (`internal/agent/loop.go:861`) through `adoptEndpoints` → `State.SetAgentURLs`
(`internal/agent/loop.go:634-641`, `:187-204`), which preserves the in-use endpoint's index so a
list change does not herd the fleet onto replica 0. `StateResponse` (`internal/wire/wire.go:84-151`)
has no such field, and neither `poll` (`internal/agent/loop.go:870-887`) nor `watchOnce`
(`internal/agent/loop.go:1148-1160`) calls `adoptEndpoints`. Renewal is at the midpoint of
`CertTTL`, so at the 24-hour default an agent learns about a replica added one minute after its
last renewal roughly 12 hours later.

**The delay is not only latency, it is the wrong direction.** A new replica takes enrolment traffic
immediately, over the public listener, and steady-state agent traffic half a certificate lifetime
later. The reason an operator adds a replica — load, or a replica that is failing — is exactly the
condition in which twelve hours of nothing is the wrong answer.

**There is a second half, and shipping only the first half would be a defect.** The compiled
policy's management floor emits one outbound rule per live replica address
(`internal/policy/compile.go:352-367`), read from the same registry query
(`internal/enroll/service.go:1019-1034`). In `ModeAuthoritative` with a policy, Orbit drops its own
allow-all outbound and renders both halves of every allowance, which is why that floor "is not
optional" (`internal/nebulacfg/policy.go:20-43`). So on a policy network in authoritative mode, a
host whose installed generation predates the new replica has no outbound rule for it: telling that
host the new endpoint without also moving its configuration hands it an address its own firewall
drops. Networks with no compiled policy, and networks in `ModeFragment`, keep the allow-all
(`internal/nebulacfg/render.go:349`) and are unaffected. Today the two gaps heal together, because
renewal re-renders the configuration from the current floor in the same response that carries the
endpoint list.

**Nothing bumps the config epoch when a replica appears.** `Tx.RegisterControlPlane`
(`internal/store/network.go:1028-1041`) is an upsert on `(network_id, addr)` and calls no
`BumpEpoch`; `Store.Register` wraps it in a bare transaction (`internal/store/lookup.go:186-194`).
Every other thing that changes a rendered configuration does bump — policy
(`internal/store/policy.go:276,333`), routes (`internal/store/route.go:67,92,280`), addresses
(`internal/store/address.go:404`), host state (`internal/store/host.go:955,993`) — and the bump is
what drives push, because `pg_notify` rides the same transaction (`internal/store/store.go:302-317`)
and reaches watchers on every replica (`internal/notify/notify.go:148-189`).

**Prior art: how Tailscale tells a running node that its infrastructure moved.** Two fields on the
same response do this. `MapResponse.DERPMap` carries the relay set
(`tailcfg/tailcfg.go:2024-2026`); `MapResponse.ControlDialPlan` carries candidate addresses for the
control plane itself (`tailcfg/tailcfg.go:2177-2180`, `2311-2345`), which is the closer analogue to
`agent_endpoints`. Four facts about how they are delivered are worth having exactly right:

1. *It is one connection, not one response per poll.* The client sets `MapRequest.Stream`
   (`control/controlclient/direct.go:1136`) and then reads repeatedly from the same response body:
   a 4-byte little-endian length prefix followed by a zstd frame, in a loop that only terminates
   when the connection does (`control/controlclient/direct.go:1300-1322`). Liveness is a
   `{"KeepAlive":true}` message about once a minute against a 120-second client watchdog
   (`control/controlclient/direct.go:1051-1055`, `:1484`), and the client caches that message's
   compressed bytes to skip decoding it (`:1487-1493`).
2. *Within that stream, the first response is complete and the rest are incremental.* "The first
   MapResponse will be complete and subsequent MapResponses will be incremental updates with only
   changed information" (`tailcfg/tailcfg.go:1971-1974`). The client enforces it: a first
   non-keepalive message without `Node` is a protocol error
   (`control/controlclient/direct.go:1388-1392`).
3. *The "unchanged" encoding is the zero value, and it is not a patch.* "The zero value for all
   fields means unchanged" (`tailcfg/tailcfg.go:1976`). A nil `DERPMap` means unchanged; a non-nil
   one is a **full replacement** of `Regions`, not a diff — the only carry-forward is at the
   sub-field level, where a nil `Regions` or nil `HomeParams` inside a non-nil `DERPMap` inherits
   the previous value (`tailcfg/derpmap.go:17-34`, `control/controlclient/map.go:659-677`).
   Genuine patch encodings exist alongside it and are separate fields with separate rules:
   `PeersChanged`/`PeersRemoved`/`PeersChangedPatch`, and `PacketFilters` keyed by name with `"*"`
   meaning clear (`tailcfg/tailcfg.go:2036-2051`, `2094-2116`).
4. *It costs client-side session state, a resume protocol, and a documented wart.* The client keeps
   `lastDERPMap`, `lastDNSConfig`, `lastNode` and a dozen more for the life of the one HTTP response
   (`control/controlclient/map.go:87-105`) and rebuilds the full netmap from them each time
   (`control/controlclient/map.go:1270`). Resuming a broken stream needs `MapSessionHandle` plus a
   `Seq` (`tailcfg/tailcfg.go:1455-1472`, `1987-1999`). And the encoding cannot express "explicitly
   empty now" for the slice-typed fields, so the control plane marshals with a different type than
   the one the client unmarshals with (`tailcfg/tailcfg.go:1976-1985`).

One more Tailscale detail is relevant to the failure path rather than the encoding: the dial plan is
held in memory only (`control/controlclient/direct.go:1356-1362`, `:1719-1720`), but the DERP map is
written to `derpmap.cached.json` on every change (`ipn/ipnlocal/local.go:2075`,
`net/dnsfallback/dnsfallback.go:233-257`, `cmd/tailscaled/tailscaled.go:728`) so a cold client can
still bootstrap. Orbit already persists `AgentURLs` for the same reason
(`internal/agent/loop.go:63-67`).

**The numbers this decision trades in.** A steady-state Orbit watch response — hold expired, nothing
new — is about 160 bytes of JSON: two epochs, `restart_required_epoch`, `network_slug`, and the two
certificate timestamps. Three replicas as `http://10.42.0.N:8446` add about 92 bytes, roughly a 60%
increase on that body. At the 30-second default hold (`internal/api/watch.go:17`,
`internal/agent/loop.go:1061`) an agent takes ~2,880 responses a day, so ~259 KiB per host per day,
or ~2.5 GiB a day across a 10,000-host fleet, spread over the overlay and across replicas. Each of
those responses is already a separate HTTP request with its own request line and headers
(`internal/agent/client.go:193-212`), which is the same order of magnitude, so this is a fraction
added to an existing per-request cost rather than a new one.

## Decision

`StateResponse` gains `AgentEndpoints []string` (`agent_endpoints`), populated on every state and
watch response from the same `agentEndpoints` query and the same 3-minute staleness window that
`EnrollResponse` already uses, with no conditional and no "unchanged" encoding; the agent calls the
existing `adoptEndpoints` from `poll` and `watchOnce` exactly as `doRenew` already does. Because the
compiled policy's management floor is what makes a new endpoint reachable at all,
`Tx.RegisterControlPlane` additionally reports whether its upsert inserted (`RETURNING xmax = 0`)
and `Store.Register` calls `BumpEpoch(networkID, EpochConfig)` in that same transaction when it did
— on a genuinely new `(network_id, addr)` only, so the 30-second heartbeat's update path bumps
nothing — which pushes the new floor and the new list to every watcher on every replica through the
notifier that already exists. On the failure paths: a registry query error fails the whole response
rather than degrading to an empty list, for the reason `agentEndpoints` already gives
(`internal/enroll/service.go:363-377`), and the agent treats that as a transport failure, rotates,
and keeps the list it has; an empty list is ignored rather than adopted, because `SetAgentURLs`
already returns false on `len(urls) == 0` and a replica that is answering cannot truthfully report
that no replica is live; and the agent-surface handlers union the responding replica's own endpoint
into the list before writing it (`api.AgentListener` gains `SelfEndpoint`, set at
`cmd/orbitd/main.go:500` from the `Node.AgentEndpoint` helper that already renders exactly this
string for the heartbeat, `internal/mesh/node.go:470-473`), so a replica whose own heartbeat
row went stale cannot hand every agent a list that omits the working endpoint they are talking to.

## Alternatives considered

**Do nothing; twelve hours to learn a new replica is acceptable.** This was the leading candidate,
and it lost on two specifics rather than on principle. First, the delay is one-sided in the wrong
direction: removal is immediate because failover does not need a current list, so the only thing
that is slow is the one an operator does under load. Second, the fix is not a new mechanism. Every
part of it exists — the query, the wire field on the sibling response, `adoptEndpoints`,
`SetAgentURLs`'s index preservation, `BumpEpoch`, the notifier — and ADR-0009 already names the
shape of it ("the fix is one field on `StateResponse`, not a new mechanism"). Declining a change
this small means accepting that `orbitd serve` scales out on a twelve-hour delay, which is not a
property anyone would choose deliberately.

**Copy Tailscale's encoding: `agent_endpoints` absent means unchanged.** Rejected, and the reason is
structural rather than aesthetic. That encoding is only sound inside one long-lived HTTP response
held by one server process: the client's `mapSession` remembers `lastDERPMap` for the life of that
response (`control/controlclient/map.go:87-105`), and a broken stream needs
`MapSessionHandle`/`Seq` to resume (`tailcfg/tailcfg.go:1455-1472`). Orbit's watch returns exactly
one response per HTTP request (`internal/api/watch.go:104`) and the agent may land on a different
replica for the next one (`internal/agent/loop.go:617-631`), so "absent" would have to mean
"unchanged since whatever some other process last told you", which no replica can know. Making it
knowable means server-side session state and a resume protocol, to save 92 bytes twice a minute.
It would also forfeit the property the watch design is built on — "the payload is a full
generation, not a delta: an agent that misses events loses nothing"
(`internal/api/watch.go:22-31`) — which is what lets the notifier coalesce and lets a severed
connection be harmless.

**A digest of the list as a query parameter, with the server omitting it on a match.** Rejected. The
list is derived from a liveness window, not a counter: `LiveControlPlanes` evaluates
`last_seen_at > now() - 3 minutes` per request (`internal/store/network.go:1055-1067`), so two
replicas can legitimately compute different digests in the same second, and an agent rotating
between them would flip between "unchanged" and a rewritten list. Making the digest meaningful
requires a real epoch for the replica set — a fourth counter beside config and blocklist — for a
saving of 92 bytes on a response that already costs an HTTP round trip. An unconditional list has no
such disagreement: whatever an agent last heard is the newest thing any replica told it.

**Send `agent_endpoints` only in responses that already carry `Config`.** Rejected. A host that is
up to date never receives one, which is precisely the failure `RestartRequiredEpoch` was designed
around and the stated reason it is sent on every poll rather than only while the agent is behind
(`internal/wire/wire.go:145`, `internal/enroll/service.go:471-479`). The rule is already written
down in this repo: a field an agent needs must not depend on the agent having been behind at the
right moment.

**Bump the config epoch on registration and leave `StateResponse` alone.** Rejected. The pushed
configuration names the new replica in a firewall rule, but the agent's endpoint list lives in
`agent_urls` in its state file and nothing except `adoptEndpoints` writes it
(`internal/agent/loop.go:63-67,634`). The host would be permitted to reach a replica it has never
heard of. Recovering the list by parsing it back out of the rendered nebula config means deriving a
protocol field from a rendered artifact, which is the exact inversion `NetworkSlug` exists to avoid
(`internal/wire/wire.go:147-150`).

**Reserve a control-plane prefix and permit it wholesale in the management floor.** Rejected for
now, and it is the most interesting of these. If replicas were allocated from a reserved sub-prefix,
the floor would be one rule for that prefix and adding a replica inside it would require no
configuration change at all — no epoch bump, no fleet-wide reload, and this ADR's second half would
disappear. It loses today because it widens every host's outbound permit from three named addresses
to anything that ever gets allocated inside a range, and because Orbit allocates from one pool per
network with no reservation concept (`internal/store/address.go:176-237`). It is an addressing
change, not a wire change, and it is the right answer if replica churn ever makes the epoch bumps
expensive.

**A DNS name or virtual address for the agent API.** Rejected in ADR-0009 and rejected again here.
The agent API is bound to the overlay (`internal/mesh/node.go:462-468`), so any name service
resolving it is itself a mesh member in the path every host depends on, and it would have to fail
static too. Rotation on the agent already gives failover with no shared component; the missing piece
was never the mechanism, it was the freshness of the list.

**Have the agent probe for replicas.** Rejected. There is nothing to probe. `BaseURL` does not mount
`/agent/v1` (`internal/agent/loop.go:38-49`), and scanning the overlay for listening agent ports
from every host in the fleet is not discovery.

## Consequences

**Easy.** Adding a replica reaches the fleet in one notification round trip instead of half a
certificate lifetime. The path is the one already in production for policy: `BumpEpoch` inside the
registering transaction, `pg_notify` on commit, every parked `/agent/v1/watch` on every replica
wakes and re-reads (`internal/api/watch.go:86-96`), and the response carries both the new
configuration and the new list. With push disabled the bound is the poll interval, a minute by
default, rather than twelve hours. The agent-side change is three lines and no new state: `AgentURLs`
and `Preferred` are already persisted, `SetAgentURLs` is already idempotent and already returns
false when nothing changed, so a repeated identical list costs one slice comparison and no disk
write.

**Hard, and this is the real cost: adding a replica is no longer free for the data plane.** A new
replica now bumps the network's config epoch, so every host in that network is handed a new
generation and reloads nebula. It is a reload and not a restart — `RestartRequiredEpoch` remains
reserved for address changes (`internal/wire/wire.go:118-145`) — and it is one bump per new
`(network_id, addr)` rather than per heartbeat, so a replica restarting on its own address costs
nothing. But a replica that stays down past the 30-minute prune (`internal/sched/sched.go:43-49`)
and then returns inserts a fresh row and bumps again, so a replica flapping on that timescale is
fleet-wide configuration churn. There is no rate limit on this and we are not adding one; the
mitigation is that the prune window is 30 minutes and the advertisement window is 3, so a replica
has to be gone a long time to re-insert.

**Hard: the steady-state response is no longer as small as it was.** About 92 bytes on a ~160-byte
body for three replicas, ~259 KiB per host per day at the default hold. `StateResponse`'s own
documentation says the material fields are sent "only when the agent's reported epoch is behind, so
a steady-state poll is small" (`internal/wire/wire.go:89-90`), and that sentence now needs
qualifying: two fields are unconditional for a reason, and this is the second of them. The number
scales with replica count, which is the one thing that would make it worth revisiting.

**Removal is still asymmetric, and now visibly so.** The endpoint list is recomputed per response,
so a replica that goes quiet drops out within the 3-minute window with no epoch bump. Its outbound
rule in the management floor does not: nothing bumps on prune, deliberately, because the sweep runs
on every replica and turning pruning into a fleet-wide re-render would make a flapping replica far
more expensive than it already is. So a decommissioned replica leaves a permit rule for an address
nobody answers on until some unrelated change re-renders. That is harmless and it is untidy, and it
is the honest description of what this ADR does.

**What it does not fix.** ADR-0009's missing path back to the public endpoint is untouched:
`ControlURL` still never returns `BaseURL` once `AgentURLs` is non-empty
(`internal/agent/loop.go:158-163`), and this change makes the list get rewritten more often, so a
control plane that is wrong about which replicas are live can now be wrong at every poll rather than
twice a day. The self-endpoint union in the decision is exactly the guard against the most likely
version of that — a replica whose own row went stale — and it is not a guard against a control plane
that is comprehensively wrong. The decommissioned-replica membership still blocks CA rotation.

**Committed to.** `agent_endpoints` meaning the same thing in both responses, derived from measured
liveness rather than configuration; failover staying on the agent; and the config epoch being the
signal that a host's rendered configuration has changed, including when what changed is which
replicas exist.

**What must be tested before this is Accepted.** `e2e/overlay_test.go:221`
(`TestEnrollmentAdvertisesLiveReplicas`) registers two replicas through `store.Register` and asserts
the enrolment list. The new claim needs the equivalent at the state and watch paths: register a
second replica while an agent is parked on a watch, and assert the agent's persisted `agent_urls`
contains it before any renewal, and that the wake came from the registration rather than from the
hold expiring. ADR-0009 records that no test runs two `orbitd` processes against one database; this
ADR does not change that, and does not need it — the bump and the fan-out are both testable at the
`enroll.Service` plus `agent.Loop` level.

**Revisit when** the per-response bytes matter at fleet scale, in which case the digest alternative
returns keyed on a real replica-set counter rather than a liveness window; or when replica churn
makes fleet-wide config bumps too frequent, in which case the reserved control-plane prefix is the
answer and the epoch bump goes away with it.

## References

- `internal/wire/wire.go:55-62,84-151` — `EnrollResponse.AgentEndpoints` and the `StateResponse` it
  is missing from
- `internal/enroll/service.go:352,363-394,436-556,1019-1034` — the staleness window, why the query
  error is returned, the state read, and the management floor's source
- `internal/agent/loop.go:33-67,158-204,612-641,861,870-887,1042-1201` — persisted list, rotation,
  `adoptEndpoints`, and the two paths that do not call it
- `internal/api/watch.go:17-105` — the long poll, one response per request, and the re-read on wake
- `internal/store/network.go:1023-1067` — `RegisterControlPlane`'s upsert and `LiveControlPlanes`
- `internal/mesh/node.go:462-473` — the overlay-only listener, and the `AgentEndpoint` helper the
  self-endpoint union reuses
- `internal/store/store.go:302-317`, `internal/notify/notify.go:148-189` — `BumpEpoch` and the
  cross-replica fan-out it drives
- `internal/policy/compile.go:352-367`, `internal/nebulacfg/policy.go:20-43` — the management floor
  and why outbound is closed in authoritative mode
- `tailcfg/tailcfg.go:1965-1985,2024-2026,2036-2051,2094-2116,2177-2180,2311-2345` (Tailscale) —
  `MapResponse` semantics, zero-means-unchanged, the real patch fields, and `ControlDialPlan`
- `tailcfg/tailcfg.go:1455-1472,1987-1999` (Tailscale) — `MapSessionHandle`/`Seq`, the resume
  protocol a delta stream requires
- `tailcfg/derpmap.go:17-34` (Tailscale) — `DERPMap`, where a non-nil value replaces `Regions`
  wholesale and only sub-fields carry forward
- `control/controlclient/map.go:87-105,622-678,1270` (Tailscale) — the per-session `last*` state,
  applying a new DERP map, and rebuilding the full netmap from remembered fields
- `control/controlclient/direct.go:1051-1055,1129-1142,1300-1322,1356-1362,1484-1516` (Tailscale) —
  `Stream`, the length-prefixed read loop on one connection, the keepalive and its watchdog, and
  where the dial plan is stored
- `ipn/ipnlocal/local.go:2075`, `net/dnsfallback/dnsfallback.go:233-257`,
  `cmd/tailscaled/tailscaled.go:728` (Tailscale) — the DERP map cached to disk as a cold-start
  bootstrap
- ADR-0002 (fail static), ADR-0008 (what we measure), ADR-0009 (control-plane replicas — this is the
  open item in its Consequences)
