# ADR-0011: Every update carries a full generation, not a delta

**Status:** Proposed
**Date:** 2026-08-11

## Context

Orbit has been sending full state since the first agent poll, and has never written down that it
decided to. The only place the choice is defended is a comment on the long poll
(`internal/api/watch.go:21-31`): "the payload is a full generation, not a delta: an agent that
misses events loses nothing, since it re-reads current state on every wake." That sentence is the
load-bearing assumption behind three other mechanisms, and it is worth stating as a decision with a
price rather than leaving as an implementation detail.

**What a wake actually returns.** `handleAgentWatch` subscribes, then calls
`enroll.Service.State` with the epochs the agent claims to hold (`internal/enroll/service.go:436`).
`State` reads the network's two counters, always returns `RenewAfter`, `NotAfter`,
`RestartRequiredEpoch` and `NetworkSlug`, and then — only if `knownConfig >= net.ConfigEpoch &&
knownBlock >= net.BlocklistEpoch` is false (`service.go:542`) — calls `renderFor`, which builds the
host's entire nebula configuration from scratch: network topology, lighthouses, relays, routes,
served prefixes, live blocklist, trust bundle, role firewall, compiled policy, the network's whole
DNS name table (`service.go:765-886`). The result is signed as one document
(`ca.NewConfigEnvelope`, `service.go:568-590`) and returned as one string. A steady-state poll
therefore returns a few hundred bytes; any poll that is behind returns everything.

**What a generation contains, and how it grows.** `internal/nebulacfg/render.go` produces one
complete YAML document. Re-rendering that document shape with the same struct tags and the same
`yaml.v3` encoder gives:

| Section | Grows with | Measured |
|---|---|---|
| everything fixed (`pki` paths, `listen`, `punchy`, `relay`, `tun`, `logging`) | nothing | ~700 B |
| `static_host_map` + `lighthouse.hosts` | lighthouses, not hosts | ~60 B each |
| `pki.blocklist` | unexpired revocations | 76 B/entry (50 entries = 3,811 B) |
| `firewall` | compiled policy rules | 108 B/rule |
| `orbit.dns.hosts` | **every host in the network** | 83 B/host, one address |

Baseline, no names and no revocations: **1,433 B**. With the name table, which is the only term
that scales with fleet size:

| Network | Generation | As a JSON string in `StateResponse.Config` | Bytes per fleet-wide epoch bump |
|---|---|---|---|
| 100 hosts, 12 rules | 10,901 B | 11,350 B (+4.1%) | ~1.1 MB |
| 1,000 hosts, 20 rules | 86,211 B | ~89 KB | ~82 MB |
| 5,000 hosts | 417,617 B | ~433 KB | ~2 GB |

Nothing compresses these: there is no `Content-Encoding` handling anywhere in `internal/` or
`cmd/`. Add the CA bundle and `ConfigSig` to every carrying response.

**The multiplier is the epoch, not the payload.** Both counters are per *network*
(`internal/store/store.go:264-294`), and all eighteen non-`Tx` call sites of `BumpEpoch` — seventeen
config, one blocklist — advance a counter for a whole network, including changes that affect exactly
one host, such as an address allocation at enrollment
(`internal/store/address.go:404`) or a lighthouse flag (`internal/store/host.go:955`). One host
joining therefore wakes every agent in the network, and every one of them re-renders and re-applies
its own complete configuration. Per bump that is N renders each reading O(N) rows: 10⁴ row-touches
at 100 hosts, 10⁶ at 1,000, 4×10⁶ at 2,000.

**And the agent pays even when its own bytes did not change.** `Loop.poll` checks only
`resp.Config == ""` (`internal/agent/loop.go:883`). There is no content comparison, so any
generation the agent is behind on runs the whole pipeline in `internal/agent/generation/apply.go`:
a staging directory, four `write`+`fsync`es, a fork/exec of the nebula binary to validate the
candidate config, renames, a reload or a proven restart, then verification, with a rollback to
`.previous/` on any failure after install. That fork/exec — not the bytes — is what a fleet
actually spends on somebody else's enrollment.

The coalescing that makes this survivable is real and deliberate: `BumpEpoch` issues the
`pg_notify` inside the caller's transaction so it lands on commit and only on commit
(`store.go:296-318`), and `notify.dispatch` drops an event when a subscriber's single-slot buffer
is full because "every waiter re-reads current state on wake, so one wakeup conveys everything a
hundred would" (`internal/notify/notify.go:191-205`). Coalescing collapses a burst within one hold
window; it does nothing for a sustained enrollment rate.

**Prior art: Tailscale made the opposite choice, and the machinery is the price.** In
`tailcfg.MapResponse`, `Peers` is "the complete list of peers ... set in the first MapResponse for a
long-polled request/response", and "Subsequent responses will be delta-encoded if
MapRequest.Version >= 5 and server chooses" (`tailcfg/tailcfg.go:2028-2035`). The deltas are
`PeersChanged` (whole changed nodes, `:2036-2040`), `PeersRemoved` (ids, `:2041-2042`) and
`PeersChangedPatch` — "a lighter version of the older PeersChanged support that only supports
certain types of updates" (`:2044-2051`). A `PeerChange` (`:3008-3048`) may carry exactly ten
fields — `DERPRegion`, `Cap`, `CapMap`, `Endpoints`, `Key`, `KeySignature`, `DiscoKey`, `Online`,
`LastSeen`, `KeyExpiry` — every one of them "zero means unchanged", and nothing else. It cannot
express an address, an allowed-IP, a hostinfo, a tag, or an expiry flag.

What they had to build for that to be safe:

- **A demotion rule, not a resync signal.** `netmap.mapResponseContainsNonPatchFields`
  (`types/netmap/nodemut.go:186-216`) lists fifteen fields whose presence means "the caller must
  fall back to rebuilding and dispatching a full NetworkMap", and `NodeMutationsFromPatch`
  (`:111-138`) returns `(nil, false)` on any `PeerChange` field it does not know: `default: //
  Unhandled field.` One unrecognised field demotes the entire response.
  `mapSession.tryHandleIncrementally` (`control/controlclient/map.go:418-469`) has five separate
  ways to give up, and the fall-through is commented "This is the part we tried to avoid but some
  field mutations (especially rare ones) aren't yet handled" (`:347-349`).
- **A full map one restart away.** `MapResponse.Seq` and `MapSessionHandle` exist for resumption
  (`tailcfg.go:1987-1999`) and no client code in the checkout reads or writes them. Safety comes
  instead from the stream: the first non-keepalive message of any poll must be a full map, or the
  client errors out — `"initial MapResponse lacked node"` (`control/controlclient/direct.go:1385-1392`)
  — and everything that goes wrong ends in a new poll: a two-minute watchdog that breaks a stalled
  connection (`direct.go:1197-1206`), `Auto.restartMap` after login (`auto.go:295-305`), and a
  2-second timeout on the downstream observer that simply returns false and takes the full path
  (`auto.go:486-513`). Deltas are safe because a full map is always one reconnect away.
- **A kill switch.** The `disable-delta-updates` node capability makes a client "not process
  updates via the delta update mechanism and ... instead treat all netmap changes as 'full' ones as
  tailscaled did in 1.48.x and earlier" (`tailcfg/nodecap/nodecap.go:131-134`).
- **A test that fails when the schema grows.** `peerChangeDiff` walks `tailcfg.Node`'s fields by
  reflection so it can `panic("unhandled field: " + field)` — "The whole point of using reflect in
  this function is to panic here in tests if we forget to handle a new field"
  (`map.go:1002-1007`). Both paths must also produce identical state:
  `tkaFilterDeltaMutsLocked` (`ipn/ipnlocal/tailnet-lock.go:129-138`) exists only so tailnet-lock
  filtering on the patch path "matches the semantics of [tkaFilterNetmapLocked] on a full netmap".
- **A protocol version ratchet.** Delta peers arrived at capability version 5 (2020-10-19),
  `PeersChangedPatch` at 33 with two fields, five more at 36, `KeySignature` at 40, `Cap` at 54
  (`tailcfg.go:57,85,87,91,105`). Every new patchable field is a wire-compatibility event forever.

Two details are worth having read the source for. First, the control server does not send narrow
patches by itself: `mapSession.patchifyPeersChanged` (`map.go:927-955`) takes the whole `Node`
objects the server put in `PeersChanged` and *re-derives* patches on the client, counting misses per
field (`counter_patchify_miss{why=...}`) — the delta protocol did not replace the full-object path,
it added a second one beside it. Second, when a patch names a node the receiver does not have, the
applier abandons the whole batch mid-loop and relies on the fallback: "if we return false, we'll
just get a full netmap soon and reset all our state anyway"
(`ipn/ipnlocal/node_backend.go:1098-1102`, `:1168-1176`). Tailscale's delta path is correct because
the full path never went away.

## Decision

Orbit sends a complete, signed, rendered generation on every update, and never a delta. An agent's
entire protocol state is two integers; a response either carries the whole configuration or carries
none of it; a missed event, a dropped long poll, a crashed agent and a replica failover are all the
same thing, because the next wake re-reads current state. We accept the resulting O(N²)
cost per fleet-wide change, and we bound it: this decision holds to **1,000 hosts in a single
network** and is wrong at **2,000**.

## Alternatives considered

**Adopt deltas, Tailscale-style.** Rejected for now, on the specific machinery Orbit would have to
build — none of which it has:

1. *Per-host sequencing.* Today the agent holds two `int64`s and the server holds two counters per
   network. Patching needs a per-host notion of "what you have", which means session handles,
   sequence numbers, and a server-side record of each host's position — the thing Tailscale defined
   (`tailcfg.go:1987-1999`) and then did not implement, because it could rely on the stream instead.
2. *An explicit "take a full generation" signal.* Orbit's transport is a request/response long poll,
   not a stream, so there is no session to tear down and no equivalent of "the first message must be
   a full map". The demotion rule would have to be an explicit field, and the agent would have to
   honour it under every failure it can hit.
3. *A patchable/not classification of the whole render, with a gate.* Every field in
   `nebulacfg.Input` and every section in `render.go` would need a decision and a test that fails
   when a new one is added, exactly as `mapResponseContainsNonPatchFields` and the reflect panic do.
4. *A second signing scheme.* `ConfigSig` covers the whole rendered document
   (`enroll/service.go:568-590`), and the agent stores the signed original beside the installed file
   so divergence is detectable later (`agent/generation/apply.go:174`, `:220-231`). A patch must
   either carry its own signature — with a rule for what the agent verifies after reassembly — or be
   signed over the *resulting* document, which requires the control plane to model each host's exact
   bytes. That modelling, not the patch format, is the expensive part here.
5. *Reconciliation with revert.* Quarantine and rollback are keyed by config epoch
   (`agent/loop.go:888`) and the previous generation is a directory of complete files
   (`apply.go:597-635`, `Revert` at `:685`). A host that reverts is at G−1 while the server believes
   it is at G, so under deltas the server cannot compute the next patch until it learns the truth.
   Today a lost revert report costs a wrong convergence count (`loop.go:938-951`); under deltas it
   would cost correctness.

And the payoff is smaller here than there. Nebula reads **one complete file** in authoritative mode
(`nebulacfg/render.go:14-19`), so any delta must be reassembled into a whole document before it can
be validated and reloaded — the transfer shrinks, the fork/exec-validate-reload does not. Tailscale
patches a live in-memory netmap; Orbit patches a file on disk that a separate process re-reads.

**Suppress a generation whose bytes did not change for that host.** The obvious cheaper fix: render,
hash, and tell an agent whose digest already matches that it is current — full-state semantics kept,
most of the N² apply storm gone. It is not rejected on the merits; it lost as an *alternative*
because it is not a different decision, it is an optimisation inside this one, and it still performs
N renders per bump unless render digests are cached. It is the first thing to build when the
thresholds below are hit.

**Split the fleet-scale sections out of the signed document** — deliver the DNS name table on its
own channel so ordinary changes stay small. Rejected on the argument already recorded in
`render.go:487-496`: the agent's instructions ride in the same document as its certificate paths
because "a second file would need its own signature, its own delivery and its own divergence check,
and would eventually disagree with this one."

**Cap network size and shard.** Rejected as a decision, kept as an operational fact: the growth term
is one network's host count, so two networks of 500 cost a quarter of one network of 1,000. That is
a real mitigation and a bad answer to "we have 2,000 machines that need to talk to each other."

## Consequences

**Easy.** Every failure mode collapses into one. A dropped connection is harmless, the notifier can
coalesce to a single wakeup, an agent can be stopped for a week, and ADR-0009's replicas need no
session affinity — any replica answers any wake from committed state, because the answer is a pure
function of the database and the requester's two integers. The signature covers the whole document,
so there is one artifact to verify and one to roll back to. The file on disk is the complete answer
to "what is this host running", which is what makes `checkInstalled` a hash comparison and
`Revert` a directory copy.

**Hard.** Cost per fleet-wide change is quadratic in one network's host count: ~1.1 MB at 100 hosts,
~82 MB at 1,000, ~330 MB at 2,000, uncompressed. Worse than the bytes, every host runs a full
validate-and-reload for a change that had nothing to do with it — an enrollment storm is N epoch
bumps, and coalescing does not help a sustained rate. And the dominant growth term is the DNS name
table, which means a convenience feature sets the scaling limit of the delivery mechanism.

**Committed to.** One signed artifact per generation, and no second channel that delivers part of a
host's state unsigned. The agent's protocol state stays two integers plus what is on disk. Any
future work on this — digest suppression, per-host epochs — must preserve the property in
`watch.go`, that an agent which missed every event is indistinguishable from one that missed none.

**Not measured today, and that is a gap.** There is no metric for generation size or for renders per
epoch bump; `orbit_config_epoch`, `orbit_hosts_config_converged`, `orbit_convergence_lag_seconds`
and `orbit_watch_connections` are what exists. Per ADR-0008, a claim about scaling that nothing
measures is a claim we will discover to be wrong in production. A histogram of rendered bytes and a
counter of renders per bump are the two additions this ADR asks for.

**Revisit when any of these is true**, and start the work at the first:

- a single network reaches **1,000 hosts**, or any rendered generation exceeds **64 KB**;
- p50 `orbit_convergence_lag_seconds` after an epoch bump exceeds `DefaultWatchHold` (30 s,
  `internal/api/watch.go:17`), which means the fleet cannot absorb a change within one hold window;
- enrollment rate into one network sustains above roughly one host per hold window, so coalescing
  stops collapsing anything.

At **2,000 hosts in one network** this decision is wrong and the order of work is: digest
suppression first (cheap, keeps full-state semantics), then per-host epochs, and deltas last —
because deltas cost the five pieces of machinery listed above and, in Orbit's file-based apply path,
save only the transfer.

## References

- `internal/api/watch.go:21-31` — the comment this ADR promotes to a decision; `:17` `DefaultWatchHold`
- `internal/enroll/service.go:436-559` — `State`, and the epoch comparison at `:542`
- `internal/enroll/service.go:568-590`, `:765-886` — `signMaterial`, `renderFor`
- `internal/nebulacfg/render.go` — what a generation contains; `:487-496` on one signed document
- `internal/agent/generation/apply.go` — stage, validate, install, deliver, verify, revert
- `internal/agent/loop.go:870-925` — poll and apply, with no content comparison
- `internal/store/store.go:296-318` — `BumpEpoch`; `internal/notify/notify.go:191-205` — coalescing
- Sizes derived by re-rendering `render.go`'s document shape with the same encoder; raw and
  JSON-escaped byte counts in the tables above
- Tailscale `tailcfg/tailcfg.go:2028-2051`, `:3008-3048`, `:1987-1999`, `:57,88,90,105,117`
- Tailscale `types/netmap/nodemut.go:111-138`, `:186-216`
- Tailscale `control/controlclient/map.go:340-366`, `:418-469`, `:783-905`, `:927-955`, `:1002-1007`
- Tailscale `control/controlclient/direct.go:1197-1206`, `:1385-1392`; `auto.go:295-305`, `:486-513`
- Tailscale `ipn/ipnlocal/node_backend.go:1098-1102`, `:1168-1176`; `ipn/ipnlocal/tailnet-lock.go:129-138`
- Tailscale `tailcfg/nodecap/nodecap.go:131-134` — the delta kill switch
- ADR-0002 (fail static), ADR-0008 (what we measure), ADR-0009 (replicas)
