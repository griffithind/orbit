# ADR-0009: Control-plane replicas are peers coordinated only by Postgres

**Status:** Accepted
**Date:** 2026-08-11

## Context

`docs/design.md:152` says "The control plane is **stateless**. All state is Postgres. Run N
replicas behind a load balancer." `docs/deployment.md` §11 says a second replica needs "no load
balancer, no virtual address, no coordination." Those two sentences cannot both be a complete
description, and an operator deciding whether to run two of these needs to know which parts are
guaranteed by design, which are true by accident, and which are not true at all.

What a replica actually is. `orbitd serve` (`cmd/orbitd/main.go:226`) opens one Postgres pool,
opens the key vault from the database under the KEK passphrase, and starts four things: the public
enrollment/admin listener, an overlay agent listener per `-mesh` network, the epoch notifier, and
the maintenance runner. Every one of those runs on every replica. There is no leader, no lease, no
`-primary` flag, and no code path that behaves differently on the second process than on the first.

**Coordination is Postgres, in three separate forms, and nothing else.**

1. *Row locks and constraints.* Writes that must not interleave take `SELECT … FOR UPDATE` on the
   owning row first — the network for a policy version (`internal/store/policy.go:245`) or a CA
   activation (`internal/store/network.go:359`), the membership for an address change
   (`internal/store/address.go:338`). Address allocation is a unique index plus
   `ON CONFLICT DO NOTHING`, so the loser of a race gets no row rather than a duplicate
   (`internal/store/address.go:176-237`). `lock_timeout=5s` and
   `idle_in_transaction_session_timeout=60s` are set on every connection
   (`internal/store/store.go:83-88`) so one wedged transaction cannot stall every other replica's
   writers for that network.
2. *`LISTEN`/`NOTIFY`* for push, described below.
3. *One advisory lock*, `0x0067_0072_0062_0074` ("orbt"), in `internal/db/migrate.go:26`.

That third one is worth stating precisely, because its own package doc gets it wrong.
`internal/db/migrate.go:5-7` says the runner is "guarded by an advisory lock so that N
control-plane replicas starting simultaneously do not race." Replicas never reach it: `serve` does
not migrate, and `internal/db.Migrate` is called only from `orbitd migrate`
(`cmd/orbitd/migrate.go:75`), which takes a different DSN — `serve` connects as `orbit_app`, which
holds no `CREATE`. The lock is real and correct; what it serializes is two `orbitd migrate`
invocations (and `EnsureRoleLogin`, `internal/db/migrate.go:157`), not two replicas booting.

**Push is not process-local, and that is the load-bearing fact.** The `Notifier`'s subscriber map
is per process (`internal/notify/notify.go:54-55`), but nothing about the wake-up depends on which
process wrote the change. `Tx.BumpEpoch` (`internal/store/store.go:302-317`) issues
`SELECT pg_notify('orbit_epoch', …)` inside the same transaction that increments the counter, and
Postgres delivers on commit to every session that has `LISTEN`ed. Each replica holds one dedicated
connection doing exactly that (`internal/notify/notify.go:148-189`). So an agent parked on
replica A's `/agent/v1/watch` is woken by a block issued through replica B, in the same delivery,
with no polling involved. The watch handler then re-reads state rather than trusting the event
payload (`internal/api/watch.go:91`), so the epoch in the notification — and therefore which
replica produced it — has no bearing on what the agent receives.

What *is* per process: the subscriber map, the `-max-watchers` cap (which counts only this
process's subscribers, so N replicas admit N × 5000 per network), the `-no-push` flag, and the
`orbit_epoch_listener_up` gauge. A replica whose `LISTEN` connection drops reconnects with backoff
to 10s (`internal/notify/notify.go:124-146`); while it is down, only the agents parked on *that*
replica fall back to hold-expiry plus poll. That is slower, not wrong: every watch response is a
full generation rather than a delta, so a missed wake costs latency and loses nothing.

**Discovery and liveness are measured, not configured.** `orbit.control_plane`
(`internal/db/migrations/0001_initial.sql:34-46`) is keyed on `(network_id, addr)` with an index on
`(network_id, last_seen_at DESC)`. A replica upserts its own row on join and every 30 seconds
after (`internal/mesh/node.go:134,381-410`, `internal/store/network.go:1028`), with `last_seen_at`
stamped by `now()` in the database — deliberately, because orbitd and Postgres are routinely not
the same host and a Go-side cutoff would compare two clocks
(`internal/store/network.go:1039-1054`). Two windows read that table and they differ on purpose:
agents are handed replicas seen within **3 minutes** (`internal/enroll/service.go:352`,
`agentEndpoints` at 377-393), while the sweep deletes rows quiet for **30 minutes**
(`internal/sched/sched.go:43-49`). A replica stops being advertised long before its registration is
deleted, so a brief outage costs it traffic rather than its row.

**Failover is on the agent.** The endpoint list arrives as `EnrollResponse.AgentEndpoints`
(`internal/wire/wire.go:55-62`) and the agent rotates cyclically through it on transport errors
only — an `APIError` from a working replica does not rotate
(`internal/agent/loop.go:145-190,599-618`). The chosen index is persisted, so a restart does not
send every host back to replica 0. Note the cadence: `AgentEndpoints` is set on enroll, join, and
renew (`internal/enroll/service.go:279,421`, `internal/enroll/join.go:445`) and `StateResponse`
(`internal/wire/wire.go:85-145`) has no such field, so poll and watch never refresh it.

**Background work is idempotent by construction.** The sweep
(`internal/sched/sched.go:137-301`) is deletes-by-predicate — expired blocklist entries, stale
`control_plane` rows, spent enrollment credentials, expired UI sessions — plus one state
transition, `ForceRetireCA`, whose input query structurally cannot return the active CA. Two
replicas racing to delete the same already-expired row leaves the same database.

**Every replica is also a membership.** `SelfIssue` (`internal/enroll/service.go:1205`) creates or
reuses a host record per network, which means each replica is counted by convergence and gated by
it: `POST /v1/cas/{id}/activate` returns 409 while any membership is behind
(`internal/api/resources.go:1395-1478`).

## Decision

Orbit supports N control-plane replicas as peers. There is no singleton, no leader election, and
no coordination outside Postgres: writes serialize on row locks and unique constraints, push fans
out through `LISTEN`/`NOTIFY` so a change committed by any replica wakes watchers on all of them,
replicas advertise themselves by heartbeating a row rather than by being configured, agents fail
over by rotating that list themselves, and the maintenance sweep runs everywhere because its jobs
are idempotent. What an operator gets is availability of the agent API and of enrollment; what
they do not get is a lower-latency database, a load-balanceable web UI, a deployment-wide rate
limit, or replica discovery faster than the renewal cadence.

## Alternatives considered

**Leader election for maintenance, via an advisory-lock lease.** Rejected. Every job in the sweep
is a delete of rows that are already expired, or a CA transition the query cannot reach while the
CA is active. A lease would add a failure mode — a lock held by a process that is alive but wedged
stops maintenance everywhere and silently, and the blocklist then grows without bound in every
host's config — in exchange for no correctness the deletes do not already have
(`internal/sched/sched.go:9-12`).

**A load balancer or virtual address in front of the agent API.** Rejected twice over. The agent
API is bound to the overlay only (`internal/mesh/node.go:427-433`), so the load balancer would
have to be a mesh member itself, which makes it one more thing holding a certificate in the path
every host depends on. And rotation on the agent already gives failover with no shared component;
the cost is that a host takes one failed request to notice, which is the right trade for
infrastructure that must keep working while the control plane is partly down
(`internal/agent/loop.go:154-159`).

**A message broker — NATS, Redis — for fan-out.** Rejected. `LISTEN`/`NOTIFY` on the database we
already require is sufficient into the five figures of hosts, and the binding limit is connection
count rather than throughput (`internal/notify/notify.go:1-13`). A broker adds a component to
day-one operations, a second thing that can be down, and a delivery path that is not transactional
with the write — losing the property that a rolled-back change cannot wake anyone and a committed
one cannot fail to.

**Migrating on `serve` startup, serialized by the existing advisory lock.** Rejected. It would
require the serving process to connect as a role holding `CREATE`, which is exactly the boundary
the two DSNs draw: the application must not be able to alter the schema or rewrite the audit log
(`cmd/orbitd/main.go:216-218`, `internal/db/migrate.go:63-67`). Migration stays a separate
command with a separate DSN, and `orbitd doctor` reports drift.

**A configured peer list — each replica told about the others.** Rejected. Registration by
heartbeat means the list an operator reads from `GET /v1/networks/{id}/replicas` and the list the
fleet is acting on are the same query with the same staleness bound
(`internal/api/resources.go:397-407`); a configured list is a second opinion that disagrees at
exactly the margin where it matters, and it needs a deregistration path, which is one more thing
to get wrong.

**Making the UI replica-agnostic by deriving the CSRF token from the session cookie alone.**
Rejected on security grounds, not on architecture: a token computable by anyone who learns the
cookie value collapses the third CSRF layer into the first
(`internal/web/middleware.go:287-292`). The consequence — see below — is that the UI is not
load-balanceable without sticky sessions, and we accept that rather than weaken the token.

**Keeping CA keys in files, copied to each replica.** Already rejected and already removed
(`docs/key-custody.md`). Two custody paths meant two sets of failure modes and a replica that could
silently hold a stale key through a rotation. A replica now needs one secret, the KEK passphrase.

## Consequences

> **Three of the findings above were fixed on 2026-08-11, after this was drafted.** The Context is
> left as written — it is the record of what was true when the decision was made — and this is what
> changed since.
>
> - **Two replicas on one overlay address** are now refused. The defence was always `SelfIssue`'s
>   "reuse only when the name matches"; it was inert because the default name was derived from the
>   very address it refereed. The name is the machine's hostname now, which differs between replicas
>   and is stable across a restart. `mesh.Config.Addr`'s claim that the `membership_address`
>   uniqueness constraint enforced this is also corrected: the second replica adopts the first's
>   membership rather than inserting a row, so no constraint was ever consulted.
> - **The `BaseURL` fallback** is not implementable and the code was right; two comments were wrong.
>   The public listener mounts enroll, admin and health and not the agent routes, so there is nothing
>   to fall back to — and putting `/agent/v1` there would expose an API whose identity is the caller's
>   source address to the internet. Both comments now describe the real recovery path, which is
>   re-enrolment with a fresh code.
> - **The UI is load-balanceable.** The CSRF key is derived from the KEK through HKDF, so every
>   replica computes the same bytes without them being stored. `docs/design.md`'s unqualified "run N
>   replicas behind a load balancer" is accurate again.
>
> Still open from this ADR: a decommissioned replica's membership is never removed, so it counts as
> lagging and blocks CA rotation; and adding a replica reaches existing agents only at renewal,
> because `StateResponse` carries no endpoint list.



**Easy.** Adding a replica is one process with its own overlay address and the same KEK
passphrase. It registers itself, appears in the live list within one heartbeat, and starts taking
agent traffic with no reconfiguration anywhere. Sharding is the same mechanism: `-mesh` is
per-instance, so scaling past a few hundred networks is more instances over disjoint subsets, and
the notifier fans out from Postgres, which all of them already listen to.

**A rolling restart is cheap but not free, and the cost is precise.** On SIGTERM the public
listener drains for 10 seconds and the UI for 5, but the overlay listener is closed outright
(`cmd/orbitd/main.go:550-553`), so parked `/agent/v1/watch` connections are severed rather than
answered. Agents see a transport error, rotate, and land on another replica — one failed request
each. There is no deregistration: the departing replica's `control_plane` row stays live for up to
the 3-minute staleness window, so enrollments and renewals in that window are handed an endpoint
that is down, and discover it by failing one request against it. On start, each replica generates a
fresh keypair and self-issues, because the private key is only ever in memory
(`internal/mesh/node.go:160-166`); the previous certificate is marked superseded but not
blocklisted (`internal/store/host.go:521-533`), so every restart adds a certificate row per network
and leaves the old certificate technically valid until its TTL.

**Adding a replica is slow to reach the fleet; removing one is immediate.** Because
`StateResponse` carries no endpoint list, an existing agent learns about a new replica only at its
next renewal — half of `CertTTL`, so 12 hours at the 24-hour default. A new replica therefore
carries enrollment traffic at once and steady-state agent traffic hours later. Removal has no such
delay, because failover does not need the list to be current.

**An agent has no path back to the public endpoint.** Once `AgentURLs` is non-empty,
`ControlURL` never returns `BaseURL` (`internal/agent/loop.go:145-149`) and `failover` only rotates
within the list. If every advertised overlay endpoint becomes permanently unreachable at once —
all replicas re-addressed, or the last one leaving the mesh — the agent has no way to reach a
control plane and no way to be told a new list, and it fails static until its certificate expires.
Both `State.BaseURL`'s own doc (`internal/agent/loop.go:34-37`) and
`internal/agent/escapehatch.go:14-18` describe a fallback to `BaseURL` that the loop does not
implement. This is a defect, not a design choice, and it is more visible with N replicas because
the endpoint list is the thing that grew.

**Two replicas given the same `-mesh` overlay address are accepted, not refused.** This is the one
place where the multi-replica story is wrong rather than merely slow. `mesh.Config.Addr` claims
"the `membership_address` uniqueness constraint enforces that rather than letting two silently
collide" (`internal/mesh/node.go:44-46`). It cannot fire. `SelfIssue` looks the address up first
and refuses only when the existing host's *name* differs from the requested one
(`internal/enroll/service.go:1275-1281`), and the name defaults to `orbit-control-<addr>`
(`internal/mesh/node.go:141-143`) — derived from the colliding address, so it always matches. The
second process therefore reuses the first's membership instead of creating a second one that the
constraint would reject: both self-issue valid certificates for the same overlay IP, both bring up
nebula on it, and `RegisterControlPlane` upserts on `(network_id, addr)` so the registry shows a
single endpoint pointing at two processes. Nothing logs anything unusual. The fix is a real
guard — device fingerprint or a liveness check on the row — not a comment.

**A decommissioned replica blocks CA rotation.** Its `control_plane` row is pruned after 30
minutes, but the membership `SelfIssue` created is never removed by anything. Once the config epoch
moves past what that replica last reported, it counts as lagging, and `handleActivateCA` returns
409 with it named in the body until an operator deletes the membership or resends with
`acknowledge_cutoff` (`internal/api/resources.go:1428-1466`). Removing a replica is therefore two
steps, and the second one is easy to forget until a rotation stalls.

**Per-process limits multiply by N.** The enrollment limiter is in-process
(`internal/api/ratelimit.go:30-46,98-103`): 10/min per source address and a 600/min global ceiling
become N × that for a set of replicas sharing one public name. The same is true of `-max-watchers`
and of the UI login limiter (`internal/web/web.go:154`). None of these is a correctness bug, but a
deployment that sized its enrollment ceiling deliberately no longer has the ceiling it chose.

**The web UI is not load-balanceable.** `csrfKey` is generated per process
(`internal/web/web.go:149-151,174-177`) and the form token is an HMAC over the session cookie under
it (`internal/web/middleware.go:281-300`), so a POST that lands on a different replica than the GET
which rendered the form is refused — every time, not just after a restart. Sessions themselves are
in Postgres (`web.StoreSessions`), so being logged in survives; only the form token does not.
`-ui-addr` binding loopback by default makes per-replica access the normal case, but
`docs/design.md:152` promises a load balancer without qualifying it, and that sentence should be
narrowed to the enrollment and admin surfaces.

**A mixed-version rolling upgrade is unguarded.** `serve` does not check the schema version at
all; only `orbitd doctor` compares applied migrations against the bundled set, including the
"migrated by a newer orbitd" direction (`cmd/orbitd/doctor.go:203-222`). Combined with ADR-0005,
which declines backward compatibility before v1.0, the honest statement is that replicas must be
upgraded together across a migration, not one at a time.

**What we are committed to.** Postgres is the only coordinator, which makes the database the
single point of failure — a normal problem with normal answers, and the reason fleet metrics are
read at scrape time rather than held in memory so that two replicas report identical numbers
(`internal/metrics/collector.go:41`, `docs/deployment.md` §8). We are also committed to
`agent_endpoints` being derived from measured liveness rather than configuration, and to failover
living on the agent.

**What is not tested.** `e2e/overlay_test.go:221` (`TestEnrollmentAdvertisesLiveReplicas`) registers
two replicas by calling `store.Register` directly and asserts the list and the rotation; no test
runs two `orbitd` processes against one database, and no test runs two `Notifier`s to demonstrate
the cross-replica wake. The fan-out is correct by construction — Postgres broadcasts to every
`LISTEN`ing session — but "correct by construction" is what this repo says about things it has not
measured, and the notifier is the one component whose failure is silent and fleet-wide.

**Revisit when** watcher connections outgrow a single Postgres (the limit named in
`internal/notify/notify.go:9-12`), when discovery latency of half a certificate lifetime becomes
unacceptable — the fix is one field on `StateResponse`, not a new mechanism — or when the UI needs
to sit behind a load balancer, which requires either sticky sessions or moving the CSRF key into
the database beside the sessions it protects.

## References

- `cmd/orbitd/main.go:226-623` — what one replica boots, in order
- `internal/mesh/node.go:381-410` — `Announce` and the 30-second heartbeat; `:44-46` the collision
  claim that does not hold
- `internal/store/store.go:296-317` — `BumpEpoch`, and why `pg_notify` is inside the transaction
- `internal/notify/notify.go:1-13,124-205` — the fan-out transport and its reconnect behaviour
- `internal/api/watch.go:32-105` — the long poll, and the re-read after a wake
- `internal/db/migrations/0001_initial.sql:34-46` — the `control_plane` table
- `internal/store/network.go:1015-1078` — register, live-list, prune
- `internal/enroll/service.go:352,377-393,1205-1317` — staleness window, endpoint list, `SelfIssue`
- `internal/sched/sched.go:9-12,137-301` — the idempotent sweep
- `internal/agent/loop.go:145-190,599-628` — rotation, adoption, and the missing fallback
- `internal/db/migrate.go:5-7,26,63-74` — the advisory lock, and the path it does not guard
- `internal/api/resources.go:1385-1478` — the convergence gate replicas are counted by
- `internal/web/middleware.go:281-300`, `internal/web/web.go:149-181` — the per-process CSRF key
- `e2e/overlay_test.go:221` — what the two-replica claim is actually tested at
- `docs/deployment.md` §11, `docs/design.md` §2 and §8, `docs/revocation.md` §3 — the operator-facing
  statements this ADR makes precise
- ADR-0002 (fail static), ADR-0005 (no compatibility before v1.0)
