# ADR-0008: Six signals defend the objectives; everything else is a dashboard

**Status:** Proposed
**Date:** 2026-08-11

## Context

Orbit is a control plane whose failures are quiet by construction. ADR-0002 makes the data plane
survive the control plane's death, so nothing an operator can see from a host tells them the
control plane is broken — established tunnels keep carrying traffic while revocation, enrollment
and rotation are all dead. The only channel that reports the difference is the one we build.

### What exists today

`internal/metrics` has two halves, and the split is deliberate (`internal/metrics/metrics.go:1-18`).

Process-local counters and gauges, incremented on the code path that does the thing:

| Metric | Where it is set |
|---|---|
| `orbit_enrollments_total{result}` | `internal/api/server.go:355-394`, results `ok`, `rejected`, `bad_request`, `error` |
| `orbit_certificates_issued_total{reason}` | reasons `enroll` (`server.go:395`), `renew` (`server.go:578`), `claim` (`internal/api/join.go:128`) |
| `orbit_agent_poll_fallback_total` | `internal/api/watch.go:47`, watcher cap only |
| `orbit_watch_connections` | `internal/api/watch.go:68-69` |
| `orbit_config_reverts_total` | `internal/api/server.go:536` |
| `orbit_epoch_notifications_total{kind}` | `internal/notify/notify.go:185` |
| `orbit_epoch_listener_up` | `internal/notify/notify.go:85-90` |

State gauges, read from Postgres in one query at scrape time (`internal/metrics/collector.go`,
`internal/store/stats.go:55`): `orbit_config_epoch`, `orbit_blocklist_epoch`, `orbit_hosts_total`,
`orbit_hosts_config_converged`, `orbit_hosts_blocklist_converged`, `orbit_convergence_lag_seconds`,
`orbit_certificates_expiring_soon`, `orbit_certificate_min_remaining_seconds`,
`orbit_blocklist_entries`, plus `orbit_db_scrape_up` and `orbit_db_scrape_failures_total`. All
labelled by network and nothing finer, because a gauge per host is a time series per machine
(`internal/store/stats.go:9-15`). Served on `127.0.0.1:9464` by default
(`cmd/orbitd/main.go:251`); with `--metrics-addr ""` the process logs "metrics disabled;
convergence and log lines are the only signals" and that is literally true.

There are no HTTP metrics of any kind. `internal/api/middleware.go:75-90` logs every request with
method, path, route (`r.Pattern`, a closed set), status and `durationMs`; `levelFor` puts 5xx at
Error and everything else — including every 4xx on an internet-facing listener — at Info. Request
rate, error rate and latency are log-pipeline questions, not metric questions.

### Health and readiness already answer different questions

`/healthz` is always 200 and touches nothing (`internal/api/server.go:616-632`): a liveness probe
that consulted Postgres would turn one database outage into every replica restarting at once,
destroying the parked watchers and the LISTEN connection that let the fleet recover the instant
Postgres returns. The body still carries the last observation, with `status: degraded` and an
`observed_age_seconds`, because `curl /healthz` is what a human reaches for.

`/readyz` performs a real round trip to Postgres — not a pool statistic — behind a 2 s cache and a
2 s timeout, and answers 503 when it fails (`server.go:634-720`). Push being down is reported in
the body and never fails readiness: agents fall back to polling, which is slower and entirely
correct.

### The revocation path, and what bounds it

`Tx.BlockHost` revokes every active certificate, writes the fingerprints, suspends the host and
advances the blocklist epoch in one transaction (`internal/store/revocation.go:31`). `BumpEpoch`
issues `NOTIFY orbit_epoch`, which Postgres delivers on commit, so a rolled-back block cannot wake
anyone and a committed one cannot fail to (`internal/notify/notify.go:1-13`). Every replica's
notifier wakes its per-network subscribers; `handleAgentWatch` subscribes *before* reading state,
holds for 30 s by default (5 min max), and answers immediately if the agent is already behind
(`internal/api/watch.go`).

Two bounds, and they differ by an order of magnitude:

- **Push up.** Distribution is single-digit milliseconds; the floor is nebula's own
  `timers.connection_alive_interval`, 5 s, which no control plane can remove. `e2e/revocation_test.go`
  measures block-commit to tunnel-teardown from nebula's hostmap and asserts p50 ≤ 15 s, max ≤ 45 s
  (`e2e/revocation_test.go:52`).
- **Push down.** `DefaultRunOptions` is `Hold: 30s, Interval: 60s, Jitter: 0.2`
  (`internal/agent/loop.go:1048`), so the worst case is a 72 s poll plus apply plus 5 s.

The fallback is a one-way door within a process lifetime. In `Loop.Run`, a single 503 from a watch
sets `push = false` for the rest of the run (`internal/agent/loop.go:1073-1079`). A replica
shedding watchers at `--max-watchers` (5000/network default) therefore demotes those agents to
60-second convergence permanently, not until the cap clears. `orbit_agent_poll_fallback_total`
counts that refusal once, and only for the cap path — a server built with no notifier answers 503
from `watch.go:37-41` without incrementing anything.

### Convergence, and why a stuck one looks like nothing

`Tx.Convergence` counts memberships in state `enrolled` or `active` whose `applied_*_epoch` is at
least the network's current epoch (`internal/store/revocation.go:231`). Agents report only after a
successful apply, never after a fetch (`internal/agent/loop.go:914-920`), and a report can lower a
recorded epoch only when it names the epoch it reverted from and that name matches
(`internal/store/host.go:427`). This is the number that gates CA activation: `handleActivateCA`
returns 409 with the lagging hosts named unless `acknowledge_cutoff` is set, and the override is
audited as `ca.force_activated` rather than `ca.activated`
(`internal/api/resources.go:1383-1456`).

So convergence stuck below 100% is an outage with a delayed fuse: revocation has not reached
somebody, and the next CA rotation will refuse. **And the metric that is documented as the alert
cannot see it.** `orbit_convergence_lag_seconds` is
`max(now - device.last_seen_at)` over un-converged hosts (`internal/store/stats.go:76-81`), and
`last_seen_at` is stamped on *every poll and watch*, not on every apply — `enroll.Service.State`
calls `TouchDevice` first thing (`internal/enroll/service.go:436-453`, `internal/store/host.go:1011`).
A host that is talking to the control plane every 30 seconds and refusing to apply holds the lag
gauge under one poll interval forever. The documented `orbit_convergence_lag_seconds > 300` alert
(`docs/deployment.md:746`, `docs/revocation.md:303`) will never fire for it.

That host is not hypothetical. Three code paths produce exactly it:

- A generation the agent quarantines after a failed apply or a failed restart, refused for the
  30-minute quarantine window and re-offered by the server on every watch
  (`internal/agent/loop.go:1100`, `watchRefused`).
- A host whose guard reverted a pushed generation; it is talking, and it is behind.
- A never-enrolled host restored by `UnblockHost`, which sits in the denominator and can never
  report an epoch. The docstring says what that cost: "One unblock of a never-enrolled host blocked
  CA rotation for that network indefinitely" (`internal/store/revocation.go:132-148`).

The number that does move in all three cases is `orbit_hosts_config_converged < orbit_hosts_total`,
and nothing alerts on it.

### What the docs claim that the code does not do

- `docs/deployment.md:751` alerts on `orbit_certificates_issued_total{reason="recover"}`. No code
  path emits that label value; the reasons are `enroll`, `renew`, `claim`. The alert cannot fire.
  The log line it pairs with, "host recovered after certificate expiry" (`deployment.md:851`), does
  not exist in the source either.
- `docs/revocation.md:233` shows the convergence endpoint returning `p50_ms`, `p95_ms`,
  `p99_ms`. `wire.ConvergenceResponse` has no percentile fields (`internal/wire/wire.go:515-524`)
  and nothing computes them.
- `docs/revocation.md:5.3` asserts `p50 < 1s`, `p95 < 2s`, `p99 < 5s`, `max < 60s`. The test
  asserts p50 ≤ 15 s and max ≤ 45 s. README's "**5.24 seconds** … An e2e test fails if that
  regresses" (`README.md:195`) is true only of a threefold regression.

### What is not measured at all

`req.DataPlaneDown` — a host whose agent is healthy and whose nebula is not — is logged at Error
and counted nowhere (`internal/api/server.go:550`), and the comment says why it matters: "it is
converged on paper and carrying no traffic". The maintenance sweep (`internal/sched`, 15-minute
default) prunes the blocklist, detects an expired active CA and reports overdue renewals, and emits
no metric of any kind — if it stops running, nothing changes shape. An expired *CA* has no gauge:
`orbit_certificate_min_remaining_seconds` reads `orbit.certificate` joined to memberships
(`internal/store/stats.go:86-89`), not `orbit.ca`, so the fleet-wide enrollment-and-renewal outage
that an expired signer causes is visible only as a log line and as rising
`orbit_enrollments_total{result="error"}`. Renewal failures on the agent surface are logged and not
counted (`internal/api/server.go:574`) — `orbit_certificates_issued_total{reason="renew"}` counts
successes only. Live replica count is in `orbit.control_plane.last_seen_at`
(`internal/store/address.go:526`) and is not exported. Agents export no metrics at all; the only
agent-side surface is the read-only unix status socket in `docs/diagnostics.md`.

## Decision

We measure to defend four stated objectives, and we alert on six signals. Anything else in
`/metrics` is a dashboard or a forensic aid, and adding a metric does not create an alert.

**The objectives.**

| # | Objective | Bound |
|---|---|---|
| O1 | Block committed → tunnel torn down, for a connected host, push up | p50 ≤ 15 s, max ≤ 45 s (`e2e/revocation_test.go:52`) |
| O2 | Same, push down | ≤ 90 s (72 s jittered poll + apply + 5 s) |
| O3 | Every `enrolled`/`active` membership on the current config epoch | within 15 minutes of the bump |
| O4 | No active certificate below 25% of its lifetime | continuously |

O1 and O2 are the revocation SLO. O3 is what the CA rotation gate reads. O4 is the thing that
takes hosts off the network silently if renewal breaks. README's 5.24 s is a measurement, not the
objective; the objective is the budget the test asserts, and the README will be corrected to say so.

**The six signals.**

| Signal | Fires when | What the operator does |
|---|---|---|
| `orbit_db_scrape_up == 0` for 2 scrapes | serving without Postgres | Page. Confirm with `/readyz` (503 with `"database": false`); fix Postgres. Do not restart `orbitd` — liveness deliberately ignores the database (`server.go:616-624`). |
| `orbit_hosts_config_converged < orbit_hosts_total` for 15 min | O3 breached; the rotation gate will refuse | Ticket. `GET /v1/networks/{id}/convergence` names the hosts; check the audit log for `host.config_reverted` and the report handler's quarantine warning. This is the signal that the lag gauge cannot produce. |
| `orbit_convergence_lag_seconds > 300` | a host is behind **and** silent for 5 min | Page. That host is not receiving revocations at all; ADR-0002 says its certificate TTL is the only remaining bound. |
| `orbit_epoch_listener_up == 0` for 5 min | push is down; O1 has degraded to O2 fleet-wide | Page, **only where push is configured**. With `--no-push` the gauge is 0 forever and the alert must not be deployed. |
| `orbit_certificates_expiring_soon > 0` | O4 breached | Ticket. The control plane cannot renew on a host's behalf; the host holds the key. `orbit_certificate_min_remaining_seconds` says how long there is. |
| `increase(orbit_config_reverts_total) > 0` | a pushed generation severed hosts | Page. More than one host means the push broke the fleet; those hosts are running the previous generation and have quarantined the new one for 30 minutes. |

**Deliberately not alerted on**, and each for a reason:

- `orbit_watch_connections` — capacity, not correctness. It falls for benign reasons (deploys,
  agent restarts) and its interesting failure is covered by the next line.
- `orbit_agent_poll_fallback_total` — a ticket, not a page. The cap fails soft and polling is
  correct. It is a ticket rather than nothing because the fallback is permanent per agent process
  (`loop.go:1073-1079`): after raising `--max-watchers`, the agents must be restarted to get push
  back, and nobody will know to do that from the gauge alone.
- `orbit_enrollments_total{result="rejected"}` and `{result="bad_request"}` — the enrollment
  listener is internet-facing. Alerting here means alerting on scanners, which is the same
  judgement `levelFor` already makes by keeping 4xx at Info (`middleware.go:92-110`).
- `orbit_blocklist_entries`, `orbit_config_epoch`, `orbit_blocklist_epoch`, `orbit_hosts_total` —
  inputs to the alerts above and context during an incident. An epoch that stops advancing is not a
  fault; an epoch that advances is not either.
- Go runtime collectors and RSS — `docs/deployment.md:900` already reached the right conclusion:
  alert on the process restarting, which the scrape target's `up` already gives.
- `/healthz` — it is 200 by construction, so an alert on it can only fire when the process is gone,
  which `up == 0` says first and more cheaply.
- Admin API latency percentiles — nobody's incident starts there, and the request log already
  carries `route` and `durationMs` if it ever does.

**Four gauges and counters we commit to adding**, because each closes a failure that today has no
metric, and each maps to one of the six above:

1. `orbit_hosts_data_plane_down` (per network) — from the `DataPlaneDown` reports at
   `server.go:550`. A host converged on paper and carrying no traffic must not be counted as healthy
   by O3.
2. `orbit_ca_min_remaining_seconds` (per network, from `orbit.ca`) — an expired active signer is a
   fleet-wide enrollment and renewal outage and currently has only a log line.
3. `orbit_maintenance_last_success_seconds` — a sweep that has stopped is invisible; blocklist
   pruning and expired-CA detection stop with it.
4. `orbit_renewals_failed_total` — `certificates_issued_total{reason="renew"}` counts successes,
   so a fleet failing renewal shows up only when O4 trips, weeks later.

Signals arrive with the operator action written down, or they do not arrive. `reason="recover"` in
`docs/deployment.md` is what the absence of that rule produces: an alert on a label nothing emits,
which nobody noticed because nobody had to say what to do when it fired.

## Alternatives considered

**Histograms for convergence lag and certificate expiry** — the original design in
`docs/revocation.md:5.4`. Rejected, and already rejected in the code: a histogram measures the
distribution of completed events, and both of these are *levels*. At any instant a host either is
or is not behind, and what matters is how long the worst one has been — a question a gauge answers
directly and a histogram cannot answer without inventing an event to observe
(`internal/store/stats.go:26-34`).

**Per-host or per-membership labelled gauges.** Rejected: one time series per machine makes
Prometheus the most expensive component of a deployment that otherwise runs on one 2 vCPU VM. The
per-host answer already exists at `GET /v1/networks/{id}/convergence`, which is queried when
somebody is actually looking (`internal/store/stats.go:9-15`).

**Fleet gauges maintained in process memory on a background ticker.** Rejected: two replicas would
keep separate counts of one fleet and disagree, every restart would reset convergence to zero, and
the exported value would be stale by up to the ticker period with no way to tell by how much. For
the metric that gates CA rotation, that is worse than having no metric
(`internal/metrics/collector.go:13-20`).

**Full RED metrics on every HTTP route** — request counter and latency histogram labelled by
`r.Pattern`. Seriously considered, because `r.Pattern` is a closed set and therefore safe to label
on (`middleware.go:81-85`). Rejected for now on the grounds that it answers no question in the six
above: enrollment outcomes are already counted by class, and the failures that actually hurt
(revocation not landing, renewal not happening, convergence stuck) are all invisible in request
statistics — every one of them is a 200. The two specific error paths worth counting get counters
of their own instead, above.

**A synthetic canary: block a throwaway membership every N minutes and measure real
block-to-teardown.** This is the only thing that would measure O1 in production rather than in CI.
Rejected as specified: it writes `membership.blocked` to the audit log on a timer, advances the
blocklist epoch of a real network, and makes every host in that network re-render and reload its
configuration on a schedule — turning the measurement into a fleet-wide load generator and the
audit trail into noise. Revisit when a dedicated canary network is cheap to stand up, which is the
form this should take.

**Alerting on `/readyz` from the monitoring system instead of `orbit_db_scrape_up`.** Rejected as a
duplicate with worse properties: readiness is what the load balancer consumes, it is cached for 2 s
per replica, and a replica pulled from rotation is already the correct remedy. The metric is the
one that survives the replica being removed and still says why.

**Deriving push health from `orbit_epoch_notifications_total` going quiet.** Rejected: a network
with no changes is legitimately silent for days, so silence is not evidence. `orbit_epoch_listener_up`
reports the LISTEN state directly, and the notifier is the authority for it — the health probe reads
`Notifier.Up()` rather than the metrics collector for the same reason
(`internal/api/server.go:722-735`).

## Consequences

**Easy.** Six alerts fit on one page and every one has a named next step. An operator can be told
"if none of these are firing, the control plane is doing its job" and that sentence is defensible
against the code. The convergence-ratio alert is the same number the CA rotation gate reads, so a
quiet monitor means a rotation will not surprise anyone.

**Hard.** The convergence-ratio alert will be noisy in fleets with laptops that go home at night: a
machine that is off is un-converged, and O3 does not distinguish it from a machine that is refusing
to apply. That is why it is a 15-minute ticket rather than a page, and why the lag gauge stays as a
separate, sharper page. If the noise becomes unbearable the fix is to exclude hosts that have not
been seen for longer than the poll interval — which narrows the alert to exactly the stuck case
this ADR was written about — and that is a schema-free change to `FleetStats`.

**Honest gaps this decision does not close.** A lighthouse that is up but not punching, a policy
that compiles to an empty ruleset, a relay saturating its uplink, and everything on the agent side
remain unmeasured. Agents export no metrics at all — only the read-only unix socket in
`docs/diagnostics.md` — so per-host diagnosis is still `orbit status` on the box. This ADR does not
propose an agent metrics endpoint; it proposes admitting that the control plane's view of a host is
"what that host last told us it applied", and that this is exactly why `DataPlaneDown` needs a
counter.

**Committed to.** Metrics stay labelled by network and nothing finer. Fleet state stays read from
Postgres at scrape time. Every new signal ships with its operator action and with a docs entry that
names only labels the code emits — the four discrepancies in the Context section get fixed with
this ADR, not later.

**Revisit if** the fleet outgrows what one Postgres can hold in LISTEN connections — the notifier's
own doc puts that in the five figures of hosts (`internal/notify/notify.go:8-12`) — because the
watcher gauge stops being a dashboard and becomes a capacity alert at that point. Also revisit if a
second control-plane component appears: these six signals all assume one process type, and the
"is it healthy" question is currently answerable because there is only one thing to ask about.

## References

- `internal/metrics/metrics.go`, `internal/metrics/collector.go` — the two halves and why they are separate
- `internal/store/stats.go:55` — `FleetStats`, one query per scrape, network-labelled
- `internal/store/revocation.go:31,132,231` — `BlockHost`, `UnblockHost`, `Convergence`
- `internal/store/host.go:427,1011` — `RecordAgentReport` monotonicity and the revert exception; `TouchDevice`
- `internal/enroll/service.go:436-453` — every poll stamps `last_seen_at`, which is what makes the lag gauge a silence detector
- `internal/api/server.go:530-555,616-735` — revert and data-plane-down handling; liveness vs readiness
- `internal/api/watch.go` — long poll, watcher cap, the 503 that demotes an agent
- `internal/agent/loop.go:914-920,1048,1073-1079` — report-after-apply, poll cadence, the one-way fallback
- `internal/api/resources.go:1383-1456` — convergence gating CA activation, and `ca.force_activated`
- `internal/sched/sched.go` — the maintenance sweep, entirely unmetered
- `e2e/revocation_test.go:52` — the asserted propagation budget
- `docs/deployment.md:729-860`, `docs/revocation.md:5` — the existing operator documentation, including the four claims corrected above
- ADR-0002 — why an unmeasured propagation claim is a marketing claim
- ADR-0003 — the revocation semantics these objectives defend
