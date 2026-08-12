# ADR-0025: Quarantine does not gate revocation

**Status:** Proposed
**Date:** 2026-08-12

## Context

ADR-0003 commits to revocation terminating live sessions: a fingerprint reaches the blocklist,
every host renders it, and nebula tears the tunnel down. The delivery path is sound and was
re-verified for this ADR — `BlockHost` bumps the blocklist epoch, revokes the certificates and
inserts the blocklist entries in one transaction, `BumpEpoch` issues `pg_notify` inside it so
delivery is on commit, every replica's `LISTEN` fans out, the watch handler re-reads rather than
trusting the payload, and the renderer emits the list unconditionally "even when empty, so that
removing the last entry actually clears it" (`internal/nebulacfg/render.go:385-388`).

Two things sit on top of that path and defeat it.

**The revert guard refuses revocations.** `Loop.quarantined` keys on the **config** epoch alone:

```go
func (l *Loop) quarantined(configEpoch int64) bool {
	if l.State.QuarantinedConfigEpoch == 0 || configEpoch != l.State.QuarantinedConfigEpoch {
		return false
	}
	...
}
```

(`internal/agent/loop.go:599-610`). `BlockHost` bumps **only** `EpochBlocklist`
(`internal/store/revocation.go:37`) — unlike `DeleteHost`, which bumps config (`:120`). So a
host that quarantined config epoch N receives the revocation labelled config epoch N, matches
`QuarantinedConfigEpoch`, and refuses it (`loop.go:887-891`, `:1161-1165`). Default quarantine
is 30 minutes (`loop.go:357`). Worse, the guard's revert rolls `l.State.BlocklistEpoch` back to
`PrevBlocklistEpoch` (`loop.go:434`), reinstalling a **pre-revocation** blocklist on a host
that is by definition already in a bad state. No test covers a revocation delivered to a
quarantined host; the guard tests all exercise config generations.

**No deployed alert can see a stuck revocation.** The metric exists —
`orbit_hosts_blocklist_converged` (`internal/metrics/collector.go:66-67`) — and
`docs/deployment.md:775-777` puts it on the explicitly *not*-alerted list. The one convergence
alert is `orbit_hosts_config_converged < orbit_hosts_total`, and because a block does not move
the config epoch, that alert **structurally cannot fire** for a stuck revocation.
`orbit_convergence_lag_seconds` derives from `last_seen_at`, which `TouchDevice` stamps on every
poll — including a poll from a host that is refusing to apply. ADR-0002 commits to convergence
being "a first-class metric rather than an assumption"; it is a first-class gauge nobody watches.

A third, smaller defect in the same area: `BlocklistGrace` is justified at
`internal/sched/sched.go:33-36` as absorbing "clock skew between the control plane and a host",
but the grace applies only to **deletion** (`PruneBlocklist … not_after < $2`,
`revocation.go:212-214`) while **delivery** filters at `not_after > $2` with no grace at all
(`LiveBlocklist`, `:189-192`). The fingerprint stops reaching peers the instant the control
plane thinks it expired. The grace is on the wrong side of the boundary it was written for.

One correction to the record while we are here: `internal/store/revocation.go:182-184` and
`docs/revocation.md:196-198` both state that nebula "rejects an expired certificate before it
consults the blocklist". It is the other way round — `third_party/nebula/cert/ca_pool.go:211-213`
checks `IsBlocklisted` first and `c.Expired(now)` at `:228`. The conclusion those passages draw
survives; the stated ordering does not, and the ordering is what the grace argument rests on.

## Decision

**A blocklist generation is never quarantined.** The guard exists to stop a bad *configuration*
from being reapplied in a loop; a blocklist is not a configuration and cannot be the cause of
the unreachability the guard is reacting to. `quarantined` takes both epochs and refuses only
when the config epoch matches *and* the blocklist epoch has not advanced. The revert stops
rolling `BlocklistEpoch` back: a quarantined host keeps the newest blocklist it has seen, always.

**Blocking bumps the config epoch too**, per ADR-0022 — which makes the existing
`orbit_hosts_config_converged` alert cover stuck revocations as a side effect, and is the
cheaper half of the fix.

**`orbit_hosts_blocklist_converged` gets a written alert and a written action.** ADR-0008's own
rule is that a metric without an action is decoration. An unpropagated revocation is the one
condition where the gap between "we issued the instruction" and "it took effect" is the whole
security property.

**`BlocklistGrace` moves to `LiveBlocklist`'s predicate, or it is deleted.** A grace that
extends how long a dead fingerprint is *retained* while shortening nothing about how long it is
*delivered* does not do what its comment says.

## Alternatives considered

**Have the agent treat any blocklist change as urgent and bypass the whole apply pipeline.**
Attractive — it is the shape ADR-0003 implies — but rejected because the blocklist arrives
inside a signed generation, and a bypass would need its own verification path. Keeping it in the
generation and fixing the gate is smaller and keeps one signature check.

**Shorten the quarantine window.** Rejected as trading one silent failure for a shorter silent
failure. Thirty minutes is a reasonable window for the problem the guard actually solves.

**Alert on `orbit_convergence_lag_seconds` instead.** Rejected: it derives from `last_seen_at`,
which a refusing host still updates, so it reports healthy for exactly the host in question.
`docs/deployment.md:766-768` already admits this.

## Consequences

The guard becomes slightly more permissive, and that is a deliberate narrowing of a safety
mechanism: a host quarantined because a configuration made it unreachable will now still accept
blocklist updates. The risk is that a blocklist entry is itself what broke the host, which
cannot happen — a blocklist entry can only remove trust in a peer, never in the host's own
certificate.

Blocking becomes two fan-outs rather than one (ADR-0022), which is a real cost on every block.

We are committed to the guard's predicate naming both epochs, which makes adding a third epoch a
change to this decision rather than an implementation detail.

What would trigger revisiting: moving to a positive-list model, where a removed host is simply
absent from the netmap a reconnecting peer receives, as Tailscale does. That removes the
blocklist, the grace, the propagation metric and this ADR together — and it is the design
question ADR-0003's Consequences already asks.

## References

- `internal/agent/loop.go:599-610` — `quarantined`, config epoch only; `:434` — the blocklist rollback
- `internal/store/revocation.go:37, 120` — the bump that happens and the one that does not
- `internal/store/revocation.go:189-192, 212-214` — delivery without grace, deletion with it
- `internal/sched/sched.go:33-36` — the grace's stated purpose
- `third_party/nebula/cert/ca_pool.go:211-213, 228` — blocklist checked before expiry
- `internal/metrics/collector.go:66-67`, `docs/deployment.md:766-768, 775-777` — the unwatched gauge
- ADR-0002 (fail static), ADR-0003 (revocation terminates live sessions), ADR-0008, ADR-0022
