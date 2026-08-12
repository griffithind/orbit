# ADR-0026: A process that disagrees with the schema refuses to serve

**Status:** Proposed
**Date:** 2026-08-12

## Context

A forward-only migration runner exists and works: `internal/db/migrate.go:63-140`, keyed on file
name in `orbit.schema_migration`, one transaction per file. ADR-0005's collapse of twenty-six
migrations into `0001_initial.sql` did not remove that capability. The gaps are all around it.

**`serve` performs no schema check whatsoever.** A repository-wide grep for `schema_migration`
finds `cmd/orbitd/doctor.go:195` and `internal/db/migrate.go`, and nothing else. An `orbitd`
started against a database one migration behind starts cleanly, opens the vault, joins the mesh
and answers `/readyz` 200 — then fails on the first request that touches the new column, as an
HTTP 500 with a pgx "column does not exist", at an unpredictable hour. Contrast the KEK, which
*is* verified at startup precisely so a mistake fails in the first second
(`cmd/orbitd/main.go:293-303`, ADR-0007). The schema is the same class of prerequisite and gets
none of the same treatment.

**`doctor` compares counts, not names, and misdiagnoses the direction.**
`cmd/orbitd/doctor.go:193-196` runs `SELECT count(*) FROM orbit.schema_migration` against
`len(db.Migrations())`. On a pre-collapse database that is 26 applied against 1 bundled, so the
`default:` branch at `:212-219` reports "this database was migrated by a **newer** orbitd". The
database is older. The advice points the operator the wrong way. Counts also cannot see the
general drift case at all: N applied and N bundled with different names reports "up to date".

**The collapse orphaned every pre-collapse database.** Such a database has 26 rows, none named
`0001_initial.sql`, so `Migrate` treats the collapsed file as pending and re-runs all 836 lines.
It fails — `0001_initial.sql:22` is `CREATE FUNCTION` with no `OR REPLACE`, `:34` is
`CREATE TABLE` with no `IF NOT EXISTS` — and it fails *safely*, one transaction per file, so
nothing is half-applied. But the operator gets a bare Postgres "already exists". ADR-0005
licenses this as "safe exactly once"; that safety rests entirely on nothing being deployed, and
that premise is invisible at 3am.

**The documented upgrade procedure migrates with the old binary.** `docs/deployment.md:934-939`
is stop → `orbitd migrate` → install the new binary → start. Step 2 runs the *currently
installed* binary, whose `embed.FS` holds the old migration set; it applies nothing and prints
"database is up to date". The new binary then serves against an un-migrated database. The manual
produces the failure.

**Version skew across the wire fails hard, in the direction a fleet upgrade takes.** Every
request body is decoded with `DisallowUnknownFields()` (`internal/api/server.go:816-818`),
covering enroll, renew, report and all of join and admin. Old agent → new control plane is fine:
the old agent sends a subset, and the response path uses plain `json.Unmarshal`. New agent → old
control plane is a hard 400 for any added field — and it does not recover, because
`APIError.Retryable()` treats 4xx as permanent (`internal/agent/client.go:159-162`) and failover
rotates only on transport errors. An upgraded agent pinned to a not-yet-upgraded replica is
stuck: it will not retry and will not fail over.

Tailscale's answer to that last problem is the instructive one, and not in the way it first
appears. They have `CapabilityVersion`, a monotonic integer currently at 145
(`tailcfg/tailcfg.go:197`) — but across those 145 versions there are only **two** `Cap >= N`
checks in non-test code. Everything else is absorbed at the deserialisation boundary:
`control/controlclient/map.go:385-415` normalises legacy shapes once, so no downstream code ever
sees a version. Their revealed preference over 145 versions is a **tolerant schema**, not a
version gate. `DisallowUnknownFields()` is the exact opposite policy.

## Decision

**`serve` verifies the applied migration set against its embedded set at startup, by name, and
exits if they differ.** Same disposition the vault already has: no degraded mode, no lazy
discovery on the first 500. A replica that cannot serve correctly must not answer `/readyz` 200.

**`doctor` compares names, reports which side is ahead correctly, and recognises a pre-collapse
database by name** — with a message saying "collapsed schema; this database predates it" rather
than "migrated by a newer orbitd".

**`DisallowUnknownFields()` comes off the agent surface** — enroll, renew, report — and stays on
the admin API, where a typo'd field should be an error rather than a silent no-op. A newer agent
talking to an older replica then degrades instead of 400ing.

**The documented upgrade order becomes install-then-migrate-then-start**, and the compose path
gets its own migrate step.

**A capability-version integer is explicitly declined for now.** Orbit ships two binaries from
one release; the schema-tolerance rule above buys most of the benefit at none of the cost. If it
is ever adopted, take the form Tailscale's k8s operator uses rather than their core capver — a
named constant with a written support window (`cmd/k8s-operator/proxygroup.go:70-74` commits to
three stable releases) — because the core capver's meaning lives only in comments and their own
test admits they have got it wrong repeatedly.

## Alternatives considered

**Check the schema lazily, on first use.** Rejected: that is the current behaviour, and the
whole complaint is that the failure surfaces at an unpredictable time as an opaque 500.

**Let `serve` migrate automatically at startup.** Tempting, and it removes the ordering problem
entirely. Rejected because with multiple replicas it means N processes racing to migrate, and
because a migration is the one operation an operator should perform deliberately with a backup
in hand.

**Keep strict decoding everywhere and require lockstep upgrades.** This is effectively today's
position and ADR-0009 states it. Rejected: "replicas must be upgraded together" is not made true
by anything in the code, and the failure it produces is an agent that will neither retry nor
fail over.

## Consequences

A schema mismatch becomes a refusal to start rather than a working control plane with a
landmine. On a rolling upgrade across a migration, that means the un-migrated replicas will not
come up — which is correct and is also a louder failure than today's silence.

Relaxing decoding on the agent surface means a genuinely malformed agent request is accepted and
ignored rather than rejected. That is the trade Tailscale made deliberately, and it costs a class
of typo detection that the admin API keeps.

We are committed to the migration set being compared by name, which makes the file names part of
the deployment contract — renaming a migration file becomes a breaking change.

What would trigger revisiting: v1.0 and the retirement of ADR-0005. At that point compatibility
becomes a promise rather than a convenience, and a capability version may earn its cost.

## References

- `internal/db/migrate.go:63-140` — the runner, keyed by file name
- `cmd/orbitd/doctor.go:193-196, 212-219` — the count comparison and the inverted diagnosis
- `internal/db/migrations/0001_initial.sql:22, 34` — why a re-run fails, and fails safely
- `docs/deployment.md:934-939` — the procedure that migrates with the old binary
- `internal/api/server.go:816-818`, `internal/agent/client.go:159-162` — strict decoding, permanent 4xx
- Tailscale `tailcfg/tailcfg.go:197`, `control/controlclient/map.go:385-415`,
  `cmd/k8s-operator/proxygroup.go:70-74`
- ADR-0005 (no compatibility before v1), ADR-0007 (key custody), ADR-0009 (replicas)
