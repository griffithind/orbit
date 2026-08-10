# ADR-0005: No backward compatibility before v1.0

**Status:** Accepted
**Date:** 2026-08-10

## Context

Orbit is at v0.4.5 with no deployed fleet. Every compatibility constraint currently observed is
therefore self-imposed, and several are actively expensive:

- **The CLI carries a half-finished rename.** Nine flag sets in `cmd/orbit/membership.go` are still
  named `"host …"` and sixteen usage strings print `usage: orbit host …` — a command that does not
  exist — surviving the `host → membership` rename documented in `docs/model.md`.
- **The schema carries the same scar.** `0016_rename_host_to_membership.sql` renames a table and
  five columns; `0015`, `0019`, `0022` and `0023` drop columns. Twenty-six migrations encode the
  history of a product nobody has installed.
- **`internal/wire` drags the data plane into every client.** Two fields typed
  `fwmatch.Decision` make `wire → fwmatch → slackhq/nebula`, so `internal/adminclient` — a pure
  HTTP client — links nebula, gvisor and wireguard.
- **`internal/api` imports all 7,301 lines of `internal/agent`** for one call to
  `agent.DefaultRenewalPolicy()`.
- **Two API routes are frozen** (`?format=text`) with a comment in `internal/api/convergence.go`
  saying so, to protect `scripts/check-break-glass.sh`.

Preserving any of this costs real work — deprecation aliases, dual-write migrations, compat shims,
a `--flag`/`-flag` dual spelling — to protect users who do not exist.

## Decision

Until v1.0, Orbit makes **no backward-compatibility guarantee** at any layer: CLI surface, HTTP API
and wire format, database schema, Go package structure, or configuration file shape.

Concretely, this authorises and expects:

- Renaming or removing CLI commands and flags with no alias period.
- Restructuring the HTTP API and `internal/wire` DTOs freely.
- **Collapsing the 26 migrations into one clean initial schema**, discarding the rename and
  drop-column history.
- Splitting and moving Go packages without preserving import paths.
- Changing output formats, including the shift from space-padded to tab-separated piped tables.

Upgrading across any pre-v1.0 release may require re-bootstrapping the control plane and
re-enrolling every host. The README and `docs/deployment.md` must say so plainly, in those words.

At v1.0 this ADR is superseded: the CLI surface, the agent↔control-plane wire protocol, and the
schema become compatibility surfaces under a stated policy, and breaking any of them requires its
own ADR.

## Alternatives considered

**Maintain compatibility from now on.** Rejected: it freezes known-wrong shapes. The `host`/
`membership` split would be permanent, the nebula dependency in `adminclient` would be permanent,
and the migration history would be permanent — all to protect an empty fleet.

**Compatibility only for the agent wire path**, so deployed hosts survive. Rejected on the facts:
there are no deployed hosts. This is the right constraint *after* v1.0 and the wrong one now.

**Deprecation aliases with a two-release removal window.** Designed, then discarded. It is the
correct policy for a product with users and pure overhead for one without — and it would have
meant shipping `orbit agent uninstall` as an alias for `orbit leave` to nobody.

## Consequences

**Easy.** The redesigns can be clean rather than additive. The CLI can adopt `--flag` as the only
spelling instead of carrying both. The schema can be one file. `wire` can stop linking the data
plane. Package boundaries can be drawn where they belong rather than where they started.

**Hard.** Every doc example, every `e2e` invocation, and `scripts/check-break-glass.sh` change at
once — **92 single-dash flag invocations in `e2e/*.go` and 66 in `docs/` and `README.md`** for the
CLI alone. That is a mechanical but wide edit, and it must land as one change per layer rather than
dribbling, or the tree spends weeks in a state where the docs and the binary disagree.

**The dangerous part is the habit, not the change.** A team that has broken compatibility freely
for a year does not become careful on the day it tags v1.0. The mitigation is that this ADR names
its own expiry, and that the v1.0 checklist includes superseding it with a written policy for each
of the three surfaces.

**Committed to.** Saying so publicly. A pre-1.0 version number is not sufficient notice; the README
must state that upgrades may require re-enrolment, because the alternative is somebody discovering
it during an upgrade.

## References

- `cmd/orbit/membership.go` — nine `"host …"` flag sets, sixteen stale usage strings
- `migrations/0016_rename_host_to_membership.sql` and the drop-column migrations
- `internal/wire/wire.go:1227` — the `fwmatch.Decision` fields that link nebula
- `internal/api/resources.go:1080` — the single-symbol import of `internal/agent`
- `internal/api/convergence.go` — the frozen `?format=text` routes
- ADR-0004 — supersedes its `-flag` compatibility promise
