# Architecture Decision Records

An ADR records a decision that was hard to make, together with the alternatives that were
rejected and why. It is not documentation of how the system works — `docs/` already does that.
It is the reasoning, written down at the moment it was still contested, so that a year later
nobody has to reconstruct it from the diff.

## When to write one

Write an ADR when a choice is **expensive to reverse** or **surprising without context**:

- A protocol or wire-format decision
- A dependency that becomes load-bearing
- A security property the design commits to (or deliberately declines)
- A default whose value is the product (a TTL, an SLA, a failure mode)
- Anything where a reasonable engineer would later ask "why on earth is it like this?"

Do **not** write one for a refactor, a naming choice, or a decision with an obvious answer.

## Process

1. Copy `0000-template.md` to the next free number. Numbers are never reused.
2. Open it as `Proposed`. Discuss on the PR.
3. Merge as `Accepted`. The decision is in force from that moment.
4. To change course, write a **new** ADR that supersedes the old one. Never edit an accepted
   ADR's Decision section — set its status to `Superseded by ADR-NNNN` and leave the text intact.
   The record of what we believed and when is the point.

## Status values

| Status | Meaning |
|---|---|
| `Proposed` | Under discussion, not in force |
| `Accepted` | In force |
| `Superseded by ADR-NNNN` | Replaced; kept for the record |
| `Deprecated` | No longer relevant, not replaced |

## Index

| # | Title | Status |
|---|---|---|
| [0001](0001-nebula-as-a-vendored-library.md) | Nebula as a vendored library, not a subprocess | Accepted |
| [0002](0002-fail-static-control-plane.md) | The control plane fails static | Accepted |
| [0003](0003-revocation-terminates-live-sessions.md) | Revocation terminates live sessions | Accepted |
| [0004](0004-no-cli-framework.md) | The CLI stays on stdlib `flag` | Accepted |
| [0005](0005-no-compatibility-before-v1.md) | No backward compatibility before v1.0 | Accepted |
| [0006](0006-code-must-be-reachable.md) | Code must be reachable from `main` | Accepted |
