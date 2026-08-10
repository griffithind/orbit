# ADR-0006: Code must be reachable from `main`

**Status:** Accepted
**Date:** 2026-08-10

## Context

Two `deadcode` runs, and the gap between them *is* the finding:

| Query | Meaning | Result |
|---|---|---|
| `deadcode -test ./...` | unreachable from anything, tests included | **23 functions** |
| `deadcode -test ./cmd/...` | unreachable from the shipped binaries | **71 functions** |

The 23 are ordinary cruft. **The 48-function difference is the pathology**: code reachable only
from its own tests and never from `main`. It is invisible to CI, invisible to coverage, and reads
as a working feature in review and in the docs.

This has already produced three production bugs.

The clearest single case: `internal/ca/x509.go` is 225 lines that issue X.509 device certificates,
with two dedicated tests (`TestIssueDeviceCert`,
`TestIssueDeviceCertSignatureVerifiesAgainstTheCAKey`). Nothing outside that test file calls it. It
was designed, implemented, tested and documented — and never connected to anything.

The expensive cases are the ones that look wired and are not:

- **`Loop.Run`** implements the push channel, config-integrity self-heal and host reconciliation.
  The daemon calls `Loop.Tick` (`cmd/orbit/agent.go:851`), which has none of them. About 1,200
  lines — nftables programming, policy routing, the DNS resolver, the exit-node escape hatch — do
  not execute in production. `e2e/revocation_test.go` calls `Loop.Run` *directly*, so the suite
  measures a path the daemon never takes, and the revocation SLA it reports is not the one
  operators get.
- **`restartRequiredEpoch`** (`internal/agent/loop.go:535`) is `_ = resp; return 0` beneath a
  five-line comment describing idempotent restart semantics the body cannot produce. The field it
  ignores exists in `wire`, is populated by the control plane, and is rendered in the UI.

The tests pass in every one of these cases. That is the point: **test coverage does not imply
reachability**, and a well-tested unreachable function is indistinguishable from a working feature
in CI, in review, and in the docs.

## Decision

Unreachable code does not merge.

1. **`deadcode` runs in CI over `./cmd/...`**, not `./...`, and the build fails on any function
   unreachable from a binary entry point. The narrower query is the whole point: `./...` reports
   only 23 findings because a test counts as a caller, which is exactly the blind spot that let
   `Loop.Run` and `internal/ca/x509.go` ship unwired.
2. **A subsystem lands wired or it does not land.** No merging a complete, tested component with
   its call site "to follow." If it cannot be reached from `main`, it is not finished.
3. **Existing findings are triaged before the gate is enabled**, into exactly two buckets — *wire
   it* or *delete it*. There is no third bucket, and "keep it for later" is the third bucket.

An allowlist file exists for genuine exceptions — platform-specific implementations that are
unreachable on the CI host, and nothing else. Every entry carries a one-line reason. A growing
allowlist is the signal that this ADR is being evaded.

## Alternatives considered

**A periodic manual sweep.** Rejected: the current 71 functions accumulated under exactly that
policy. A check that depends on somebody remembering is not a check.

**Lint for unused *unexported* symbols only** (which the compiler nearly gives us). Rejected: it
catches none of the real cases. Every function in this ADR's evidence is exported, or is a method
on an exported type, and would pass.

**Delete `Loop.Run` and its subsystems rather than wiring them.** Considered seriously, because
"whatever is not needed shouldn't exist" would allow it. Rejected on the merits: the push channel
is the revocation differentiator, and host reconciliation prevents an exit node from routing
Nebula's own UDP into its own tunnel. These are wanted features that were never connected — the
correct fix is connection, not deletion. That judgement is exactly what the triage in point 3 is
for, and it must be made per subsystem rather than by policy.

## Consequences

**Easy.** The dead-code question becomes mechanical instead of a matter of taste. Reviewers stop
having to guess whether a new exported helper has a caller coming.

**Hard.** Legitimate work-in-progress needs a branch rather than a merge, and speculative
abstractions — the four `*Func` adapter types in `internal/agent`, built for tests that do not use
them — become impossible to land. That is the intended effect and it will occasionally be annoying.

**A real limitation, stated plainly.** `deadcode` performs static reachability analysis. Code
reached only through reflection, build tags for other platforms, or `go:linkname` will be reported
as dead. The allowlist covers this, and its size is the metric to watch.

**Committed to.** Running the triage before turning the gate on. Enabling it against 71 existing
findings would either block all work or force a blanket allowlist, and a blanket allowlist is
indistinguishable from not having the gate.

## References

- `deadcode -test ./cmd/...` — 71 findings, 38 in `internal/agent`
- `internal/ca/x509.go` — 225 lines, tested, zero non-test callers
- `internal/agent/loop.go:535` — `restartRequiredEpoch`
- `internal/agent/loop.go:991` vs `cmd/orbit/agent.go:851` — `Run` vs `Tick`
- `e2e/revocation_test.go:155` — the suite exercising a path production does not run
- ADR-0003 — the revocation SLA this bug undercuts
