# ADR-0017: Every platform we tag for is a platform the gates analyse

**Status:** Accepted
**Date:** 2026-08-12

## Context

ADR-0006 says code must be reachable from `main`, and CI enforces it with two `deadcode` gates:
one scoped to `./cmd/...` with an allow file, and one over `./...` with no exemptions at all.
Both ran exactly once, on the runner's own `GOOS`.

The agent is the part of this repository with platform-specific code, and it has eighteen
platform-tagged files. Three of them — `escapehatch_other.go`, `dns_other.go`,
`dnsapply_other.go` — carry `//go:build !linux && !darwin`, so they are in neither the Linux
nor the macOS build. A gate that runs on one `GOOS` cannot see them, and cannot see what
happens to shared code when they are the ones selected.

That blind spot produced a real orphan, found by running the gate under a foreign `GOOS`:

```
=== gate as CI ran it (host = darwin) ===
0
=== same gate, GOOS=freebsd ===
internal/agent/hostcfg/dns.go:372:6: unreachable func: isOwnResolver
internal/agent/hostcfg/dns.go:378:6: unreachable func: hostPort53
```

Both functions lived in `dns.go`, which every platform compiles, while their only callers were
`dns_linux.go` and `dns_darwin.go`. On any other `GOOS` they were dead, and the gate that
exists to catch exactly that reported clean.

This is the third variant of one mistake in this package. The first was an orphan that failed
to type-check (`dns_other.go` left behind by the agent split). The second was a test file
orphaned by the same move, which `go build` does not compile — the reason the vet step exists
and says so. The third is an orphan that compiles perfectly on every platform and is called by
nobody on most of them. `vet` catches the first two and has no unused-function analysis, so
only `deadcode` can catch the third — and only if it is pointed at the platform where the code
is dead.

There is an implementation trap in the fix, and it is silent.
`GOOS=freebsd go run golang.org/x/tools/cmd/deadcode@latest ...` cross-compiles **the tool**
rather than changing the analysis target, and produces empty output. A CI step written that way
is green because it analysed nothing. The tool must be `go install`ed once for the host and the
resulting binary then run with `GOOS` set.

Two related gaps in the same family, verified and not closed by this decision:

- The vet loop runs `GOARCH=amd64` only, while `release.yml:149` and `Makefile:33` both ship
  `darwin/arm64` and `linux/arm64`. Two published architectures are never type-checked.
- Every job in both workflows is `runs-on: ubuntu-latest`. The macOS-specific code is
  type-checked and never *executed* — zero darwin tests have run in CI.

## Decision

The unexempted gate runs once per `GOOS` in the build-tag set — `linux`, `darwin`, `freebsd`,
`windows` — the same list the vet loop already uses, and its results are concatenated before
the check. `deadcode` is installed once with `GOBIN` and then invoked with `GOOS` set, never
via `go run` under a foreign `GOOS`, and the step carries a comment saying why.

Code whose callers are all on one platform lives in a file tagged for that platform. Where a
symbol is written on every platform and read on only some — `ownResolvers` is the case that
prompted this — the write stays in the shared file and the readers move, with a comment at each
end naming the other.

The narrowly-scoped first gate stays on the host `GOOS`. Its scope is `./cmd/...` and its
purpose is "nothing in the binaries is unreachable", which is a per-binary question already
covered by an allow file that carries per-platform entries. Widening it would multiply the
allow file by four for no additional finding.

## Alternatives considered

**Run the full test suite on a macOS runner.** This would close the larger gap — code that is
type-checked but never executed — and it is the right thing eventually. Rejected for now
because it is a different decision with a different cost (runner minutes, a Postgres service on
macOS, the e2e suite's assumptions about the host), and bundling it here would stall a fix that
is four lines of YAML.

**Add a `//go:build` lint that forbids shared files from holding platform-only helpers.** There
is no such analyser, and writing one means encoding "which callers exist" — which is what
`deadcode` already computes correctly. Rejected as reimplementing the tool we have.

**Move the two helpers into `dns_linux.go` and `dns_darwin.go` as duplicates.** Rejected: two
copies of a loop guard is how the two copies drift, and the second gate would not catch it
because both would have callers.

**Widen the vet loop to every published `GOARCH` in the same change.** Correct and cheap, but
it is a separate finding with a separate justification, and it belongs in its own change rather
than riding along under this ADR's title.

## Consequences

The gate is roughly four times slower. Measured on this repository it is seconds, because the
analysis is the cost and the module is small; that will not stay true forever, and the first
time it becomes a real part of PR latency is the moment to reconsider the platform list rather
than the gate.

Adding a `GOOS` to the build-tag set now means adding it to two loops, and forgetting the
second one restores exactly the blindness this closes. The two loops sit adjacent in
`ci.yml` and both carry the list inline, which is the cheapest form of that coupling that does
not require a shared file.

We are now committed to the vendored nebula (ADR-0001) type-checking on all four platforms,
since `deadcode` compiles the whole program. That is already true and worth stating: a nebula
bump that breaks a platform we do not ship for will now fail CI.

The two gaps left open — `GOARCH` coverage and darwin execution — are recorded here rather
than fixed here. What would trigger revisiting: shipping a Windows or FreeBSD artifact, which
turns "type-checks" into a claim we would be making to users. ADR-0018 takes that up for
Windows.

## References

- `.github/workflows/ci.yml` — the two gates and the two loops
- `internal/agent/hostcfg/dns_unix.go` — where the two orphans now live
- `internal/agent/hostcfg/dns.go` — `ownResolvers`, written everywhere, read on two platforms
- `.github/workflows/release.yml:149`, `Makefile:33` — the published `GOARCH` set
- ADR-0006 (code must be reachable from `main`) — the rule this enforces
- ADR-0001 (nebula as a vendored library) — why the whole program compiles per platform
