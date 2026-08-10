# ADR-0004: The CLI stays on stdlib `flag`

**Status:** Proposed
**Date:** 2026-08-10

## Context

`cmd/orbit` is 7,130 lines of hand-rolled `flag.FlagSet` dispatch with 357 lines of tests, against
competitors — Tailscale especially — with genuinely excellent CLIs. The obvious move is to adopt a
framework. Measured against the actual constraints, it is the wrong one.

**On single-dash flags — an argument that does not survive ADR-0005, recorded because it was the
original reasoning.** Orbit's published syntax is single-dash-long (`-json`, `-root`, `-network`),
with 92 invocations in `e2e/*.go` and 66 in `docs/` and `README.md`. `spf13/pflag` — and therefore
cobra — parses `-json` as the shorthand cluster `-j -s -o -n` and fails; `SetNormalizeFunc` does
not help, because normalisation runs *after* shorthand splitting. `alecthomas/kong` shares the
limitation.

That looked disqualifying. It is not, because ADR-0005 permits rewriting all 158 call sites. The
decision below therefore rests on the remaining reasons, which are weaker individually and still
sufficient collectively. **If those reasons are ever judged insufficient, this ADR should be
superseded rather than quietly reinterpreted.**

`peterbourgon/ff` (both v3/ffcli and v4) fails differently and worse: `membership show web-01
--json` returns `json=false, err=nil`. ff/v4 additionally swallows *unknown* flags appearing after
a positional, silently. This is precisely the bug `parseFlags` (`cmd/orbit/main.go:145`) exists to
fix, and whose comment states the reason: silently unparsed flags "look like they worked."

Measured footprints (Go 1.26.5, darwin/arm64, probe binaries rather than documentation):

| Option | External modules | Packages | Binary |
|---|---|---|---|
| stdlib `flag` | **0** | 63 | 2556 KB |
| ff/v3 ffcli | 1 | 74 | 2712 KB |
| cobra | 2 | 87 | 3652 KB |
| urfave/cli/v3 | 1 | 81 | 4680 KB |
| kong | 1 | 83 | 5144 KB |

The peer cohort is unanimous in a way that is hard to dismiss: **slackhq/nebula** — Orbit's own
data plane — **coredns**, and **flannel** are all on stdlib `flag`; wireguard-go parses `os.Args`
directly; Tailscale is on ffcli with a custom usage function. Go's own `cmd/go` hand-rolls a
`base.Command` struct around `flag.FlagSet`.

Orbit has also already paid for things no framework provides. The exit-code classes
(`errors.go`: 0 ok, 1 failure, 2 usage, 3 unauthorized, 4 forbidden, 5 not found, 6 conflict,
7 unreachable) have no equivalent in any of them and would be reimplemented on top of whatever was
adopted. `emitJSON` writes the server's bytes verbatim so `orbit … -json | jq` and `curl … | jq`
are interchangeable — a property a framework's marshaller would quietly destroy.
`e2e/cli_test.go`'s `TestCLIDoesNotLinkTheDataPlane` already treats the CLI's dependency graph as a
CI-enforced boundary.

The one genuine gap is shell completion. Tailscale solved it for stdlib `flag` in roughly 500 lines
by vendoring cobra's Apache-2.0 completion scripts into `tempfork/spf13/cobra` and building
`ffcomplete` over them — explicitly, in their own README, *"to implement similar tab-completion for
ffcli and the standard library flag package."* Zero added modules.

## Decision

Stay on stdlib `flag`. Harden the in-house layer instead:

1. Extract a `command` struct — `name`, `aliases`, `short`, `long`, `flags`, `run`, `subs` —
   modelled on `cmd/go`'s `base.Command`, replacing `main.go`'s switch and the 17 group functions
   (~150 LOC, and it deletes the duplicated `subUsage`/`unknownSub` verb strings that have already
   drifted into two dialects).
2. Flip the 47 `flag.ExitOnError` to `ContinueOnError` and route errors through `exitCode`. Under
   `ExitOnError`, `fs.Parse` calls `os.Exit(2)` before returning — which makes **all 40
   `parseFlags` error checks unreachable today** and sends flag errors to real stderr rather than
   the `errOut` seam the tests use. There is a working template in the tree at
   `third_party/nebula/cmd/nebula-cert/`.
3. Vendor cobra's four completion scripts under `internal/cli/completion/` (Apache 2.0, attribution
   required), add a hidden `__complete` handler over the command tree, ship
   `orbit completion bash|zsh|fish|powershell`.
4. Adopt `--flag` as the canonical and documented spelling. Per ADR-0005 there is no compatibility
   obligation, so the single-dash spellings in `e2e/` and `docs/` are rewritten rather than
   aliased. Note that stdlib `flag` accepts both spellings regardless, so this is a documentation
   and test edit, not a parser change — which is precisely why the framework question is decided
   on `-json` *parsing* rather than on which spelling we prefer.

## Alternatives considered

**cobra.** Disqualified on `-json`. Also: a typo'd subcommand (`orbit membership shwo`) returns
`err == nil` and silently runs the parent with `"shwo"` as an argument unless every one of 18 group
commands sets `Args: cobra.NoArgs`, and forgetting one is invisible.

**kong.** Disqualified on `-json`. Its only completion path, `kongplete`, adds 5 modules and has
been unmaintained since November 2023.

**ff/v3 or ff/v4.** Disqualified on correctness — reintroduces the silent flag-swallowing bug.
ff/v4 is still `v4.0.0-beta.1` with its last commit in August 2025; ff/v3 last released July 2023.
Neither has any completion support at all.

**urfave/cli/v3.** The only framework that survives the constraints: genuinely zero third-party
dependencies, accepts `-json` and `--json` interchangeably, allows flags after positionals, ships
completion for four shells. If this ADR is overruled, this is the answer — not cobra. It is still a
rewrite of 7,100 lines to buy completion that costs 500.

## Consequences

**Easy.** Zero new modules on a binary that ships to every managed host. The exit-code classes,
`emitJSON` verbatim, `parseFlags`' interspersed-flag handling, the TTY-aware renderer, and
`announce()` all survive untouched. The dependency-graph test keeps meaning what it means.

**Hard.** We own the dispatcher, the help renderer, and the completion handler. That is real
maintenance, and the current code shows what happens when nobody owns it: 9 flag sets in
`membership.go` are still named `"host …"` and 16 usage strings print `usage: orbit host …` — a
command that does not exist — surviving the documented `host → membership` rename. The `command`
struct exists to make that class of drift impossible rather than merely unlikely.

**Committed to.** Completion becomes our code, and it must be tested. `orbit help --json` (the
analogue of Tailscale's `--json-docs`) is the mechanism: it walks the tree and emits every command,
flag and alias, which drives both documentation generation and the completion tests from one
source.

**Revisit if** we ever need Windows-native shell integration beyond what the vendored scripts give,
or if the command count roughly triples. At Tailscale's 134 commands the calculus would be
different; at Orbit's ~50 it is not close.

## References

- `cmd/orbit/main.go:145` — `parseFlags` and the bug it fixes
- `cmd/orbit/errors.go` — the exit-code classes
- `cmd/orbit/output.go:38` — `out`/`errOut` test seams; `emitJSON` verbatim contract
- `e2e/cli_test.go` — `TestCLIDoesNotLinkTheDataPlane`
- `tailscale.com/cmd/tailscale/cli/ffcomplete` and `tailscale.com/tempfork/spf13/cobra`
- `slackhq/nebula`, `coredns`, `flannel` — stdlib `flag` in the peer cohort
- Go `cmd/go/internal/base.Command`
