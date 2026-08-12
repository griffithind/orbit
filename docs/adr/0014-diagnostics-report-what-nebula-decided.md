# ADR-0014: Diagnostics report what nebula decided, not what we inferred

**Status:** Accepted
**Date:** 2026-08-12

## Context

`orbit peers`, `orbit why` and `orbit netcheck` exist to answer one question an operator has
when a tunnel is slow or absent: *where is the traffic actually going, and why*. Because
nebula runs in-process (ADR-0001), the agent can read nebula's own state directly rather than
scraping a subprocess. It does — `PeersFrom` in `internal/agent/status/status.go` walks the
hostmap and copies fields out of each `HostInfo`.

Copying is where the accuracy is lost. Four things were verified against the source.

**The relay predicate disagrees with nebula's.** `status.go:168` is
`func (p Peer) Relayed() bool { return len(p.RelaysToMe) > 0 }`. Nebula's own decision, at
`third_party/nebula/inside.go:347`, is `useRelay := !remote.IsValid() && !hostinfo.GetRemote().IsValid()`
— a peer is relayed when there is no usable direct remote, full stop. Nebula never removes a
relay from `relayState` once hole punching succeeds, so a tunnel that punched through
perfectly still has a non-empty `CurrentRelaysToMe` and still prints `relay`. The one field
that would answer the question correctly, `CurrentRemote`, is already copied at
`status.go:184-185` and is not consulted by the predicate. So the command reports the *history*
of a connection as if it were its state, and it reports it in the direction that makes a
working mesh look broken.

**`QueryLighthouse` is documented and never called.** `docs/diagnostics.md:19` lists it among
the nebula entry points the diagnostics are built on, and `:103` builds a whole diagnosis
around it — separating "policy says no" from "we never found each other". A search of the
repository outside `third_party/` finds the identifier in those two doc lines and nowhere
else. The distinction the document promises cannot be drawn.

**Underlay candidates are dropped.** `PeersFrom` copies `CurrentRemote` and
`CurrentRelaysToMe` and does not copy the candidate remote list. "We know four addresses for
this peer and none of them answered" and "we know nothing about this peer" print identically,
and they have opposite causes and opposite fixes.

**A tuning value is applied under a comment that says it is not.**
`internal/nebulacfg/render.go:580` reads `defaultLighthouseInterval = 60 // seconds; nebula's
own default`. Nebula's actual default is `10` (`third_party/nebula/lighthouse.go:228`,
`c.GetInt("lighthouse.interval", 10)`). Orbit therefore reports to lighthouses six times less
often than nebula would, everywhere, and the comment says the line changes nothing. A host
that roams takes up to a minute to become findable at its new address, and nothing in the
diagnostics surfaces that this is a configured value rather than a fact of the protocol.

**Nebula's own counters are not exported.** The embedded data plane collects handshake,
relay and tunnel statistics; `internal/agent/dataplane/embedded.go` reads none of them, so
none reach the status socket or ADR-0008's metrics. Every question about *rates* — how often
handshakes fail, how much traffic is relayed — is unanswerable from Orbit and has to be
answered by reading nebula's logs.

## Decision

Every field the diagnostic commands print is either read directly from nebula's state, or
derived using nebula's own expression for the same question, with a comment naming the
nebula source line it mirrors.

Concretely, and in this order:

`Relayed()` becomes `p.CurrentRemote == ""`, mirroring `inside.go:347`. `RelaysToMe` stays in
the report as what it is — the relays available for this peer — and stops being the predicate.

`PeersFrom` copies the candidate remote list, so "known but unreachable" and "unknown" are
distinguishable in output.

`orbit why` calls `QueryLighthouse` where `docs/diagnostics.md:103` says it does, or that
paragraph is deleted. A document describing a diagnosis the tool cannot perform is worse than
no document, because it sends an operator looking for output that will never appear.

`defaultLighthouseInterval` is either set to nebula's actual default of 10, or kept at 60 with
a comment stating what it is trading and why. It is not left claiming to be a no-op.

Nebula's counters are exported through the same path as everything else in ADR-0008, or the
decision not to export them is recorded there.

## Alternatives considered

**Report both predicates — "nebula thinks direct, relay state present".** Rejected. The value
of `orbit peers` is that an operator can act on one line of it. Two disagreeing signals in the
same column moves the disagreement from our code into the operator's head.

**Drop `Relayed()` and print `CurrentRemote` raw.** Tempting, and it is honest. Rejected
because "relayed" is the word operators use and the thing they are looking for; an address
column requires knowing which addresses are relays. The predicate should exist and should be
correct.

**Scrape nebula's log lines instead of its state.** Rejected for the reason ADR-0001 gives for
embedding it at all: we have the structs, and parsing our own dependency's log format is a
compatibility surface we would own forever.

**Restate every nebula default in the rendered config so none of them can drift.** Rejected —
`render.go:574-578` already argues this correctly: Orbit is the only *file*, not a restatement
of every built-in, and a short reviewable list is the point. The fix for the interval is to
make the comment true, not to lengthen the list.

## Consequences

`orbit peers` will report fewer relayed peers than it does today, and on a healthy mesh most
of the current `relay` labels will disappear. That is the correction, but anyone who has
built an expectation on the current output — including any runbook — will see it change.

Copying the candidate list makes the status report larger, and the report is already what
ADR-0007's threat model calls a map of the estate. The socket's mode is the control there,
and ADR-0015 tightens the directory around it.

We are committed to a comment beside each derived predicate naming the nebula source it
mirrors, which means the vendored bump in ADR-0001 acquires a review step: when nebula's
predicate changes, ours has to be re-read. That cost is real and it is the point — the current
predicate drifted silently precisely because nothing tied it to anything.

What would trigger revisiting: nebula exposing a stable diagnostic API of its own. Today the
hostmap is an internal structure we read because we are in the same process, and a supported
surface would let us stop mirroring expressions.

## References

- `internal/agent/status/status.go:168` — the predicate; `:149-156, 181-185` — the fields
- `third_party/nebula/inside.go:347` — nebula's own relay decision
- `third_party/nebula/lighthouse.go:228` — the real default of 10
- `internal/nebulacfg/render.go:580` — the comment claiming 60 is that default
- `docs/diagnostics.md:19, 103` — `QueryLighthouse`, promised and uncalled
- ADR-0001 (nebula as a vendored library) — why reading the structs is available at all
- ADR-0008 (what we measure) — where nebula's counters would land
