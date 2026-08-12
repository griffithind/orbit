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

The **Built** column is separate from Status on purpose. `Accepted` means the
decision is in force; it says nothing about whether the code has caught up.
`Partial` means some of the ADR's Decision section is in the tree and the commit
that landed it says which part is not — 0016 has its fail-closed rule and its
address-family check but not the blackhole or the escape-hatch bootstrap, 0027
has bring-up but no rehearsed restore, 0031 measures skew but does not report
it, 0030 has concurrent upstreams, TCP escalation, re-assertion, EDNS0 and
truncation but no cache, which it excludes deliberately,
0032 has the config half and not the endpoint cache, 0034 has the masquerade default,
the MSS clamp and ruleset assertions, but not the netns forwarding test that
would catch a rule that is present and wrong.

0011 and 0012 record decisions the architecture already embodied, so there was
nothing to build. 0018 is Windows, which the analysis behind it puts at six to
eight engineer-weeks before signing.

## Index

| # | Title | Status | Built |
|---|---|---|---|
| [0001](0001-nebula-as-a-vendored-library.md) | Nebula as a vendored library, not a subprocess | Accepted | — |
| [0002](0002-fail-static-control-plane.md) | The control plane fails static | Accepted | — |
| [0003](0003-revocation-terminates-live-sessions.md) | Revocation terminates live sessions | Accepted | — |
| [0004](0004-no-cli-framework.md) | The CLI stays on stdlib `flag` | Accepted | — |
| [0005](0005-no-compatibility-before-v1.md) | No backward compatibility before v1.0 | Accepted | — |
| [0006](0006-code-must-be-reachable.md) | Code must be reachable from `main` | Accepted | — |
| [0007](0007-key-custody-and-recovery.md) | Key custody and recovery | Accepted | — |
| [0008](0008-what-we-measure.md) | What we measure | Accepted | — |
| [0009](0009-control-plane-replicas.md) | Control-plane replicas | Accepted | — |
| [0010](0010-replica-discovery.md) | Every agent response carries the replica list | Accepted | Implemented |
| [0011](0011-full-generations-not-deltas.md) | Full generations, not deltas | Accepted | — |
| [0012](0012-policy-compiles-to-addresses.md) | Policy compiles to addresses | Accepted | — |
| [0013](0013-the-resolver-is-restored-not-just-set.md) | The machine's resolver configuration is ours to restore, not only to set | Accepted | Implemented |
| [0014](0014-diagnostics-report-what-nebula-decided.md) | Diagnostics report what nebula decided, not what we inferred | Accepted | Implemented |
| [0015](0015-host-state-is-removed-by-whoever-finds-it.md) | Host state is removed by whoever finds it | Accepted | Implemented |
| [0016](0016-the-exit-route-fails-closed.md) | The exit route fails closed | Accepted | Partial |
| [0017](0017-every-platform-we-tag-for-is-a-platform-we-check.md) | Every platform we tag for is a platform the gates analyse | Accepted | Implemented |
| [0018](0018-windows-is-a-client.md) | Windows is a client, and nothing else | Accepted | Not started |
| [0019](0019-no-dynamic-app-connectors.md) | No dynamic app connectors; route sets instead | Accepted | Not started |
| [0020](0020-one-network-owns-the-host.md) | Host-global resources have exactly one owner | Accepted | Implemented |
| [0021](0021-gateway-reachability-is-derived-from-routes.md) | A gateway's inbound reachability is derived from its routes | Accepted | Implemented |
| [0022](0022-what-a-host-renders-bumps-the-config-epoch.md) | Anything that changes what a host renders bumps the config epoch | Accepted | Implemented |
| [0023](0023-blocking-a-device-stops-issuance.md) | Blocking a device stops issuance to it | Accepted | Implemented |
| [0024](0024-one-enrollment-door.md) | One enrolment door, and it proves possession | Accepted | Implemented |
| [0025](0025-quarantine-does-not-gate-revocation.md) | Quarantine does not gate revocation | Accepted | Implemented |
| [0026](0026-a-process-that-disagrees-with-the-schema-refuses-to-serve.md) | A process that disagrees with the schema refuses to serve | Accepted | Implemented |
| [0027](0027-a-restore-is-a-rehearsed-procedure.md) | A restore is a rehearsed procedure, not a list of files | Accepted | Partial |
| [0028](0028-a-gateway-is-not-a-router-to-its-own-lan.md) | A gateway is not a router to its own LAN | Accepted | Not started |
| [0029](0029-the-resolver-is-authoritative-for-its-own-domain.md) | The resolver is authoritative for its own domain | Accepted | Implemented |
| [0030](0030-the-forwarder-is-a-real-forwarder.md) | The forwarder is a real forwarder | Accepted | Partial |
| [0031](0031-clock-skew-is-measured-not-inferred.md) | Clock skew is measured, not inferred | Accepted | Partial |
| [0032](0032-discovery-survives-the-lighthouse.md) | Discovery survives the lighthouse | Accepted | Partial |
| [0033](0033-overrides-cannot-reach-what-orbit-owns.md) | Overrides cannot reach what Orbit owns | Accepted | Implemented |
| [0034](0034-the-gateway-data-path-is-tested.md) | The gateway data path is tested, not just rendered | Accepted | Partial |
