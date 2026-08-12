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
| [0007](0007-key-custody-and-recovery.md) | Key custody and recovery | Accepted |
| [0008](0008-what-we-measure.md) | What we measure | Accepted |
| [0009](0009-control-plane-replicas.md) | Control-plane replicas | Accepted |
| [0010](0010-replica-discovery.md) | Every agent response carries the replica list | Accepted |
| [0011](0011-full-generations-not-deltas.md) | Full generations, not deltas | Accepted |
| [0012](0012-policy-compiles-to-addresses.md) | Policy compiles to addresses | Accepted |
| [0013](0013-the-resolver-is-restored-not-just-set.md) | The machine's resolver configuration is ours to restore, not only to set | Accepted |
| [0014](0014-diagnostics-report-what-nebula-decided.md) | Diagnostics report what nebula decided, not what we inferred | Accepted |
| [0015](0015-host-state-is-removed-by-whoever-finds-it.md) | Host state is removed by whoever finds it | Accepted |
| [0016](0016-the-exit-route-fails-closed.md) | The exit route fails closed | Accepted |
| [0017](0017-every-platform-we-tag-for-is-a-platform-we-check.md) | Every platform we tag for is a platform the gates analyse | Accepted |
| [0018](0018-windows-is-a-client.md) | Windows is a client, and nothing else | Accepted |
| [0019](0019-no-dynamic-app-connectors.md) | No dynamic app connectors; route sets instead | Accepted |
| [0020](0020-one-network-owns-the-host.md) | Host-global resources have exactly one owner | Accepted |
| [0021](0021-gateway-reachability-is-derived-from-routes.md) | A gateway's inbound reachability is derived from its routes | Accepted |
| [0022](0022-what-a-host-renders-bumps-the-config-epoch.md) | Anything that changes what a host renders bumps the config epoch | Accepted |
| [0023](0023-blocking-a-device-stops-issuance.md) | Blocking a device stops issuance to it | Accepted |
| [0024](0024-one-enrollment-door.md) | One enrolment door, and it proves possession | Accepted |
| [0025](0025-quarantine-does-not-gate-revocation.md) | Quarantine does not gate revocation | Accepted |
| [0026](0026-a-process-that-disagrees-with-the-schema-refuses-to-serve.md) | A process that disagrees with the schema refuses to serve | Accepted |
| [0027](0027-a-restore-is-a-rehearsed-procedure.md) | A restore is a rehearsed procedure, not a list of files | Accepted |
| [0028](0028-a-gateway-is-not-a-router-to-its-own-lan.md) | A gateway is not a router to its own LAN | Accepted |
| [0029](0029-the-resolver-is-authoritative-for-its-own-domain.md) | The resolver is authoritative for its own domain | Accepted |
| [0030](0030-the-forwarder-is-a-real-forwarder.md) | The forwarder is a real forwarder | Accepted |
| [0031](0031-clock-skew-is-measured-not-inferred.md) | Clock skew is measured, not inferred | Accepted |
| [0032](0032-discovery-survives-the-lighthouse.md) | Discovery survives the lighthouse | Accepted |
| [0033](0033-overrides-cannot-reach-what-orbit-owns.md) | Overrides cannot reach what Orbit owns | Accepted |
| [0034](0034-the-gateway-data-path-is-tested.md) | The gateway data path is tested, not just rendered | Accepted |
