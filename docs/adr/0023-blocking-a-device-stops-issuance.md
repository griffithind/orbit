# ADR-0023: Blocking a device stops issuance to it

**Status:** Proposed
**Date:** 2026-08-12

## Context

Orbit deliberately keeps device private keys in plaintext at `0600` on disk — no PKCS#11, no
TPM. `docs/credential-model.md:160-176` argues the trade explicitly, and the argument has one
load-bearing sentence:

> `orbit device block` refuses a device everywhere on the control plane immediately. A stolen
> disk image buys mesh access until the certificate expires, not indefinitely.

That sentence is false, and the mechanism it describes does not exist.

`BlockDevice` writes one column — `blocked_at` on `orbit.device` — and nothing else
(`internal/store/device.go:357-370`). It does not suspend memberships, revoke certificates, or
bump any epoch. `setDeviceBlocked` adds an audit row and no more (`internal/api/device.go:88-135`).

The agent API never consults that column. `ResolveAgentHost` is:

```sql
SELECT h.id, h.state
  FROM orbit.membership_address a
  JOIN orbit.membership h ON h.id = a.membership_id
 WHERE a.network_id = $1 AND a.addr = $2
```

(`internal/store/lookup.go:149-165`) — two tables, neither of them `orbit.device`. `AgentIdentity`
carries exactly two fields, and `agentIdentity` checks only `MembershipSuspended`
(`internal/api/server.go:433-435`). `Service.Renew` checks only `host.State == MembershipSuspended`
(`internal/enroll/service.go:407-409`). The code-enrolment path has the same omission
(`service.go:248-250`).

So a blocked device keeps renewing its certificate every twelve hours, indefinitely. Not "until
the certificate expires" — forever, because each renewal issues a fresh one.

The omission is specific rather than systemic, which is what makes it a defect and not a
design: `Claim` and `Authorize` **do** check the device (`internal/enroll/join.go:399-401`,
`:318-326`). Two of the four doors are locked. And the CLI is the only surface that describes
the true behaviour — `cmd/orbit/device.go:196-204` says "Existing nebula tunnels are unaffected…
To cut its traffic too: `orbit membership rm`" — while `internal/api/device.go:76-79` repeats
the documentation's claim.

There is a second gap behind it. The device key is immutable by construction: "a row is a key;
a different key is a different device" (`internal/store/device.go:187-188`), enforced by an
`ON CONFLICT (key_fingerprint) DO UPDATE` that touches only `last_seen_at` and `hostname`.
`docs/key-custody.md:21` records device keys as rotating "never". So the response to a leaked
device key is to block the device — the operation that does not work — and the only recovery is
a new key, which produces a new device row and new memberships, losing addresses, roles and
policy on every network the machine belongs to. Nothing implements or documents that path.

Tailscale separates a long-lived machine key from a rotatable node key with a control-settable
expiry that clients respect (`tailcfg/tailcfg.go:376, 495-499`). Orbit has the machine key with
no node key underneath it: the mesh key rotates but is not the identity, and the identity
neither rotates nor expires.

## Decision

**A blocked device is refused at every door that issues credentials.**

`ResolveAgentHost` and `AgentIdentity` carry the device's blocked state, and `Renew` and the
code-enrolment path refuse a blocked device exactly as `Claim` and `Authorize` already do. The
check goes in the resolution, not in each handler, so a future issuance path inherits it rather
than having to remember it.

**Blocking a device suspends its memberships and revokes their live certificates.** Blocking is
the operation an operator reaches for when a machine is stolen, and the only useful meaning of
that operation is ADR-0003's: the fingerprints reach the blocklist and live tunnels drop. A
device block that leaves the machine on the mesh until its certificate expires is a slower
version of doing nothing.

**Device key rotation is a recorded position, either way.** Either it is supported — which
means a hand-off signed by the old key, carrying the memberships across — or it is not, and the
documentation says what an operator does after a disk image leaks, which is re-enrol and
re-assign. What must stop is the current state, where the fallback is unbuilt and the primary
mechanism does not work.

## Alternatives considered

**Make `orbit membership rm` the documented answer and correct the claim in
`credential-model.md`.** This is the smallest honest change, and the CLI already says it.
Rejected as the whole answer: `membership rm` is per-network, so blocking a stolen laptop that
belongs to four networks is four commands, and the device-level operation exists precisely
because that is the wrong shape. But correcting the doc is part of this decision regardless —
the sentence must not survive in its current form for a single release.

**Have the agent refuse to run on a blocked device.** Rejected: the agent on a stolen machine is
under the attacker's control, and a check there protects nothing. The check has to be at
issuance, which is the control plane.

**Check `blocked_at` in each handler rather than in the resolver.** Rejected for the reason the
defect exists: two handlers remembered and two did not.

## Consequences

Blocking becomes a heavier operation — it now revokes certificates and bumps two epochs
(ADR-0022) — and it becomes irreversible in a way it is not today: unblocking will not restore
the revoked certificates, only allow new ones to be issued. That is the correct semantics and it
is a behaviour change for anyone using `block`/`unblock` as a soft toggle.

The argument against hardware-backed keys becomes true rather than aspirational. That matters
beyond this ADR: `credential-model.md`'s whole position rests on the revocation being fast and
complete, and until now the position rested on a mechanism that was not wired.

We are committed to device state being part of agent identity resolution, which couples
`orbit.device` into the hot path of every agent request. That is one more join on the most
frequent query in the system, on an indexed key.

What would trigger revisiting: adopting a rotatable node key. That would make the device key a
pure identity anchor and move revocation onto key expiry, which is a different and probably
better design — and a different ADR.

## References

- `internal/store/device.go:357-370` — `BlockDevice`, one column; `:187-188` — the key is the row
- `internal/store/lookup.go:149-165` — `ResolveAgentHost`, joining two tables, neither `orbit.device`
- `internal/api/server.go:433-435`, `internal/enroll/service.go:407-409, 248-250` — the three unchecked doors
- `internal/enroll/join.go:318-326, 399-401` — the two doors that do check
- `docs/credential-model.md:160-176` — the claim this ADR makes true
- `cmd/orbit/device.go:196-204` — the CLI text that has been accurate all along
- ADR-0003 (revocation terminates live sessions), ADR-0007 (key custody), ADR-0022 (epoch bumps)
