# ADR-0027: A restore is a rehearsed procedure, not a list of files

**Status:** Proposed
**Date:** 2026-08-12

## Context

The premise everyone has been working from is right: the KEK passphrase is the only item whose
loss is unrecoverable. `InitKEK` is an unconditional insert of a single row
(`internal/store/secret.go:51`) and `orbit_app` deliberately holds no DELETE on `orbit.kek`
(`0001_initial.sql:774`). Everything else is in the dump or regenerable.

That is a statement about *backup*. It says nothing about *restore*, and the restore path is
where this falls apart.

**Restoring onto a host with a different hostname does not start at all.** `defaultName` is
`"orbit-control-" + os.Hostname()` (`internal/mesh/node.go:164-168`), `serve` has no `-name`
flag, and `meshSpecs.Set` never sets `mesh.Config.Name`, so `mesh.Join` fills it from
`defaultName`. `SelfIssue` then finds the restored membership by address and refuses:

> `overlay address %s is already held by host %q` — `internal/enroll/service.go:1280`

with the comment that a different name at the same address "means an operator pointed two things
at one address; refuse rather than quietly take it over". Correct reasoning for the case it was
written for. `mesh.Join` failing returns straight out of `serve`, so **the control plane does not
come up**, and the only workaround — set the new host's hostname to the old one — is documented
nowhere. This is a direct regression from the fix recorded in ADR-0009: the previous
address-derived name was stable across a host move, and the hostname is not. That ADR's
Consequences do not mention restore.

**Restoring onto a different public IP silently strands the fleet.** `-lighthouse` is a *seed*:
`SetDevicePublicAddrs` is called only inside the `created` branch (`enroll/service.go:1260-1272`),
with the reasoning that the record is the source of truth afterwards — again correct for the case
it was written for. On restore the record exists, the flag is ignored, and the restored control
plane keeps advertising the **old** public address in every host's `static_host_map`. The
circularity is what makes it fatal: hosts reach the agent API over the overlay, the overlay needs
a reachable lighthouse, and hosts that cannot punch to the new address cannot be told the new
address. `scripts/setup-control-plane.sh:245-271` documents exactly this for the address-change
path; `docs/deployment.md` §7, which is what someone performing a restore is reading, does not.

**Three documents publish three different backup sets, and none is complete.**
`scripts/setup-control-plane.sh:441-445` and `deploy/compose.yml:157-166` each say "two things";
`docs/deployment.md:682-702` lists four and adds `/var/lib/orbit/device.key`; ADR-0007 lists
three and is the only one naming `ORBIT_KEK_ARGON_MEMORY_MIB`. That parameter is genuinely
load-bearing — it is not stored beside the salt, so a restore that forgets a raised value is
**indistinguishable from a wrong passphrase**, which is the one unrecoverable event.

**Nothing rehearses it.** ADR-0007 commits to quarterly restore rehearsal "on the cadence
`make check-break-glass` already has". `scripts/check-break-glass.sh` checks only the
break-glass token — and its own header carries the argument this ADR needs: "An untested
recovery path is a belief, not a capability." No test anywhere restores a dump. `README.md:377-379`
already admits it.

**`/readyz` cannot tell a healthy database from an empty one.** `internal/api/server.go:713-720`
runs `s.store.Read(probeCtx, func(context.Context, *store.Tx) error { return nil })` — a
`BEGIN READ ONLY; COMMIT` that reads no row and touches no `orbit` table. The comment directly
above says "the only honest test of 'can I serve a request' is to do what serving a request
does." It does not. It returns 200 against a database that is out of disk (reads succeed, every
write fails, so no enrolment, no renewal, no `BumpEpoch`, and therefore **no revocation
delivery**), against a read-only replica, and against a database with no `orbit` schema at all.

What *does* work on restore, and is worth recording so it is not re-solved: agents reconnect with
no action. `AgentEndpoints` are overlay addresses; the replica self-issues a fresh certificate at
every start with the private key only in memory; CA and identity keys come back out of the dump
under the KEK; nothing depends on the in-memory epoch, because `handleAgentWatch` re-reads state
on every wake. **Every restore failure is in bring-up, not in convergence** — which is precisely
the argument for making bring-up survivable.

## Decision

**The backup set is stated once and the other copies point at it**: the dump, the KEK
passphrase, `ORBIT_KEK_ARGON_MEMORY_MIB` if raised, and `/var/lib/orbit/device.key`.

**`serve` gets `-name`.** `defaultName` staying the hostname is right for the collision it was
built for; the fix for restore is an override, not a revert.

**`-lighthouse` stops being creation-only, or `orbitd doctor` compares the flag against the
stored device addresses and fails loudly when they differ.** Silence here is a fleet-wide
partition with no signal.

**`/readyz` reads a row** from an `orbit` table, and `orbitd doctor` derives the KEK and checks
the verifier — ADR-0007's commitment 9, still open, and the one failure that stops the process
from starting is the one `doctor` cannot currently see.

**`make check-restore` exists on the same quarterly cadence as `check-break-glass`**, and an e2e
test restores a dump into a fresh database *with a different hostname* and asserts an agent
reconverges. This is the part that makes the rest of the decision real: every item above was
found by walking the path, and the only thing that keeps them found is walking it automatically.

## Alternatives considered

**Make the replica's identity fully address-derived again.** Reverts ADR-0009's fix and
reintroduces the two-replica collision it closed. Rejected: the two requirements — stable across
a host move, unique across replicas — are both satisfiable with an explicit name, and neither is
satisfiable by a derivation.

**Detect a restore automatically and take over the record.** Rejected. "This looks like a
restore" is indistinguishable from "an operator pointed two things at one address", which is the
exact case `SelfIssue` refuses for good reason.

**Document the procedure without testing it.** Rejected on the authority of
`check-break-glass.sh`'s own comment. Four of the findings in this ADR are things a written
procedure would have said were fine.

## Consequences

`serve` grows a flag that most deployments never set, and a wrong `-name` becomes a new way to
fail — refused at `SelfIssue` with a clear message rather than silently.

A `/readyz` that reads a row will 503 during a migration window where the table does not yet
exist. That is correct and it is a behaviour change for anyone whose load balancer treats 503 as
"remove from rotation" — which is the point.

We are committed to a restore rehearsal that runs on a schedule and to an e2e test that performs
one. The test is the expensive part: it needs a real dump, a fresh database, and a differing
hostname, which is more setup than any current e2e case.

What would trigger revisiting: multi-replica deployments becoming the norm. Restore of one
replica out of three is a different operation — the survivors hold the truth — and the procedure
here is written for the single-replica case that the deployment docs recommend.

## References

- `internal/mesh/node.go:164-168`, `internal/enroll/service.go:1280` — the hostname blocker
- `internal/enroll/service.go:1260-1272` — `-lighthouse` seeding only at creation
- `internal/api/server.go:713-720` — the no-op readiness probe and the comment it contradicts
- `scripts/check-break-glass.sh` — the cadence, and the argument
- `scripts/setup-control-plane.sh:245-271, 441-445`, `deploy/compose.yml:157-166`,
  `docs/deployment.md:682-702` — the three incomplete backup sets
- ADR-0002 (fail static), ADR-0007 (key custody and recovery), ADR-0009 (control-plane replicas)
