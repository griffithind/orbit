# The model

What the nouns are, what each one owns, and what has to change to get there.

This is the anchor document. When a design decision feels unclear, the question
to ask is "which noun owns this fact", and the answer should be here.

---

## 1. The nouns

**Device** — a machine. It generates its own identity key at first start, before
it has joined anything and before it has heard of a control plane. That key
never changes and nobody issues it. A device outlives every network it joins.

**Network** — a mesh. It owns an address space, a curve, one or more CAs, a
policy, and a set of roles.

**Membership** — a device *in* a network. This is what `host` has always been:
not a machine, but the join of a machine and a mesh.

**User** — a person. Not yet built; see §7. Noted here so the model leaves room
for it rather than discovering it later.

The first two are independent. The third exists only because the first two do.

---

## 2. Which noun owns which fact

The rule: **a fact belongs to the narrowest noun that determines it.** Disk
encryption is a property of a machine, not of a machine's presence in a network,
so it belongs to the device. An overlay address is meaningless without a
network, so it belongs to the membership.

### Device

| | |
|---|---|
| **Identity** | public key, key fingerprint, key backing (`file` / `token`) |
| **Liveness** | first seen, last seen — *"is this machine talking to us"* |
| **Facts** | hostname, OS, OS version, kernel, architecture, agent version, nebula version |
| **Posture** | disk encryption, firewall, secure boot state, patch level, TPM presence — each with the time it was observed |
| **Attestation** | evidence, what it proved, when it was verified |
| **Blocking** | blocked at, reason — refused on this control plane, across every network |

### Network

| | |
|---|---|
| **Identity** | identity key → network ID, slug, display name |
| **Addressing** | CIDRs |
| **Crypto** | curve *(permanent)*, certificate version, certificate TTL |
| **Trust** | CAs — one active, others retired |
| **Authorization** | policy document, roles |

### Membership

| | |
|---|---|
| **Who and where** | device, network |
| **Naming** | name, unique within the network |
| **Addressing** | overlay addresses, address-changed-at |
| **Authorization** | role, tags |
| **Topology** | is lighthouse, is relay, static addresses |
| **State** | `pending` → `active` → `suspended` → `deleted` |
| **Convergence** | applied config epoch, applied blocklist epoch, restart-required epoch |
| **Instance** | listen port, tun device, config mode, config overrides |
| **Credential** | the nebula certificate |

Instance settings stay here and not on the device deliberately: a machine in two
networks runs two nebula instances, and they cannot share a UDP port or a tun
device.

---

## 3. What this fixes

### Posture stops being reported N times

A machine in three networks has one disk-encryption state, not three. Under the
current model the agent would report it per-membership — three rows, three
chances to disagree, and no answer to "is this laptop encrypted" that does not
involve picking one.

It also dissolves a tension that looked permanent. `internal/policy` refuses
`posture:` selectors because a nebula certificate cannot carry posture. That is
true and stays true. But policy already compiles **server-side to addresses**
(`internal/policy/policy.go`, and the reasoning at lines 20-41), so a
posture-derived *tag* flows through the existing compiler without the
certificate being involved at all. The refusal was never about posture being
unknowable — it was about the certificate not being the place for it.

### Liveness becomes two honest facts

*"This device is talking to the control plane"* and *"this membership's tunnel
is up"* are different states, and `host.last_seen_at` conflates them. A laptop
online but partitioned from one of its networks is a real situation the current
model cannot express, and it is exactly the situation worth alerting on.

### Blocking gets a scope

Blocking a **device** refuses it everywhere on this control plane — a stolen
laptop. Suspending a **membership** removes it from one network — a machine
being rebuilt. Both are useful, they are not the same action, and today only the
second exists.

### A machine's identity survives

Re-enrolling currently produces a new identity, so "is this the same machine
that was here last week" is an inference from a hostname. With a device key it
is a fact.

---

## 4. What moves, and what goes

### Moves off `host` onto `device`

`nebula_version`, `agent_version`, `last_seen_at`. All three are machine facts
that have been living on the join table.

### Renamed

`host` → `membership`. The current name claims the row is a machine. It is not,
and every reader has had to hold that correction in their head.

### Deleted

**`POST /v1/memberships`** — admin pre-creates a machine. Incompatible with a model
where a membership exists because a device joined. Replaced by a **reservation**:
an enrollment code that carries the intended name, address and role, with the
membership created when a device presents it.

**`orbit agent recover` and `internal/enroll/recovery.go`.** The recovery flow
exists solely because a host with an expired certificate cannot reach the
control plane to renew it. A device identity that never expires removes the
circularity, so there is nothing to recover from. See
`docs/design-device-identity.md` §2.

**Host states `created` and `enrolled`.** Both are artifacts of
pre-create-then-enroll. A membership is `pending` (joined, not authorized),
`active`, `suspended`, or `deleted`.

---

## 5. Invariants

These are the statements the schema and the code should make impossible to
violate, not merely avoid violating.

1. **A membership cannot exist without a device.** `device_id NOT NULL`.
2. **A device's key never changes.** A different key is a different device;
   there is no update path, only a new row.
3. **The control plane never holds a device private key.** It can mint a
   certificate for a machine and can never impersonate one. Enforced by a
   tripwire in migration 0011.
4. **Posture is recorded once per device** and evaluated by every network that
   device belongs to.
5. **A network's curve is fixed at creation.** Nebula refuses a certificate
   whose curve differs from its signer's, and nothing updates it.
6. **The network ID commits to a key the control plane can prove it holds** —
   the network identity key, not a CA, because CAs rotate. See
   `design-device-identity.md` §4.
7. **Blocking is a control-plane decision with one enforcement point**, so it
   takes effect on the next connection with no propagation.

---

## 6. Cost, and why now

This touches the store, the API, the CLI, the web UI, and the e2e harness. On a
deployed system the argument against would be strong.

It is safe here for one specific reason: **there is no deployment, and the tests
fail honestly.** The suite runs against real Postgres and boots real nebula
instances that complete real handshakes — no mocks standing in for the
behaviours that matter. A refactor is safe in proportion to how truthfully the
tests break, and these break truthfully.

The sequencing that keeps the tree working:

1. **The join path.** *(Done.)* A device joins; a membership is created in
   `pending` carrying `device_id`; an operator authorizes it; the device
   collects its certificate by proving it holds the key it joined with. Purely
   additive — the existing pre-create-then-enroll path keeps working beside it.

   The shape that fell out and was not obvious beforehand: **the device
   signature replaces the enrollment code entirely on this path.** Authorization
   allocates an address and nothing else, and the machine comes back to claim.
   No secret travels at any point, so there is nothing to leak from a
   provisioning repository. `POST /enroll/v1/join`, `POST /enroll/v1/claim`,
   `GET /v1/networks/{ref}/pending`, `POST /v1/memberships/{id}/authorize`,
   `orbit join`, `orbit membership pending`, `orbit membership authorize`.
2. **Device facts and posture.** *(Done.)* `orbit.device` carries OS, OS
   version, kernel, arch, agent and nebula version, plus disk encryption, secure
   boot, firewall and TPM presence. Native reads, no osquery. The agent sends
   them on every report; the control plane resolves the membership to its device
   and records once. `GET /v1/devices`, `orbit device ls -gaps`,
   `orbit device show`, and device-wide blocking.
3. **Codes become reservations.** *(Done.)* `POST /v1/memberships` is gone, along
   with `orbit membership reserve` and the web's Add-a-host form. An enrollment
   credential now carries either an existing host (re-enrolment) or a
   reservation — name, optional pinned address, optional role — and the
   membership is created at redemption, already naming its device. `POST
   /v1/networks/{ref}/reservations`, `orbit membership reserve`,
   `orbit join -code`.

   Two consequences that were not obvious in advance. Address exhaustion moved
   from creation to REDEMPTION, because a reservation holds a name and does not
   allocate — which is right, an operator may reserve against a prefix they are
   about to widen. And creating a membership became two audit entries by two
   actors at two times: the operator who reserved the place
   (`enrollment_code.created`) and the machine that took it (`host.created`,
   attributed to its device fingerprint).
4. **`device_id NOT NULL`**, and the moved columns drop off `host`.
5. **Rename** `host` → `membership`. *(Done.)* Table, columns, constraints and
   indexes; `store.Host` → `store.Membership`; `/v1/memberships` → `/v1/memberships`;
   the `hosts:*` scopes → `memberships:*`; the audit actions `host.*` →
   `membership.*`; `orbit membership` → `orbit membership` (aliased `member`).

   Deliberately NOT renamed: `internal/fwmatch`, `internal/nebulacfg` and
   `internal/ca`. Those wrap nebula's own vocabulary — a firewall rule's `host:`
   selector, a "host certificate" — and translating it at that boundary would
   mean a reader holding two names for one nebula concept. `Hostname` stays
   too: it really is a host name.
6. **Delete recovery.** *(Done.)* `orbit agent recover`,
   `internal/enroll/recovery.go`, `internal/agent/recover.go`, the two
   `/enroll/v1/recover*` endpoints, the challenge wire types and the
   `RecoveryGrace` setting.

   The replacement is not a new command: a machine whose certificate expired
   re-runs `orbit join`. The join is idempotent and returns the membership
   it already holds — same address, same role, same name, and NOT the name it
   asked for — and the claim that follows is authenticated by a device key no
   clock can invalidate. Asserted end to end in
   `e2e/join_test.go:TestExpiredCertificateRecoversByRejoining`, which was
   written and made to pass before any of it was deleted.

> An earlier draft of this list put device facts first. That order does not
> work, and the reason is worth keeping: moving `last_seen_at` and the version
> fields onto `device` requires memberships to *have* a device, and nothing
> links them until the join path exists. The agent's report identifies a host by
> its overlay source address, so before joining there is no device to attach a
> posture reading to. **The link has to exist before anything can move across
> it.**

Steps 1–3 leave the tree working at every point. Step 4 is the one that cannot
land early: `NOT NULL` while `POST /v1/memberships` still exists would fail at runtime
on host creation while every local test stayed green, because migrations are
tracked by name and an already-migrated database never re-runs the file.

---

## 7. Users, and leaving room

A user is a third gravity well, not an attribute of the other two. A person
exists independently of any machine and gets *sessions* on devices — so the
eventual shape is a `user` noun and a `session` join, mirroring device and
membership.

The thing to avoid is hanging users off either existing noun. `store.Identity`
already anticipates this: its `Kind` admits `ActorUser` and its `Subject` is
sized for an OIDC subject, so the audit path needs no change when users arrive.

`internal/policy` will still refuse `user:` selectors, and should. A nebula
certificate identifies a device; a user's reach is enforced where a user is
visible, which is the service layer, not the packet filter. See
`docs/credential-model.md` §5.

---

## 8. Open

- **The network identity key.** Generated at bootstrap, never rotated, as
  sensitive as the CA key for joining hosts. Storage and encryption-at-rest
  should match the CA's; that is decided but not built.
- ~~**Posture shape.**~~ **Settled: typed columns.** The deciding argument is
  what reads them — policy compiles server-side to addresses, so a posture
  predicate becomes a `WHERE` clause over the fleet on every compile. Columns
  make that indexable; a document makes it a traversal per row and turns a typo
  in a selector into a silent no-match. The cost is a migration per new signal,
  which is acceptable while the set tracks what an agent can natively read.

  Two consequences worth carrying forward. Each posture column is a **nullable
  boolean where NULL means "could not determine", not false** — a machine whose
  probe broke is not a non-compliant machine, and the correct response to those
  two is opposite. And posture **does not coalesce** on write, unlike facts: a
  signal that stops being readable becomes unknown rather than keeping the last
  value that happened to be true. That is precisely the failure mode of
  Microsoft Entra's device-compliance signal, which is stale by construction:
  an ~8-hour check-in, policy propagation up to a day, and compliance is not a
  CAE critical event — so a machine can be non-compliant for a working day
  while every consumer reads it as fine.
- **Whether `pending` memberships expire.** A join that nobody authorizes is a
  row that accumulates. Some bound is needed; whether it is a TTL, a cap per
  network, or a manual sweep is undecided.
