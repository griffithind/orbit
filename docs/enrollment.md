# Joining and enrollment

Joining is where trust is created. Everything downstream — firewall rules,
routing, revocation — is only as sound as the moment Orbit decided a given
public key belongs to a given identity.

This document specifies that moment, the steady-state renewal that follows, and
what happens when renewal stops working.

**Two doors, and the difference is where the gate sits.**

| | Gate | Command | When |
|---|---|---|---|
| **Join** | a human says yes | `orbit agent join` | a machine handed to a person; anything provisioned before its name is decided |
| **Reservation** | a code, made in advance | `orbit membership reserve` then `orbit agent join -code` | unattended provisioning, where nobody is watching a queue |

A reservation records the whole of the operator's intent — name, address, role,
and whether the machine will be a lighthouse or a relay and where it is
reachable. That is what makes it unattended: nothing is left to be applied after
the machine arrives, so there is no window in which the intent is half in
effect.

Both end in the same place: a membership that names a device, holding a
certificate issued over a mesh key that never left the machine. The difference
is only whether a secret had to travel.

`orbit agent enroll` is a third, narrower thing: re-issuing a certificate to a
membership that already exists, with a code bound to it. It is not how a machine
gets onto a network for the first time.

---

## 1. The bootstrap problem

A machine that has never joined has no certificate, therefore no Nebula tunnel,
therefore no way to reach the overlay-only Agent API (`design.md` §4.3). It must
talk to a **public** endpoint, and it must prove it is entitled to a certificate.

The old answer was that it proves it with a secret given out of band, and that
secret's strength was the ceiling on the strength of every identity in the mesh.

**The current answer is that it proves possession of a key it generated itself.**
At first start the agent writes a device key to `/var/lib/orbit/device.key`;
`join` is a signature over it. Nobody issues that key and nothing expires it, so
the ceiling moved: what a joining machine can prove no longer depends on how well
a secret was handled on the way to it.

A code still exists and is still useful — it is what pre-authorizes a join so
nobody has to watch a queue — but it now carries the operator's *intent* (a name,
optionally an address and a role) rather than being the only thing standing
between a stranger and a certificate. See `design-device-identity.md`.

**Orbit implements one credential method: `code`.** Two more are designed in §4
and §5 and are not built. They are documented because the reasoning is worth
keeping, not because you can use them.

| Method | Bootstrap secret | Assurance | Status |
|---|---|---|---|
| `code` | single-use code, 15 min TTL | operator-mediated | **implemented** |
| `cloud_iid` | signed cloud instance identity document | platform-attested | design only, §4 |
| `attestation` | TPM 2.0 / Secure Enclave key attestation | hardware-bound | design only, §5 |

Neither appears in the schema, and that is deliberate. A CHECK constraint listing
a method is a claim the method works, and anyone reading the schema for what the
system can do would be misled by one that no handler can produce a credential
for. Adding either is an `ALTER` and a handler.

---

## 2. Invariants

These hold for every method. They are the properties to regression-test.

1. **The host private key is generated on the membership and never transmitted.**
   Orbit only ever receives a public key. There is no code path that accepts a
   private key, and no column to store one.
2. **A credential is single-use.** Redemption is an atomic conditional update;
   a replay loses the race and is rejected.
3. **A credential names exactly one outcome.** Either an existing membership
   (re-enrolment) or a reservation — never both, enforced by a CHECK constraint.
   It cannot be redeemed for a different name, address, or role than the one it
   was issued against, and a machine redeeming a reservation takes the reserved
   name rather than one it asks for.

3a. **A membership cannot exist without a device.** `device_id NOT NULL`. Every
   path that creates one takes a device: a join, a reservation redemption, or
   the control plane's own row. See `model.md` §5.
4. **A credential is short-lived.** 15 minutes by default. Long-lived join
   tokens are how fleets get compromised.
5. **Every redemption attempt is audited**, with source address and outcome.

   An attempt whose credential does not resolve is recorded with no target,
   because there is no host to name — but the attempt itself is exactly what
   someone reviewing an incident wants to see, and a burst of them from one
   address is the signature of a replayed or guessed code. Once a credential
   *has* been redeemed the membership is known, and any subsequent failure is audited
   against it as `membership.enroll_failed`.

6. **Rate-limited per source address**, with a global ceiling. Enrollment is the
   one public, unauthenticated, and cryptographically expensive surface: every
   request costs a keyed-hash lookup and, on success, a billable KMS signing
   operation.

   IPv6 is bucketed by /64, not by address. A client routinely holds a whole
   /64 and can source from any address in it, so per-address limiting there
   would be trivially bypassed while appearing to work. The global ceiling
   covers the distributed case a per-address limit cannot.

---

## 3. Method: `code`

The operator-mediated path. Equivalent in shape to the incumbent's
`dnclient enroll`, with a tighter TTL.

### 3.1 Issuing

```http
POST /v1/memberships
Authorization: Bearer <token with memberships:create>

{ "network_id": "net_…", "name": "web-01",
  "overlay_addr": "10.42.0.7", "role_id": "role_…", "tags": ["prod"] }
```
```http
POST /v1/memberships/host_…/enrollment-code
Authorization: Bearer <token with memberships:enroll>

→ 201
{ "code": "orb_1_aBcD…",        // shown exactly once
  "expires_at": "2026-08-03T21:15:00Z",
  "enroll_url": "https://orbit.example.com/enroll/v1/enroll" }
```

**Storage:** only `secret_hash` is persisted, as `SHA-256(code)`. The plaintext
exists only in the HTTP response.

Everything about that line follows from one number: 24 random bytes is **192
bits**.

An early draft specified Argon2id, on the theory that enrollment codes are
low-entropy secrets. True of human-chosen codes, false of these — Argon2id's cost
buys nothing against a value that size, and it would have forced a choice between
a random salt (making lookup-by-hash impossible) and a fixed salt (a slow keyed
hash with extra steps).

A later draft used `HMAC-SHA256(pepper, code)` with a per-deployment pepper,
justified as making the stored form useless to an attacker holding the table.
**That was redundant for the same reason.** Against 192 bits of CSPRNG output,
plain SHA-256 is exactly as underivable: there is no precomputation to frustrate,
no dictionary to widen, and no guess to slow down. The pepper stopped nothing the
entropy had not already stopped, while costing a secret that had to be
byte-identical on every replica and stored apart from the database — one of the
things that made a second control plane not actually work. See
[key-custody.md](key-custody.md) §4.3.

The two properties actually needed are that the stored form be useless after a
database leak and deterministic enough for a single indexed lookup. A plain
digest gives both, and needs no configuration, no distribution, and nothing to
lose.

**Single use is a database fact, not a cryptographic one.** Redemption is
`UPDATE … WHERE used_at IS NULL` — one statement, one winner. This is why a
self-verifying signed token was rejected as a replacement: a signature can prove
a code is authentic and unexpired, and cannot prove it is unspent.

**Format:** `orb_<version>_<base32(24 random bytes)>` plus a short checksum. The
version prefix makes rotation possible; the checksum lets the client reject a
typo before making a request, and lets secret-scanning tools match it.

### 3.2 Redeeming

```http
POST /enroll/v1/enroll

{ "credential":  "orb_1_aBcD…",
  "public_key":  "<base64 raw X25519 or ECDH P-256 public key>",
  "curve":       "CURVE25519",
  "agent_version": "0.2.0",
  "host_info":   { "hostname": "web-01", "os": "linux", "arch": "amd64" } }
```

Server, in one transaction:

```
1. hash credential, look up by hash          → 404 if absent (constant-time)
2. UPDATE … SET used_at = now()
     WHERE id = $1 AND used_at IS NULL AND expires_at > now()
   0 rows → 409 already used / expired
3. load host + network + active CA
4. validate public_key: correct length for curve, not a low-order point
5. issue certificate via ca.Issuer
6. persist certificate row, write audit record
7. render config for this host
```

Response:

```json
{ "membership_id": "host_…",
  "certificate": "-----BEGIN NEBULA CERTIFICATE-----\n…",
  "ca_bundle":   "-----BEGIN NEBULA CERTIFICATE-----\n…",
  "config":      "pki:\n  …",
  "config_epoch": 42,
  "blocklist_epoch": 17,
  "agent_endpoint": "https://10.42.0.1/agent/v1",
  "renew_after": "2026-08-04T09:00:00Z" }
```

Note `agent_endpoint` is an **overlay** address. From here on the membership talks to
Orbit over Nebula, and holds no bearer credential at all.

### 3.3 Agent side

```
1. generate keypair                      → host.key (0600), never sent
2. POST /enroll/v1/enroll with public key
3. write host.crt, ca.crt, nebula.yml
4. start / SIGHUP nebula
5. verify: tunnel to a lighthouse establishes
6. on failure, roll back and exit non-zero — do not leave a half-enrolled host
```

Public-key validation at step 4 of §3.2 matters: reject the all-zero key and
other low-order X25519 points. They are not a practical attack on Noise IX here,
but they indicate a broken client, and accepting one mints a certificate that
can never complete a handshake.

---

## 4. Method: `cloud_iid` — designed, not built

For autoscaling, where a human cannot paste a code and a baked-in long-lived
token is exactly the thing to avoid.

Nothing below exists in the code. It is a specification for the day someone
needs it.

The instance presents its cloud-signed identity document; Orbit verifies the
signature against the provider's published keys and matches the instance's
attributes against a pre-registered rule.

```json
{ "method": "cloud_iid",
  "provider": "aws",
  "document": "<base64 PKCS#7 signed instance identity document>",
  "public_key": "…", "curve": "CURVE25519" }
```

Orbit verifies:

1. signature chains to the provider's regional public key
2. document freshness (`pendingTime` within a few minutes; replay window)
3. `instance_id` has not previously enrolled — **this is what makes it
   single-use**, and it must be a unique constraint, not an application check
4. attributes match a registered rule for this network:

```yaml
enrollment_rules:
  - method: cloud_iid
    provider: aws
    account_id: "1234567890"
    region: us-east-1
    conditions:
      instance_tags:
        Environment: production
        Service: api
    grants:
      role: role_api_server
      address_pool: 10.42.10.0/24     # auto-allocate from pool
      name_template: "{{ .instance_id }}"
```

The membership is created on first enrollment rather than in advance, since
autoscaled instances do not exist when the rule is written.

**Failure mode to design against:** anyone who can launch an instance in that
account, region, and tag set can join the mesh. Scope rules narrowly, and treat
`account_id` as mandatory — an unscoped provider rule is a mesh-wide backdoor.

---

## 5. Method: `attestation` — designed, not built

Highest assurance: the membership key is generated **inside** a TPM 2.0 or Secure
Enclave and provably cannot be exported.

Blocked on a decision, not on effort: TPM 2.0 has no X25519, so this forces the
curve choice for an entire network. See the caveats at the end of this section.

```json
{ "method": "attestation",
  "credential": "orb_1_…",          // still code-gated; attestation adds to it
  "public_key": "…",
  "attestation": { "format": "tpm",
                   "ek_cert": "…", "ak_pub": "…",
                   "certify_info": "…", "signature": "…" } }
```

Orbit verifies the EK certificate chains to a known TPM vendor root, that the
attestation key is bound to that EK, and that `certify_info` proves the
submitted public key was created in that TPM with non-exportable attributes.

Two honest caveats:

- **The hard part is not the protocol, it is vendor root management.** Smallstep
  makes exactly this point about ACME device attestation: the plumbing is
  straightforward, the attestation *verification* logic and the trust store of
  TPM vendor roots is the real work. Budget accordingly.
- **Nebula's X25519 host keys cannot live in most TPMs.** TPM 2.0 does not
  support X25519 key agreement. In practice attestation is usable with **P-256
  networks** (ECDH P-256 is widely supported), or the attested key is a separate
  device-identity key that gates enrollment while the Nebula key stays in
  software. Decide which, and document it — a claim of "hardware-bound Nebula
  identity" that isn't is worse than no claim.

It is the right long-term answer and the wrong thing to block a first release
on.

---

## 6. Renewal

Steady state. Runs over the overlay, authenticated by source address
(`design.md` §4.3), with no bearer credential.

```http
POST /agent/v1/renew          (from 10.42.0.7, over the tunnel)
{ "public_key": "…", "curve": "CURVE25519" }
```

Orbit resolves the membership from the source overlay address, confirms it is not
blocked, and issues a fresh certificate from the network's **active** CA.

### 6.1 Timing

Renew at **50% of certificate lifetime**, with jitter.

With a 24-hour lifetime that is every ~12 hours, leaving a 12-hour window to
recover from failure before the certificate expires. Jitter (±10%) prevents a
fleet enrolled together from stampeding together.

```
issued ──────────────┬──────────────── expires
                    50%
                     └─ first attempt, then retry with backoff
                        for the remaining half of the lifetime
```

### 6.2 Key rotation on renewal

Generate a **new keypair** on each renewal by default. The cost is negligible
and it bounds the value of a stolen key file. Provide `--reuse-key` for
TPM-backed keys, which cannot be regenerated cheaply.

### 6.3 Applying it safely

Nebula holds v1 and v2 certificates simultaneously and rehandshakes on mismatch
(`connection_manager.go:tryRehandshake`), so overlap is well-supported. Lean on
it, but still make the swap atomic:

```
write host.crt.new, host.key.new              → fsync
rename over the live paths                     → atomic
SIGHUP
verify: certificate.ttl_seconds gauge advanced AND a tunnel re-established
  ok      → commit, delete .old
  not ok  → restore .old, SIGHUP again, alert
```

**Do not renew into an address change.** `pki.go:reloadCerts` rejects a reload
whose networks differ (`design.md` §1.5). If the membership's assigned address changed,
the agent must schedule a service restart, not a SIGHUP, and surface it as a
distinct event.

---

## 7. When renewal stops working

Three ways a machine ends up unable to renew normally. All three need an answer,
or the fleet slowly bleeds machines.

### 7.1 Expired certificate (machine was offline)

**There is no recovery command, because there is nothing to recover from.**

The old flow — an ECDH challenge over the public listener, a proof of possession
against the key still on disk, a 30-day grace window, `orbit agent recover` —
existed for one reason: the agent API listens only on the overlay, so a machine
whose certificate expired could not reach the control plane to renew the
certificate that would give it a working overlay. Breaking that circle took a
protocol.

A device identity is generated on the machine at first start, is issued by
nobody, and expires never (`design-device-identity.md` §2). So the circle is
gone, and the way back is the way in:

```bash
orbit agent join -url https://orbit.example.com -network prod
```

The join is idempotent: it resolves the device by its key and returns the
membership that device already holds — same address, same role, same name. The
name on the command line is IGNORED for a machine that is already a member,
which is deliberate: a machine must not be able to rename itself out from under
a policy that selects on the name. The claim that follows is authenticated by
the device key, so no clock is involved anywhere.

Two consequences worth stating:

- **Nothing is time-limited.** The grace window is gone. A laptop switched off
  for a year comes back the same way one switched off for a day does.
- **A lost mesh key is not a problem.** The old command needed the previous
  private key still on disk to prove possession. The device key is a different
  key with a different lifetime, and the mesh key is regenerated on every claim.

`e2e/join_test.go:TestExpiredCertificateRecoversByRejoining` asserts all of it.

### 7.2 Lost device key (disk failure, reimage)

A machine that lost `/var/lib/orbit/device.key` is, to this control plane, a
DIFFERENT MACHINE. That is not a limitation to work around — it is the property
the whole model rests on. The key is the identity; a control plane that would
accept "it is really me, I just lost my key" would accept it from anyone.

So it joins again, as new: `orbit agent join` generates a fresh device key and
lands in the pending queue, or redeems a reservation an operator made for it.
Either way somebody decides, which is the correct amount of ceremony for a
machine claiming a place it cannot prove it held.

The old membership is a separate decision and should usually be removed
(`orbit membership rm`), which revokes its certificate. Leaving it is a row
holding an address for a machine that no longer exists.

Do not build a "re-key this membership" path. It would be a way to move a
membership onto a key nobody verified, which is exactly what an attacker who
learns a membership id wants.

### 7.3 Host cannot reach Orbit at all after a bad config push

Handled by the agent-side revert described in `design.md` §9: if the membership cannot
reach Orbit for longer than a threshold after applying epoch *N*, it reverts to
*N−1*. This is the only defence against pushing a firewall rule that severs
every host's path back to the control plane, and it is worth building before the
first production rollout rather than after the first outage.

---

## 8. Attack analysis

| Attack | Defence |
|---|---|
| Steal an enrollment code in transit | TLS; 15-minute TTL; single-use; audited redemption reveals the race |
| Replay a redeemed code | Atomic conditional update on `used_at`; second attempt gets 409 |
| Brute-force codes | 192 bits of entropy; per-address rate limit plus a global ceiling; constant-time lookup by hash |
| Database leak yields usable codes | Only Argon2id hashes stored |
| Enroll with someone else's public key | Harmless — the attacker has no private key and cannot handshake. The victim simply cannot enroll with a used code, which surfaces as an alert |
| Redeem a code for a different identity | Credential is bound to one membership; name, address and role come from that record, never from the request |
| Compromised host renews forever | Blocking sets host state and blocklists the fingerprint; renewal checks state; short TTL bounds the window |
| Cloud IID replay from another instance | `instance_id` uniqueness constraint; document freshness window |
| Cloud IID from an attacker's own account | `account_id` is mandatory in every rule |
| Recovery endpoint abused to mint certificates | Requires ECDH proof against the key in the expired certificate; grace window; blocked memberships refused; alerted |
| Agent API called from off-overlay | Listener bound to the overlay address only; source address is cryptographically verified by Nebula's own anti-spoof check on every packet |

---

## 9. What to build first

Orbit ships `code` only, and that is the right scope. It is the method every
operator understands, it exercises the full issuance path end to end, and the
other two methods are additive — they change how a credential is validated, not
what happens afterwards.

Do get the invariants in §2 right on day one. They are cheap now and are the
kind of thing that becomes a migration later.
