# Key custody

Where Orbit's secrets live, what an attacker has to hold to use them, and what
has to change for a second replica to be possible.

Status: **§4.1 and §4.3 are built.** Private keys are stored encrypted in
Postgres under a passphrase-derived KEK, and the enrollment pepper is gone.
§4.2 (offline identity key) was built and then **deliberately dropped** — the
reasoning is recorded there. §2 describes what was true before.

---

## 1. What secrets exist

| Secret | Scope | Today | Rotates? |
|---|---|---|---|
| **CA signing key** | per CA, per network | `db://` — sealed in `orbit.secret`. `file://` still supported | yes — that is what CA rotation is |
| **Network identity key** | per network | `db://` — sealed in `orbit.secret`. `file://` still supported | **never** — its hash *is* the network ID |
| **KEK passphrase** | per deployment | `ORBIT_KEK_PASSPHRASE` / `_FILE`, never persisted | yes, by resealing every secret |
| ~~Enrollment pepper~~ | — | **removed** — see §4.3 | — |
| API tokens | per token | SHA-256 in the database | n/a — hashes, not secrets |
| Device keys | per machine | on the machine | never |
| Mesh (host) keys | per membership | on the machine | on every renewal |

The last two are the ones that matter most and they are already right: the
control plane has never held either, and migrations 0011 and 0013 carry
tripwires that fail if a column which could hold one is added. Nothing below
changes that.

### The property to preserve

> **Read access to the database does not let an attacker mint a certificate.**

This is what makes a leaked `pg_dump`, an SQL-injection bug, or a compromised
read replica survivable rather than fatal. Any change to key storage is measured
against it first.

---

## 2. Two problems with the file

### 2.1 KMS is documented but does not exist

`internal/ca/registry.go` names `awskms://`, `gcpkms://` and `pkcs11://` in the
`SignerFactory` doc comment. Only `FileSignerFactory` is wired — in `orbitd`,
twice, with no alternative reachable by configuration.

`design.md` §5 is honest about this ("interface only; no backend ships today").
The **threat model in §10 is not**: it says "CA private keys are in KMS" and
"KMS-side rate limits", and the README repeats "KMS custody". No deployment
anyone can currently run has any of that. A threat model claiming a mitigation
the code cannot perform is worse than one that admits the gap, because it is
what a reader plans around.

**This should be corrected regardless of what else is decided.**

### 2.2 High availability does not actually work

`deployment.md` §11 says a second replica needs no load balancer, no virtual
address and no coordination. That is true of the *overlay* and untrue of the
*secrets*. To add a replica today you must, by hand and undocumented:

- copy every network's CA key file,
- copy every network's identity key file,
- keep all of it in step through every CA rotation.

That is **N files per network**, distributed out of band, with no mechanism to
detect drift. (It was N files plus an identical `ORBIT_ENROLL_PEPPER` until §4.3
removed the pepper.) A replica holding a stale CA key does not fail
loudly; it fails when it is asked to sign, which is when someone is trying to
enrol a machine.

This is the real problem. The security posture of a file on a hardened VM is
defensible. The operational shape does not survive a second machine.

---

## 3. The options, and why most are wrong

**Shared filesystem (NFS, EBS multi-attach).** Trades a secret-distribution
problem for a filesystem-availability problem, and the control plane now cannot
start when the mount is slow. No.

**pgcrypto.** Encryption *inside* the database means the key material passes
through the database, which is the one place it must not be. This is
obfuscation, not encryption. No.

**Postgres TDE.** Not in stock Postgres, and it protects the disk, not the
database — a `SELECT` still returns plaintext. Wrong layer.

**Derive the CA key deterministically from a passphrase.** Then rotation is
impossible (the same passphrase gives the same key) and a passphrase compromise
is permanent. No.

**Vault / KMS as the primary custody.** Another server to run, or a cloud
dependency in a product whose entire premise is self-hosting. A Linode VM has no
KMS. This can be an *option*; it cannot be the answer.

On cost: the objection to KMS is usually stated as price, and price is not
really the problem — per-key monthly charges are small in absolute terms. The
problem is that it is **per key and per cloud**. Orbit's keys multiply per
network and per CA rotation, and a self-hosted deployment on a VPS has no KMS to
call at all. Designing for "there is no KMS" as the default is correct; adding
one as a backend later is cheap.

---

## 4. Recommendation

### 4.1 Envelope-encrypt the keys into Postgres — BUILT

Store each secret as ciphertext in the database, encrypted under a **key
encryption key (KEK) that is not in the database.**

```
ORBIT_KEK_PASSPHRASE ──Argon2id(salt from DB)──▶ KEK
                                                 │
                       orbit.secret(kind, scope, nonce, ciphertext)
                                                 │
                                          XChaCha20-Poly1305
                                                 ▼
                                      CA key · identity key
```

**The security property is preserved exactly.** Today an attacker needs
`(database read) + (file read on the control-plane host)`. Afterwards they need
`(database read) + (the KEK, which lives on the control-plane host)`. Same two
factors, same hosts. A leaked dump remains useless on its own.

**The operational problem is solved.** A replica needs **one secret** —
the KEK — delivered the way a database password already is. No file
copying, nothing to keep in step through a rotation, and a replica with the
wrong KEK fails at startup rather than at signing time.

Notes on the details:

- **Direct encryption, not a per-key DEK layer.** The plaintexts are 32–64
  bytes. A DEK indirection exists to make KEK rotation cheap on large
  ciphertexts; here re-encrypting every row is milliseconds. Skip the layer.
- **KEK derived once at startup**, from a salt stored in the database (a salt is
  not secret). Not per-row, or every read costs an Argon2 derivation.
- **This is the passphrase machinery that already exists**, applied one layer
  up. `ORBIT_CA_KEY_PASSPHRASE` and `systemd-creds --with-key=host+tpm2` are
  already the documented pattern in `deployment.md` §3; the KEK is the same
  secret with a wider job.
- **Backups change character.** `pg_dump` becomes sufficient to restore a
  control plane *given the KEK*, which is better than today (no separate key
  file to lose). The KEK must then be stored somewhere the database backup is
  not.
- ~~Keep `file://` working.~~ **Reversed.** This was the plan, on the reasoning
  that the signer ref is a string so a deployment could hold some keys in each.
  That flexibility is the problem: two custody schemes mean two things to back
  up, two ways to lose a network, and a replica that can silently hold a stale
  key while the other replicas moved on. `internal/vault` now rejects `file://`
  by name, and `-ca-key` is gone.

**What was built, and one thing that changed on contact:**

`internal/secrets` holds the crypto, `internal/store` moves sealed bytes, and
`internal/vault` is the only place in the tree that holds a KEK and a database
handle at once — neither of the other two may import the other, or key material
ends up one refactor away from a query.

The Argon2id parameters are **64 MiB, t=3, p=4** — deliberately not nebula-cert's
2 GiB. nebula-cert derives once, interactively, on a workstation; this derives at
every control-plane start, on a small VM with Postgres sharing it, where a 2 GiB
allocation is most of the machine at the moment it can least spare it.
`ORBIT_KEK_ARGON_MEMORY_MIB` raises it and cannot lower it.

Two things the database enforces rather than the code:

- `orbit_app` has **no DELETE on `orbit.kek`** — dropping that row orphans every
  secret irreversibly. This needed an explicit `REVOKE`, because 0002's
  `ALTER DEFAULT PRIVILEGES` grants DELETE on every new table in the schema; the
  narrower `GRANT` alone changed nothing. The migration's own assertion caught
  that on the first run.
- The AEAD's additional data binds each ciphertext to its **row id and kind**, so
  an attacker with database *write* cannot move a network identity key into a
  CA's row — both are Ed25519 and both would parse — and have the control plane
  sign certificates with it.

### 4.2 Offline keys: what is possible, and what is worth it

**For the CA, the offline-root / online-intermediate pattern is impossible, and
no amount of design gets around it.** Nebula has no intermediate CAs (`design.md`
§1.1): every CA in a trust bundle is independently a root. There is no way to
make the online signing key less powerful than a root, because there is no
"less powerful than a root" in the format.

Worth stating flatly, because it is the thing everyone tries to design around.
What is available instead:

- **Narrow the online CA.** CA constraints already bound networks and groups, so
  a CA that can mint `{web}` cannot mint `{db}`. Several narrow CAs beat one
  broad one. Supported today, under-used.
- **A pre-published break-glass CA.** Create a second CA, publish it into every
  trust bundle so hosts already trust it, and keep its key offline and off every
  host. If the online CA is compromised, activate the offline one. This does not
  reduce blast radius — it is still a root — but it converts "re-enrol the entire
  fleet" into "activate, rotate, revoke", which is the difference between a bad
  day and a rebuild.

**For the network identity key, offline is possible — and after building it, the
answer is that it is not worth it.** The design is recorded here because the
reasoning is what a future change has to argue against.

It would work like this. The identity key signs a **delegation** — "proof key P
is valid until T" — and the control plane holds only P. A joining machine
verifies `network ID → identity key → delegation → proof`. Compromising the
control plane yields P, which expires; the identity key never goes online.
Unlike the CA, this is possible at all because it is Orbit's own protocol rather
than nebula's certificate format.

**Why it was dropped.** Four things, and the last is decisive:

1. **The attacker who can steal the identity key already owns the fleet.** It
   lives beside the CA key, under the same KEK, on the same host. Reaching one
   means reaching both — and with the CA key they can mint certificates for
   every existing machine. Recovery is a CA rotation either way.

2. **Losing it returns you to last week's posture, not below it.** The identity
   key defends against being pointed at the *wrong URL*. Before network IDs
   existed, that attack always worked. Compromise removes a defence added in
   this release; it does not open a hole that was previously closed.

3. **Recovering the network ID is one variable, not a re-enrolment.** The agent
   verifies the ID at join and *does not persist it* — memberships are keyed on
   the device, not the network ID. So retiring a compromised ID means changing
   one argument in whatever runs `orbit agent join`, and machines keep their
   memberships, addresses and certificates. The expensive-sounding recovery is
   not expensive.

4. **The failure mode is worse than the threat.** A delegation expires, and when
   it does *every join fails* until somebody produces a new one with the offline
   key. That is a recurring operational obligation whose forgetting causes an
   outage, on a schedule, forever — traded against a threat that requires host
   compromise and whose recovery is a config change.

**When it would be worth building.** A fleet large enough that re-pointing every
machine is genuinely costly, and an operations team that can carry a quarterly
key ceremony without forgetting it. Neither is true of a single-VM deployment,
and building it there buys a smaller risk reduction than the outage risk it adds.

So the identity key lives in the vault with the CA key, under the KEK, and the
network ID is treated as **replaceable rather than permanent** — which is what
point 3 makes it.

### 4.3 The enrollment pepper is redundant — REMOVED

Asked directly: can codes be derived from the network key and verified
cryptographically instead of being peppered?

**The signed-token idea does not work, and the pepper should go anyway — for a
different reason.**

#### The pepper buys nothing

`credential.go` already reasons carefully about entropy: a code is 24 random
bytes, 192 bits, which is why the stored form is a fast keyed hash rather than
Argon2id. That reasoning is right and it goes one step further than the code
does.

The pepper is justified in that file as "an attacker holding the table cannot
derive a usable code without the pepper". Against a 192-bit CSPRNG value, plain
`SHA-256(code)` is exactly as underivable. There is no precomputation to
frustrate, no dictionary to widen, and no guess to slow down — the search space
is 2^192 either way. Every attack the pepper is supposed to stop is already
stopped by the entropy:

| Attack | With pepper | Without |
|---|---|---|
| Invert the stored hash | 2^192 | 2^192 |
| Precompute / rainbow table | useless | useless |
| Confirm a code obtained elsewhere | blocked | possible — and worthless, because holding the code means you can just redeem it |

Meanwhile it costs exactly what §2.2 is about: a per-deployment secret that must
be **identical on every replica** and **stored apart from the database**. It is
one of the three things a second replica needs by hand, and it is the one
protecting nothing.

Dropping it makes the stored form `SHA-256(code)`, keeps the single indexed
lookup, and removes a secret from the HA problem. Outstanding codes stop working
at the changeover, which the 15-minute TTL makes a non-event.

#### Why signed self-verifying codes are the wrong shape

A code signed by the network identity key — payload of `{network, name, addr,
role, expiry}`, verified without a database row — is appealing and loses two
properties that matter:

1. **Single use.** A signed token is a bearer credential replayable until it
   expires. Today single use is a database fact — `UPDATE … WHERE used_at IS
   NULL`, one statement, one winner. No signature can provide that; you would
   need a table of spent tokens, which is the row you were trying to remove.
2. **The name is held.** An unspent reservation takes its name via a partial
   unique index, so two operators cannot reserve `web-01` and both walk away
   believing they have it. A stateless token reserves nothing.

The row is not overhead being carried for the pepper's sake. It is what makes a
code single-use and a name reserved, and redemption has to touch the database
anyway — it creates the membership. Signing would save nothing and cost both.

The one genuine benefit — rejecting a forged code without a database round trip
— is a DoS argument, and the enroll surface is already rate-limited per source
address with a global ceiling.

**Done: the row stays, the pepper is gone, the code is still a random value.**
`Hash()` is now `SHA-256` and takes no configuration. `ORBIT_ENROLL_PEPPER` is
no longer read anywhere — remove it from any `.env` you have.

### 4.4 Order

1. **Correct the docs.** `design.md` §10 and the README claimed KMS custody that
   does not exist. *(Done.)*
2. **Drop the pepper** (§4.3). *(Done.)* Removed one of the three secrets a
   replica needs, at no security cost.
3. **Envelope encryption into Postgres** (§4.1). Removes the other two, and with
   them the hand-copied key files. Everything else is optional; this is not.
4. ~~**Identity-key delegation**~~ — considered, built, dropped. See §4.2.
5. **Optional backends**: KMS or PKCS#11 as a KEK provider, and a documented
   break-glass CA procedure.

Steps 2 and 3 are what a deployment needs, and both are done. Step 5 is what it
wants before it matters.
