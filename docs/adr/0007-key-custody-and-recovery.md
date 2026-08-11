# ADR-0007: The KEK passphrase is a custody item of its own, and losing it is not recoverable

**Status:** Proposed
**Date:** 2026-08-11

## Context

Every private key the control plane holds is a row in `orbit.secret`, sealed under one key
encryption key per deployment. The code that does this is built and shipping; what is missing is a
written statement of what an operator is therefore holding, and what happens when they stop
holding it.

**What exists.** `orbit.kek` is a single row — its primary key is a boolean `CHECK`ed to true
(`internal/db/migrations/0001_initial.sql:48`) — carrying a 16-byte salt and a verifier. The KEK is
`Argon2id(passphrase, salt, t=3, m=64 MiB, p=4) → 32 bytes`
(`internal/secrets/vault.go:110`, `:176`). The salt is random and not secret; the passphrase is
never persisted. `ORBIT_KEK_ARGON_MEMORY_MIB` raises the memory cost and is refused if it would
lower it (`internal/secrets/vault.go:140`). The parameters are **not stored** beside the salt, and
the function's own doc comment says raising them after bootstrap makes existing secrets unopenable.

**The passphrase resolves in four places, in order:** `ORBIT_KEK_PASSPHRASE_FILE`,
`ORBIT_KEK_PASSPHRASE`, then `ORBIT_CA_KEY_PASSPHRASE_FILE` and `ORBIT_CA_KEY_PASSPHRASE` as
upgrade-compatibility aliases (`internal/secrets/vault.go:276`). Trailing `\r\n` is trimmed.

**A wrong passphrase fails at startup, not at first signature.** `Init` seals the constant string
`orbit-kek-verifier-v1` into `verifier_nonce`/`verifier_ciphertext`; `Open` re-derives and checks
it, returning `ErrWrongKEK` (`internal/secrets/vault.go:159`, `:245`; `internal/vault/vault.go:38`).
`orbitd serve` calls `vault.Open` before it builds the CA registry, before the API, before it joins
any mesh (`cmd/orbitd/main.go:293`). There is no degraded mode: a control plane that cannot open
its vault does not start. Under `Restart=on-failure` / `RestartSec=5s`
(`cmd/orbitd/install.go:85`) that is a five-second crash loop, each iteration paying one ~0.1s
Argon2id derivation.

**What is encrypted is exactly two kinds of thing**, enforced by a `CHECK` constraint:
`ca_signing_key` and `network_identity_key` (`0001_initial.sql:76`). XChaCha20-Poly1305, random
24-byte nonce, additional data binding each ciphertext to its row id and kind so a row cannot be
moved or relabelled (`internal/secrets/vault.go:207`).

**Everything else in the database is plaintext**, and none of it is a private key:
`network.identity_public_key` (`:130`), `ca.cert_pem` (`:243`), `device.public_key` (`:304`),
`api_token.token_hash` (`:577`), `enrollment_credential.secret_hash` (`:423`), plus memberships,
addresses, policy and the audit trail. Device identity keys and nebula host keys never reach the
control plane at all.

**The blast radius of the passphrase is the deployment, not a network.** One `orbit.kek` row covers
every network's CA signing key and every network's identity key, including networks created later
through `POST /v1/networks` and `POST /v1/cas` (`cmd/orbitd/main.go:341`). Losing it does not
degrade signing — it removes the control plane. No enrolment, no renewal, no revocation delivery,
no policy edits, no console.

**There is no re-key path, and the database blocks the obvious workaround.** `orbit_app` holds
`SELECT, INSERT, UPDATE` on `orbit.kek` and deliberately not `DELETE`, where every other table gets
all four (`0001_initial.sql:774`). `InitKEK` is an unconditional `INSERT`
(`internal/store/secret.go:51`), so `orbitd bootstrap` against a database whose passphrase was lost
fails on the primary key. Starting over in place requires the superuser DSN to `TRUNCATE
orbit.secret, orbit.kek` — which is precisely what the test fixture does, as the superuser, with a
comment explaining that `orbit_app` must not be able to (`e2e/vault_test.go:40`).

**What survives a lost passphrase** is the data plane, bounded by `cert_ttl` — ADR-0002's
partition bound. Default 24h (`cmd/orbitd/main.go:638`, `internal/store/network.go:73`); the
documented bring-up uses 168h. Existing tunnels keep carrying traffic until certificates expire,
and then stop. Recovery is a new deployment: new network UUID, new verifiable network ID, new CA,
new admin token, and one `orbit membership reserve` + `orbit join` per machine per network. Device
keys at `/var/lib/orbit/device.key` survive, so machines keep their identity; memberships,
addresses, roles and the audit trail do not carry across.

**Rotation, today.** CA rotation is fully built — create, converge, activate, retire, with an
`acknowledge_cutoff` emergency path (`docs/design.md` §6). The network identity key is never
rotated within a network because its hash *is* the network ID, but the ID is treated as replaceable:
agents verify it at join and do not persist it. **KEK rotation is not built.**
`Tx.ListSecrets` and `Tx.ResealSecret` exist, are documented "for KEK rotation"
(`internal/store/secret.go:113`, `:142`), and have no caller anywhere in `cmd/`, `internal/` or
`e2e/`. The table in `docs/key-custody.md` §1 says the KEK rotates "by resealing every secret". No
code path does that.

**The default deployment co-locates the two things that must be apart.**
`scripts/setup-control-plane.sh:210` generates `ORBIT_KEK_PASSPHRASE` into `./.env` beside the
Postgres passwords, on the host that also carries the database volume, and `deploy/compose.yml:80`
passes it to the container as an environment variable — the form
`internal/secrets/vault.go:265` says the `_FILE` variant exists to avoid, naming `docker inspect`.
The script prints "store this somewhere else entirely" at the end. The state it leaves on disk is a
backup and its key in the same directory.

## Decision

**Already true in code, and recorded here as decisions rather than accidents:**

1. **One KEK per deployment, derived and never stored.** Not one per network, not one per CA. The
   cost is a single blast radius; the benefit is one secret to escrow and one to hand a replica.
2. **Argon2id at 64 MiB / t=3 / p=4, raise-only.** Not nebula-cert's 2 GiB, because this derives at
   every control-plane start on a small VM sharing memory with Postgres. Lowering it is refused.
3. **The passphrase is verified at startup, before anything is opened or joined**, against a
   verifier written at bootstrap. A control plane that cannot open its vault refuses to start;
   there is no partial mode in which enrolment works and signing does not.
4. **Exactly two kinds of secret enter the vault**, database-enforced, each ciphertext bound to its
   row id and kind. Nothing else may be added — API tokens and enrolment codes are hashes, and
   device and mesh private keys never reach the control plane.
5. **`db://` is the only custody path.** `file://` is rejected by name
   (`internal/vault/vault.go:149`); a deployment cannot be half in the database and half on disk.
6. **`orbit_app` cannot delete `orbit.kek`.** Dropping that row orphans every secret irreversibly,
   so the application role is not permitted to do it.

**New operational commitments, not implemented today:**

7. **The backup set is three items, and the second and third live somewhere the first does not:**
   the database dump; the KEK passphrase; and any non-default `ORBIT_KEK_ARGON_MEMORY_MIB`. The
   third is on this list because the Argon2id parameters are not stored next to the salt — a raised
   value is part of the key, and a restore that forgets it is indistinguishable from a wrong
   passphrase. Storing the parameters in `orbit.kek` would retire this item; until then it is
   escrowed with the passphrase.
8. **The supported install must stop co-locating.** `setup-control-plane.sh` must not leave the
   only copy of the passphrase in `./.env` beside the database volume, and the compose path moves
   to `ORBIT_KEK_PASSPHRASE_FILE` with a Docker secret so it is not in `docker inspect`.
9. **`orbitd doctor` derives the KEK and checks the verifier.** It checks the DSN, migrations, mesh
   ports, console exposure and enroll URL today, and not the one thing whose failure stops the
   process from starting — while its own header claims it runs "everything serve checks"
   (`cmd/orbitd/doctor.go:21`).
10. **Two recovery procedures are written out separately**, because they are not the same event.
    *Database lost, passphrase held*: `orbitd migrate`, restore the dump, start — nothing else, and
    this is the case backups exist for. *Passphrase lost*: there is no recovery. The procedure is a
    rebuild, and it must state that the in-place path requires the superuser DSN to clear
    `orbit.kek` and `orbit.secret`, that every machine re-enrols per network, and that the clock is
    `cert_ttl`.
11. **KEK rotation gets a command, or `ListSecrets`/`ResealSecret` are deleted.** ADR-0006 allows no
    third option, and the docs currently promise the feature.
12. **Restore is rehearsed quarterly**, on the cadence `make check-break-glass` already has. An
    untested restore is a belief.

## Alternatives considered

**Keep the keys as files on the control-plane host.** The original design. Rejected on operations,
not security: a second replica meant hand-copying N files per network and keeping them in step
through every CA rotation, with no way to detect drift — and a replica holding a stale CA key fails
at signing time, while somebody is adding a machine.

**Keep `file://` working alongside `db://`.** Planned, then reversed. Two custody paths mean two
things to back up, two sets of failure modes, and a replica that silently holds a stale key while
the others moved on. The flexibility was the defect.

**pgcrypto.** Rejected: the key material passes through the database, which is the one place it
must not be. That is obfuscation.

**Postgres TDE.** Rejected as the wrong layer — it protects the disk, and a `SELECT` still returns
plaintext. Also not in stock Postgres.

**Shared filesystem (NFS, EBS multi-attach) for the key files.** Rejected: trades a
secret-distribution problem for a filesystem-availability one, and the control plane then cannot
start when the mount is slow.

**KMS or Vault as the primary custody.** Rejected as the default: it is another server to run, or a
cloud dependency, in a product whose premise is self-hosting on a VPS that has no KMS. The
objection is not price — per-key charges are small — it is that the cost is per key and per cloud
while Orbit's keys multiply per network and per CA rotation. It stays available as a `RemoteSigner`
backend, which is a `signer_ref` edit and nothing else.

**A per-key DEK layer under the KEK.** Rejected: the indirection exists to make KEK rotation cheap
on large ciphertexts, and these plaintexts are 32–64 bytes. Resealing every row is milliseconds.

**Deriving the CA key deterministically from the passphrase**, so nothing needs storing. Rejected:
the same passphrase yields the same key, so rotation becomes impossible and a passphrase compromise
is permanent.

**Escrowing a recovery copy of the KEK inside the database**, wrapped under a second key. Rejected:
it makes a `pg_dump` sufficient on its own, which is the exact property everything else here is
built to prevent. The test that pins it is `TestTheDatabaseAloneIsNotEnough`.

**Splitting the passphrase across operators (Shamir, or two-of-three).** Rejected: derivation
happens at every process start, unattended, including an automatic restart at four in the morning.
A scheme that needs two humans present turns a reboot into an outage.

**An offline network identity key with a signed, expiring delegation.** Designed, built, and
dropped — recorded in `docs/key-custody.md` §4.2. The decisive reason is that a delegation expiring
makes *every join* fail until somebody performs a key ceremony, which is a recurring outage risk
traded against a threat whose recovery is changing one argument.

## Consequences

**Easy.** A replica needs one secret, delivered the way the database password already is, with
nothing to copy and nothing to drift. A leaked dump, a snapshot, or a detached volume is
ciphertext. Escrow is one item, not N key files. A mistyped passphrase is caught in the first
second of startup rather than during someone's enrolment.

**Hard, and this is the real cost.** The failure is deployment-wide and absolute. Losing one CA key
file used to cost one network's CA, recoverable by rotation inside one certificate lifetime.
Losing the KEK costs every CA key and every identity key in the deployment at once, and there is no
rotation path out of it because the thing that would perform the rotation cannot start. Recovery is
a rebuild and a full re-enrolment, with `cert_ttl` — 24h by default — as the entire budget for
noticing.

**We are committed to** the passphrase being a first-class custody item with the same handling as
the break-glass token, and to the installer reflecting that rather than contradicting it. We are
also committed to `orbitd doctor` catching a wrong passphrase, because the current arrangement is a
crash loop whose message is only in the journal.

**Revisit if** either of two things becomes true. A deployment target that has a KMS or a PKCS#11
token makes `RemoteSigner` the better default, and the KEK becomes a bootstrap detail rather than
the whole custody model. Or a fleet grows large enough that re-enrolment is genuinely catastrophic
rather than merely expensive, at which point the offline-identity-key design in `key-custody.md`
§4.2 is worth its recurring ceremony after all.

## References

- `internal/secrets/vault.go:110`, `:140`, `:176`, `:207`, `:245`, `:276` — Argon2id parameters,
  raise-only knob, derivation, AEAD, verifier, passphrase resolution order
- `internal/vault/vault.go:38`, `:68`, `:149` — startup verification, bootstrap init, `file://`
  rejected by name
- `internal/store/secret.go:51`, `:113`, `:142` — unconditional `InitKEK` insert; `ListSecrets` and
  `ResealSecret`, documented for KEK rotation and called by nothing
- `internal/db/migrations/0001_initial.sql:48`, `:69`, `:76`, `:774` — the single-row `kek` table,
  `secret`, the two permitted kinds, and the withheld `DELETE`
- `cmd/orbitd/main.go:293`, `:638`, `:769`, `:946` — vault opened before anything else; `cert-ttl`
  default of 24h; bootstrap sealing both keys; the custody note printed at bootstrap
- `cmd/orbitd/doctor.go:21` — the checks `doctor` runs, and the one it does not
- `cmd/orbitd/install.go:85` — `Restart=on-failure`, `RestartSec=5s`
- `scripts/setup-control-plane.sh:210`, `deploy/compose.yml:80` — where the passphrase is written
  and how it is passed
- `e2e/vault_test.go:40`, `:118` — the superuser reset, and the property
- `docs/key-custody.md` §3, §4.1, §4.2 — the rejected options and the dropped delegation design
- `docs/design.md` §5, §6 — CA custody and the rotation procedure
- `docs/deployment.md` §3, §5, §7 — the KEK, break-glass escrow, and the backup table
- ADR-0002 — `cert_ttl` as the bound on how long the data plane outlives the control plane
- ADR-0006 — why `ListSecrets`/`ResealSecret` must be wired or deleted
