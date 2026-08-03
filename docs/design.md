# Orbit — Technical Design

An open-source control plane for [Nebula](https://github.com/slackhq/nebula): host
lifecycle, enrollment, config distribution, and PKI.

---

## 1. Constraints imposed by Nebula

These are not preferences. They are properties of the Nebula code that every
design decision below is downstream of. File references are to `slackhq/nebula`.

### 1.1 There are no intermediate CAs

`cert/ca_pool.go:AddCA` rejects any certificate that is not self-signed
(`ErrNotSelfSigned`). `cert/sign.go:SignWith` refuses to sign a certificate that
has `IsCA` set. Verification resolves the issuer with a single map lookup
(`ncp.CAs[issuer]`), not a chain walk.

**Therefore:** the "offline root signs an online intermediate" pattern used by
step-ca, Vault, and every public web PKI is unavailable. Orbit's online signing
key is a root of trust that every host trusts directly.

Everything in §5 (CA custody) and §6 (CA rotation) exists because of this.

### 1.2 CA certificates carry hard, enforced constraints

`cert/ca_pool.go:checkCAConstraints` enforces, on both signature and
verification, that a leaf certificate:

- expires no later than its CA, and begins no earlier
- has `Networks` contained within the CA's `Networks`
- has `UnsafeNetworks` contained within the CA's `UnsafeNetworks`
- carries `Groups` that are a **subset** of the CA's groups, when the CA lists any

**Therefore:** a narrowly scoped CA is the only available blast-radius control.
Orbit issues one CA per network, scoped to that network's prefix and its role
groups, with a bounded lifetime. `internal/ca` refuses to build an issuer whose
signer does not match its CA, and `TestCAConstraintsEnforced` pins each of these
rules against the real `cert.CAPool`.

Operational corollary, found while testing interop with `nebula-cert`: that tool
sets a new CA's `NotBefore` to its creation time, so a freshly created CA cannot
sign a certificate backdated even one second. The usual "subtract a minute to
absorb clock skew" idiom fails against a young CA. `Issuer.ValidityFor(ttl,
skew)` clamps both ends of the window to the CA's, and every issuance path
should use it rather than computing timestamps directly.

### 1.3 Revocation is a fingerprint blocklist distributed as config

There is no CRL and no OCSP. `pki.blocklist` is a list of SHA-256 fingerprints
loaded into the CA pool (`pki.go:loadCAPoolFromConfig`). Enforcement happens on
a timer, per tunnel, in `connection_manager.go:isInvalidCertificate`:

```go
} else if err == cert.ErrBlockListed {
    // "Remote certificate is blocked, tearing down the tunnel"
    return true
```

Blocklisting always tears the tunnel down. *Expiry* only tears down when
`pki.disconnect_invalid` is set.

**Therefore:** revocation latency equals config-distribution latency, and a
partitioned host keeps trusting a revoked peer until its certificate expires.
See [revocation.md](revocation.md).

### 1.4 Config is directory-merged, and lists append

`config/config.go:parse` merges every `.yml` in a config directory using
`mergo.WithAppendSlice`. `pki.ca` accepts either a path or inline PEM. Reload is
`SIGHUP` and is hot — tunnels survive it.

**Therefore:** Orbit never rewrites an operator's configuration file. It owns
exactly one fragment, `50-orbit.yml`, alongside whatever the operator maintains.
Firewall rules from both files concatenate. See §7.

### 1.5 Certificate rotation is hot; changing a host's address is not

`pki.go:reloadCerts` explicitly rejects a reload in which the certificate's
networks or curve changed:

> `"Networks in new cert was different from old"`

**Therefore:** renewal with a stable overlay address is zero-downtime and is the
common path. Re-addressing a host is a distinct operation requiring a process
restart, and must be modeled and surfaced as such.

### 1.6 The signing hook Orbit is built on

```go
// cert/sign.go
type SignerLambda func(certBytes []byte) ([]byte, error)
func (t *TBSCertificate) SignWith(signer Certificate, curve Curve, sp SignerLambda) (Certificate, error)
```

CA private keys never need to enter the control plane's address space.
`internal/ca.Signer` is a thin, context-aware interface over this.

### 1.7 Host static keys cannot sign

`pki.go:newCipherSuite` builds the Noise static keypair as **X25519** for
`Curve_CURVE25519` certificates — a Diffie-Hellman key with no signature
operation. (P-256 certificates use ECDH P-256, whose raw key *could* be used
with ECDSA, but relying on that inconsistency is a trap.)

**Therefore:** agent authentication cannot be "sign a nonce with your Nebula
key". See §4.3 for what Orbit does instead.

---

## 2. Architecture

```
                         ┌──────────────────────────────────┐
   operators ──token───▶ │  Admin API      /v1/…            │
   CI / IaC ──token────▶ │  (OIDC later — see 4.4)          │
                         ├──────────────────────────────────┤
   unenrolled hosts ───▶ │  Enroll API     /enroll/v1/…     │  public TLS
                         ├──────────────────────────────────┤
   enrolled hosts ─────▶ │  Agent API      /agent/v1/…      │  overlay only
                         └───────────────┬──────────────────┘
                                         │
                         ┌───────────────▼──────────────────┐
                         │  CA service (internal/ca)        │
                         │  Signer ──▶ file (KMS/PKCS#11:    │
                         │             RemoteSigner, unbuilt)│
                         └───────────────┬──────────────────┘
                                         │
                    Postgres  +  NOTIFY/LISTEN fan-out
```

Three separately-bound HTTP surfaces, because they have three different threat
models and three different exposure requirements. Running them in one process is
fine; running them on one listener is not.

| Surface | Exposure | Authentication | Rate limit |
|---|---|---|---|
| Admin | public or private | API token with scopes; OIDC is additive, see 4.4 | per token |
| Enroll | public | single-use enrollment credential | per source address + global ceiling |
| Agent | **overlay address only** | source overlay IP (see §4.3) | per host |

The control plane is **stateless**. All state is Postgres. Run N replicas behind
a load balancer.

### 2.1 The agent runs Nebula in-process

One binary and one service per host. The agent:

1. writes `/var/lib/orbit/<slug>/nebula.yml`, `host.crt`, `ca.crt`
2. reloads Nebula, or stops and starts it when §1.5 requires it
3. reports the applied config epoch and observed tunnel health back to Orbit

It does this for EVERY network the host has joined, in one process: a host can
belong to several networks run by control planes that have never heard of each
other, and each keeps its own directory, certificate, and Nebula instance. The
instances are irreducible — two overlays cannot share a UDP port or a tun
device — so what is shared is the process and the service, not the engine.

**This was the other way round until v0.3.0**, and the reasoning that changed is
worth keeping. Supervising a separately-installed binary meant: a Nebula to
install and keep on PATH, a second unit, a `-restart` spec naming a systemd
instance, and a version skew between the configuration Orbit renders and the
binary that loads it — the config test could pass something the real Nebula then
rejected. Deployment cost more than the isolation was worth.

What the isolation bought, stated precisely so the trade is legible:

- **Unchanged.** A control plane outage still leaves every host holding its
  certificate and its tunnels. Nothing in that path involves the control plane,
  and §9 is unaffected.
- **Changed.** Agent liveness and tunnel liveness are now the same liveness. A
  crash in the poll loop takes the data plane down until the service manager
  restarts it, where two processes under two units failed independently. With
  `Restart=always` that is seconds.
- **Changed.** A Nebula security fix ships on Orbit's release cadence rather
  than the host package manager's. That is a real cost and the main argument
  for the old arrangement.

The agent recovers from its own failures rather than requiring a visit: a
network whose directory is not ready is retried with backoff, and a Nebula that
failed to start or has died is restarted at the top of every poll — before the
poll, so a host whose data plane is down spends the tick getting it back.

---

## 3. Data model

```
api_token(id, name, token_hash, scopes[], expires_at, last_used_at, revoked_at)
audit_log(id, actor_type, actor_id, action, target, meta, source_ip, at)

network(id, name, cidrs[], cert_version, curve, cert_ttl,
        config_epoch, blocklist_epoch)
 ├─ ca(id, network_id, name, fingerprint, cert_pem, signer_ref,
 │     curve, not_before, not_after, state)
 ├─ role(id, network_id, name, groups[], firewall_rules jsonb)
 ├─ control_plane(network_id, host_id, addr, agent_port, last_seen_at)
 ├─ blocklist_entry(id, network_id, fingerprint, reason, epoch, not_after)
 └─ host(id, network_id, name, role_id, tags[], is_lighthouse, is_relay,
         static_addrs[], state, applied_config_epoch,
         applied_blocklist_epoch, last_seen_at)
     ├─ host_address(network_id, host_id, addr)
     ├─ certificate(id, host_id, ca_id, fingerprint, pem, cert_version,
     │              not_before, not_after, state)
     └─ enrollment_credential(id, network_id, host_id, method,
                              secret_hash, expires_at, used_at, used_from)
```

State machines:

```
ca:          pending → active → retiring → retired
certificate: pending → active → superseded
                             └→ revoked
                             └→ expired          (derived, not stored)
host:        created → enrolled → active → suspended → deleted
```

### 3.1 Invariants live in the database

A control plane that mints identities cannot rely on application-layer checks
that a concurrent request can race. Each of these is a constraint, not a
convention:

| Invariant | Mechanism |
|---|---|
| One active CA per network | partial unique index |
| One active certificate per host **per cert version** | partial unique index — v1 and v2 legitimately coexist during a version migration |
| Overlay addresses unique within a network | `host_address` primary key |
| Enrollment credentials are single-use | conditional `UPDATE`, one statement |
| Cloud instance ids enroll once | primary key on `(provider, instance_id)` |
| Applied epochs never regress | `greatest()` on write |
| The audit log is append-only | no `UPDATE`/`DELETE` grant to `orbit_app` |

The application connects as `orbit_app`, a role with no `CREATE` and no ability
to rewrite the audit log. It is not the table owner, so a bug cannot alter the
schema and a compromise cannot quietly drop the evidence.

### 3.2 Networks are the unit of separation

A network is a separate mesh: its own CA, address space, hosts, and epochs.
Nothing crosses between them, and a certificate issued by one network's CA does
not verify against another's — `internal/ca`'s `TestNetworkIsolation` pins that,
and it is also what makes CA-rotation overlap safe, since a pool trusting two
CAs accepts either.

**Two networks may use the same prefix.** Running `prod` and `staging` both on
`10.42.0.0/16` is legal and reasonably common. It is also why the agent API
resolves a host by `(network, source address)` rather than by address alone; see
§4.3.

### 3.3 Scaling limits

Measured by `e2e/scale_test.go` (`TestMeshJoinCost`), so these are numbers
rather than estimates.

**Rows are free.** Networks, hosts, certificates, and audit entries are just
rows; Postgres bounds them, and not at any scale this project will reach soon.

**Joined networks are the binding constraint.** Each network orbitd *joins*
(§4.3) is a full nebula instance: its own UDP socket, userspace network stack,
hostmap, and timer goroutines.

| Per joined network | Cost |
|---|---|
| Goroutines | ~28 |
| Heap (idle) | ~0.33 MB |

| Joined networks | Goroutines | Heap (idle) |
|---|---|---|
| 10 | ~280 | ~3 MB |
| 100 | ~2,800 | ~33 MB |
| 1,000 | ~28,000 | ~330 MB + 1,000 UDP sockets |

The heap figure is an idle baseline; hostmaps grow with peer count. Treat **low
hundreds of joined networks per process** as the working limit, and note that
1,000 nebula instances in one process is a lot of file descriptors regardless of
what the heap says.

**A network orbitd has not joined still works.** Enrollment, admin, issuance,
and blocking are unaffected; the network simply has no agent API, so its hosts
cannot poll, renew, or receive pushed revocations. Joining is an explicit
per-instance decision rather than an implicit consequence of creating a network.

**Shard by network, horizontally.** `-mesh` is per-instance and the store is
shared, so scaling past a few hundred networks is a matter of running more
orbitd instances, each joining a disjoint subset. No coordination is needed: the
agent API is stateless and the notifier fans out from Postgres, which every
instance already listens to.

**Replicas discover each other through the database.** Each registers the
overlay endpoint it serves on (`control_plane`) and heartbeats every 30s;
enrollment and renewal hand agents the *live* list, and agents rotate through it
on transport failure. A replica that dies stops being advertised when its
heartbeat goes stale, and its row is removed by the maintenance sweep — there is
no deregistration path to get wrong, and no load balancer in front of the
control plane.

**Hosts scale independently of networks.** The limit there is watcher
connections — one HTTP connection and one goroutine per agent long-polling —
capped by `-max-watchers` (default 5000 per network) and ultimately by the
process's file descriptors. Agents that cannot get a watcher slot fall back to
polling, which is why that cap fails soft rather than refusing service.

---

## 4. API surfaces

### 4.1 Admin API — `/v1`

Scoped bearer tokens, modeled on the incumbent's `hosts:create` /
`hosts:enroll` style so migration tooling is straightforward.

```
POST   /v1/networks                      networks:write
GET    /v1/networks                      networks:read
GET    /v1/networks/:ref                 networks:read  (uuid OR name)
GET    /v1/networks/:id/convergence      networks:read  (§6 rotation gate)

POST   /v1/cas                           cas:write      (pending, not active)
GET    /v1/cas?network_id=               cas:read
POST   /v1/cas/:id/activate              cas:write
POST   /v1/cas/:id/retire                cas:write

POST   /v1/roles                         roles:write
GET    /v1/roles?network_id=             roles:read
GET    /v1/roles/:id                     roles:read
PATCH  /v1/roles/:id                     roles:write    (202 if groups changed)
DELETE /v1/roles/:id                     roles:write    (409 if any host carries it)

POST   /v1/hosts                         hosts:create
GET    /v1/hosts?network_id=&…           hosts:read     (filtered, paginated)
GET    /v1/hosts/:id                     hosts:read
PATCH  /v1/hosts/:id                     hosts:write
DELETE /v1/hosts/:id                     hosts:block    (revokes, then removes)
GET    /v1/hosts/:id/certificates        hosts:read     (paginated, no PEM)
POST   /v1/hosts/:id/enrollment-code     hosts:enroll
POST   /v1/hosts/:id/block               hosts:block
POST   /v1/hosts/:id/unblock             hosts:block

GET    /v1/networks/:id/convergence      networks:read
POST   /v1/tokens                        tokens:write
GET    /v1/tokens                        tokens:read
DELETE /v1/tokens/:id                    tokens:write
GET    /v1/audit-logs                    audit:read     (action, target, since, until, limit)
GET    /v1/whoami                        —              (authenticated; no scope)
```

Two status codes on that list are not decoration.

`PATCH /v1/roles/:id` answers **202, not 200, when `groups` changed**. Firewall
rules are configuration and converge in seconds; groups are inside the signed
certificate, so every host carrying the role presents the old set until it
reissues. "Accepted, processing not complete" is literally the state of the
system, and it is the one signal a caller that ignores the body cannot miss. The
response carries the affected host count and the instant the last one converges,
computed from live certificate rows rather than estimated — the renewal jitter
is a SHA-256 of the host id, so the true time is derivable.

A group change also stamps `role.groups_changed_at`, and `enroll.Service.State`
pulls renewal forward for any host whose certificate predates it (§7). Without
that the 202's deadline would be half a certificate lifetime away; with it, about
a minute. The agent has always been able to honour such a hint — what was
missing was any reason for the server to send one.

`DELETE /v1/roles/:id` answers **409 naming the hosts** that carry the role.
`ON DELETE RESTRICT` means the database refuses regardless, but `mapErr` renders
a foreign-key violation as `ErrNotFound` — so without the pre-check an operator
would be told the role does not exist when the truth is that fourteen hosts use
it.

Three checks live here rather than downstream, because each one otherwise fails
much later and much less legibly:

- **Firewall rules are validated strictly.** Nebula's `convertRule` reads only
  keys it knows and ignores the rest, so `{"port":"22","proto":"tcp",
  "groupss":["ssh"]}` becomes a rule with *no group constraint* — applied to
  every host with that role, with nothing in any log. `ValidateFirewall`
  rejects unknown keys, bad ports, and rules that constrain nothing.
- **A CA must be constrained.** `networks` is required; an unconstrained CA can
  mint any identity in the mesh (§1.1), so the API will not create one.
- **A role's groups must be a subset of the active CA's.** Otherwise issuance
  fails later with a constraint error naming a certificate rather than the role
  the operator just wrote.

A new CA is created **pending**, never active. Promotion is a separate call, so
publishing a CA into every trust bundle and confirming convergence (§6) is a
deliberate step rather than something an operator can skip by accident.

Every mutating call writes an audit record in the same transaction as the
mutation. If the audit write fails, the mutation fails.

### 4.2 Enroll API — `/enroll/v1`

Public. Detailed in [enrollment.md](enrollment.md).

```
POST /enroll/v1/enroll     { credential, public_key, curve, attestation? }
                        →  { certificate, ca_bundle, config, epochs,
                             agent_endpoints, renew_after }

GET  /enroll/v1/recover/challenge?host_id=…
POST /enroll/v1/recover    proof-of-possession for a host whose certificate
                           expired while it was offline (enrollment.md §7.1)
```

### 4.3 Agent API — `/agent/v1`, bound to the overlay

Once enrolled, a host has a Nebula tunnel. Orbit runs **as a Nebula host** and
binds the agent API only to its overlay address.

The identity assertion is the source address, and it is cryptographically sound
because `firewall.go:Drop` verifies on **every single packet** that the peer's
certificate actually owns the source address:

```go
nwType, ok := h.networks.Lookup(fp.RemoteAddr)   // h = peer's verified cert
if !ok { return ErrInvalidRemoteIP }
```

A host cannot send a packet with a source address its certificate does not
carry. This yields mTLS-grade authentication with **no long-lived bearer token
on any host** — removing an entire class of credential theft that the incumbent
design carries, and keeping the management API off the public internet entirely.

```
GET  /agent/v1/state          → current config epoch, blocklist epoch, cert status
GET  /agent/v1/watch          → long-poll / SSE; returns when an epoch advances
POST /agent/v1/renew          → { public_key } → new certificate
POST /agent/v1/report         → applied epochs, nebula version, tunnel health
```

Three consequences to design for:

- **Bootstrap.** A host with no certificate cannot reach the overlay. Enrollment
  therefore happens on the public Enroll API, once. See
  [enrollment.md](enrollment.md).
- **Expiry deadlock.** A host whose certificate expires while offline cannot
  reach the overlay to renew. Mitigated by renewing at 50% of lifetime and by a
  public recovery endpoint that requires proof of possession of the existing key.
- **One nebula interface per network.** Easy to miss and expensive to discover
  late. Two networks may legitimately use the same prefix — `prod` and `staging`
  both on `10.42.0.0/16` is common — so a source address like `10.42.0.7` is
  *ambiguous on its own*. Orbit runs a distinct nebula interface per network and
  resolves identity as `(network, source address)`, taking the network from
  **which listener the request physically arrived on**, never from anything in
  the request. `store.ResolveAgentHost` requires the network id for exactly this
  reason, and `TestOverlappingNetworkCIDRs` pins the behaviour.

Implementation notes, both learned the hard way:

- The agent routes are mounted **only** on the overlay listeners, never on the
  public one. `TestAgentAPIAbsentFromPublicListener` asserts 404, not 401: a 401
  would mean the route exists and only authentication stands between the
  internet and it.
- The control plane must open its agent port **inbound in its own nebula
  firewall**, and `internal/mesh` sets that rule itself rather than inheriting
  it from a role. Nebula defaults to deny-inbound, so a control plane with no
  rule completes handshakes and then silently drops every agent connection —
  it looks exactly like a network fault. Setting it in code also stops a role
  edit from ever widening what the control plane exposes to every managed host.

### 4.4 Identity, and why OIDC is deferred rather than designed around

Every caller on the admin API resolves to one `store.Identity`:

```go
type Identity struct {
    Kind    string    // ActorToken today; ActorUser for an OIDC subject
    Subject string    // token uuid, or an issuer-qualified subject
    Display string    // token name, or an email
    Scopes  []string
    TokenID uuid.UUID // set only when Kind is ActorToken
}
```

Nothing below `admin()` knows what a token is. Adding OIDC means one branch in
that middleware — Orbit tokens carry the `orbat_` prefix, so distinguishing a
JWT from a token is a prefix check rather than a guess — and every handler,
scope check, and audit entry is unchanged.

`Display` is not scaffolding for that future. It is why the audit log reads
`deploy-bot` instead of a uuid **today**, and it is captured at write time
rather than joined, because tokens are revoked and hosts are hard-deleted:
attribution that depends on a join degrades over exactly the period an audit
cares about.

**When OIDC does land, three rules are not negotiable.**

1. **Tokens keep working, always.** Not behind an `-allow-token-fallback` flag
   someone will helpfully disable. The bootstrap token is the break-glass path
   and `orbitd bootstrap` never touches an IdP.
2. **An unset `-oidc-issuer` means the code path does not exist** — no discovery
   fetch, no JWKS refresh goroutine, no per-request branch. That is the
   difference between optional and merely configurable.
3. **A failed IdP never blocks startup.** Log loudly, serve with tokens. A
   control plane that will not boot because an identity provider is unreachable
   is worse than one with no SSO at all.

Two details are the usual way this is got wrong: **`aud` must be pinned** to an
Orbit-specific audience, or any token that IdP issued for any service
authenticates here; and **JWKS must be served stale on fetch failure**, or a
30-second IdP blip locks out every operator mid-incident.

Group-to-scope mapping belongs in configuration, not in the database. The
mapping from "IdP group" to "may mint certificates" is precisely what an
attacker with admin API access would want to edit — the same reasoning that
keeps `orbit_app` from being able to `ALTER` the schema.

### 4.5 The control plane cannot dial the overlay

`internal/mesh.Node` exposes `Listen` and no `Dial`. orbitd runs nebula on a
userspace gVisor netstack with no tun device, so the host kernel has **no route
to the overlay**: `http.DefaultClient` inside orbitd cannot reach any address in
the mesh. The control plane accepts agent connections and initiates nothing.

This is worth stating because it is invisible until something depends on it, and
then it fails confusingly. The concrete case is an in-mesh identity provider —
Keycloak on an overlay address — where JWKS fetch would simply never connect.

Nebula's `service.Service` does provide `DialContext`, so exposing it is roughly
fifteen lines. **It should not be done casually.** Outbound reach means a
compromised orbitd, on the machine holding the mesh's root CA key, can connect
to every host it manages. If it is ever added it should be scoped to one
declared destination rather than offered as a general dialer.

That constraint interacts with a cycle worth recording. An in-mesh IdP creates
three dependencies, not one:

- **Bootstrap** — Keycloak needs a certificate, which needs the admin API, which
  needs Keycloak. Broken by rule 1 above: bootstrap → token → enroll Keycloak →
  *then* enable OIDC. An OIDC-only Orbit could never host its own IdP.
- **Recurring** — Keycloak's certificate expires every `cert_ttl`. If renewal
  fails and OIDC is the only admin path, fixing Keycloak requires the API that
  Keycloak gates. This one does not resolve; it needs a break-glass token stored
  outside the mesh and actually tested — `orbitd token create`, and the
  procedure in deployment.md 5.
- **Name and trust** — in-mesh FreeIPA means DNS resolution also crosses the
  overlay, and Keycloak's TLS certificate chains to FreeIPA's CA, which nebula's
  CA knows nothing about. Two PKIs in one deployment that never interact and
  both have to be right.

The recommendation is to dual-home the IdP: in-mesh for everything else, plus
one address only orbitd uses. Orbit is what everything else depends on, so it
should depend on as little as possible — the mesh surviving the control plane's
death is the headline property, and it is a poor trade to make the control plane
depend on a service that needs the control plane to exist.

---

## 5. CA custody

`internal/ca.Signer` is the only path to a signature.

| Implementation | Use |
|---|---|
| `FileSigner` | **the supported path** — key on local disk, encrypted at rest |
| `KMSSigner` + `RemoteSigner` | interface only; no backend ships today |
| `NewMemorySigner` | tests and `--dev` only |

Orbit targets a self-hosted deployment on an ordinary VM, so the CA key lives on
that VM's disk. Be clear-eyed about what that means: nebula has no intermediate
CAs (§1.1), so this key is a root of trust for the entire mesh, and anyone who
reads it can mint any identity the CA's constraints allow.

Three things bound that, and all of them are free:

**Encryption at rest.** The realistic leak vectors on a cloud VM are disk
snapshots, backups, and a volume detached and mounted elsewhere. An encrypted
key survives all three. It does *not* survive compromise of the running process,
which necessarily holds the decrypted key in memory — so this is protection
against your infrastructure provider's storage layer, not against RCE.

`orbitd bootstrap` encrypts automatically when a passphrase is available and
warns loudly when it is not, because an unencrypted key is a failure nothing
else surfaces: everything works.

```
ORBIT_CA_KEY_PASSPHRASE_FILE   read from a file  (preferred)
ORBIT_CA_KEY_PASSPHRASE        read from the environment
```

The file form costs nothing and unlocks the good options on a plain VM. On
systemd, `LoadCredentialEncrypted=` places a **TPM-sealed** secret in
`$CREDENTIALS_DIRECTORY`; point `ORBIT_CA_KEY_PASSPHRASE_FILE` at it and a
stolen disk image is useless without that machine's TPM. Docker's
`/run/secrets/` works the same way. Neither keeps the passphrase from a process
an attacker already controls, but both keep it out of `ps`, out of shell
history, and out of anything that dumps the environment into a log.

**Permissions, enforced.** A CA key with any group or other permission bit is
refused at load, not warned about. That mistake is silent otherwise, and it
means every other user on the box — including any service that gets popped — can
mint mesh identities.

**A narrow, short-lived CA.** Constraints bound what a leaked key can mint
(§1.2); a 90-day lifetime bounds how long it can mint it. Both matter more here
than they would with a hardware-backed key, and rotation (§6) is what makes a
short lifetime practical rather than a recurring outage.

### What this does not protect against

Code execution in `orbitd` yields the decrypted key. No file-based scheme
changes that, and it is worth stating rather than implying otherwise. The
mitigations that do apply are the ones above plus §10: audited issuance, scoped
CAs, and a rotation path you have rehearsed.

A `RemoteSigner` backend (cloud KMS, PKCS#11) would close that gap by keeping
the key outside the process entirely. The interface exists and documents the
digest contract; no implementation ships, because the deployment target does not
have one available. It remains the upgrade path if that changes — the
`signer_ref` on each CA is what would be edited, and nothing else.

---

## 6. CA rotation

Because of §1.1, this is the *only* recovery path from signing-key compromise.
Build and rehearse it before you need it.

```
1. POST /v1/cas                     create CA₂ — inserted 'pending' AND
                                    published to every trust bundle
2. GET  /v1/networks/:id/convergence  wait for hosts to apply it
3. POST /v1/cas/:id/activate        CA₂ → active, CA₁ → retiring.
                                    Refused with 409 while hosts are behind.
4. (hosts renew onto CA₂)
5. POST /v1/cas/:id/retire          CA₁ → retired, dropped from the bundle.
                                    Refused while it has live certificates.
```

Three things carry the safety of this, and each was a gap the first
implementation had:

**Creating a CA publishes it.** `CreateCA` advances the config epoch in the same
transaction. Without that a pending CA sits in the database, reaches no trust
bundle, and convergence reports 100% because nothing changed — so an operator
promotes it and partitions the entire fleet. The pending state only means
anything if pending CAs are actually distributed.
`TestNewCAIsPublishedImmediately` pins it.

**Activation is gated on convergence.** A 409 naming the lagging hosts, because
"not converged" without saying who is not actionable. The gate lives at the API
layer rather than in the store, so the emergency path can override it.

**Retirement is gated on usage.** `GET /v1/cas` reports `active_certificates`
per CA, which is how an operator knows a rotation has finished. Retiring drops
the CA from every trust bundle; doing that while hosts still present its
certificates invalidates exactly the hosts that had not renewed.

### Emergency rotation

After a key compromise, cutting off unconverged hosts is the lesser harm:

```json
POST /v1/cas/:id/activate
{ "acknowledge_cutoff": true }
```

A typed field rather than a query flag, so it cannot be taken by accident, and
audited as `ca.force_activated` — a distinct action carrying how many hosts were
cut off. An auditor should not have to infer that from a timestamp.

### Automatic retirement

The maintenance sweep retires CAs that have outlived their own `NotAfter`,
without counting certificates. That is safe by construction: nebula enforces
`leaf.NotAfter <= ca.NotAfter` (`cert/ca_pool.go checkCAConstraints`), so once a
CA has expired nothing it ever signed can still verify. Keeping it in the bundle
costs bytes in every host's configuration and can never accept anything.

This is the *only* automatic CA state change. Retiring a live CA stays manual,
because that decision can strand hosts that have not renewed.

---

## 7. Config generation

Orbit owns one directory per network, and every file in it:

```
/var/lib/orbit/<slug>/
  nebula.yml     # Orbit's; the COMPLETE config, fully regenerated each epoch
  ca.crt         # trust bundle, every non-retired CA
  host.crt       # rotated by renewal
  host.key       # written once at enrollment, never sent
  agent.json     # agent state: control plane URL, epochs, guard state
  .previous/     # one generation, for rollback
```

`nebula -config` points at the **file**, not the directory. `config.go:resolve`
stats the path and loads a non-directory verbatim, so the merge described in §1.4
does not happen at all — that is what makes Orbit authoritative over this host,
and it is the precondition for any policy view claiming to be complete rather
than a lower bound.

A host that genuinely needs operator configuration alongside Orbit's runs the
agent with `-mode fragment`, which writes `config.d/50-orbit.yml` and points
nebula at the directory. Rules concatenate again, and Orbit can no longer
guarantee any rule is absent.

`/var/lib` rather than `/etc` because every file here is runtime state the agent
writes and replaces. On an image-based system (bootc, OSTree, Fedora CoreOS)
`/etc` is an overlay the image reconciles on upgrade, and state written there can
be reverted underneath a running host.

`nebula.yml` carries the managed keys:

```yaml
pki:
  ca: /var/lib/orbit/<slug>/ca.crt      # full bundle, all trusted CAs
  cert: /var/lib/orbit/<slug>/host.crt
  key: /var/lib/orbit/<slug>/host.key   # written once at enrollment, never sent
  blocklist: [ …fingerprints… ]
  disconnect_invalid: true              # always; see §1.3

static_host_map: { … }                  # lighthouses
lighthouse:
  am_lighthouse: false
  hosts: [ … ]
relay:
  relays: [ … ]
firewall:
  inbound:  [ … ]                       # from role; appends to operator's rules
  outbound: [ … ]
```

Two things to be deliberate about:

- **`disconnect_invalid: true` always.** Without it, an expired certificate does
  not tear down a live tunnel (§1.3), and the expiry-based revocation backstop
  in [revocation.md](revocation.md) silently does nothing.
- **Rules append, they do not replace.** An operator rule and an Orbit rule both
  apply. This is `mergo.WithAppendSlice` (§1.4). Document it loudly; a "deny by
  omission" mental model is wrong here.

Every generated config carries a monotonic `config_epoch`. The agent reports the
epoch it has applied, which is what makes §6 step 3 and convergence measurement
possible.

---

## 7a. Policy compilation

A network can express its firewall as **one document** instead of per-role rule
sets. Opt-in per network via `firewall_source`, which is `role` or `policy` and
never both.

```json
{"version": 1,
 "allow": [{"src": ["tag:web"], "dst": ["tag:db"], "proto": "tcp", "ports": ["5432"]}]}
```

### It compiles to addresses, not to groups

The obvious target is `groups:`, since nebula matches groups out of the peer's
certificate. It is the wrong one, and the reason is that `cidr:` is not weaker.

Before any rule is consulted, `Firewall.Drop` validates the peer's claimed source
address against the networks in its **verified certificate** and returns
`ErrInvalidRemoteIP` on mismatch. So a `cidr:` selector is bound to a signature
exactly as strongly as a `groups:` selector.

That inverts the cost. Groups live inside the signed certificate, so changing one
means reissuing every affected host's certificate and waiting out each host's own
renewal — a median of half a certificate lifetime. Addresses are configuration, so
a policy edit is a config epoch: hot, sub-second, **zero certificates reissued**.
Orbit can do this only because it owns address assignment. Tailscale's
coordination server does the same thing — it resolves `tag:` to node IPs and ships
an IP-keyed filter; identity never reaches the node's packet filter there either.

### Both directions are emitted

Outbound rules are enforced on the **sender** against the **destination's**
certificate (`inside.go` calls `Drop(..., incoming=false, ...)` down the same
peer-cert path). So one allowance compiles to an inbound rule on each `dst` host
*and* an outbound rule on each `src` host, and a flow is closed unless both ends
agree. Nebula gives defence in depth here that Tailscale's model does not.

### The management floor

Authoritative mode drops Orbit's default outbound allow-all — keeping it would
make every compiled outbound rule dead weight that still reads like enforcement.
That creates a hazard: a policy that forgets the control plane takes the fleet
offline *and* removes the path to the fix.

So the compiler emits one thing the document did not ask for — outbound to each
live replica's agent port on every host, inbound from the network prefixes on the
replicas. It is not overridable. A firewall you can lock yourself out of with a
typo is not a safety feature.

### What is refused, permanently

User selectors (`alice@example.com`, `user:`, `localpart:`), every `autogroup:`,
`app` capabilities, `srcPosture`, `via:`, `svc:`. A nebula certificate identifies
a **device** — name, networks, unsafe networks, groups — and there is no user
identity in the handshake and nothing in `FirewallRule.match` that could consume
one. Accepting a user selector and enforcing a device rule is a lie in the
permissive direction, so it is an error naming the reason rather than a silent
drop.

`group:`/`groups:` are refused too, redirected to `role:`/`tag:`: a group cannot
change without a fleet-wide reissue, and Orbit resolves the equivalent
server-side for free.

### Scale, measured

Rendered size is the constraint, not compile time (25 ms at 5000 hosts).
All-to-all with 3 allowances:

| hosts | per-host config | fleet push per epoch |
|---|---|---|
| 100 | 43 KiB | 4.2 MiB |
| 1000 | 432 KiB | 421 MiB |
| 2000 | 863 KiB | 1.6 GiB |

Tiered policy stays cheap — 1000 hosts at 27 KiB each, 27 MiB fleet-wide. The
limit is roughly **1000 hosts on an all-to-all shape**.

Caching the resolved document is *not* the fix: compiling all hosts at once is
only 27% faster than compiling each separately, because emission is quadratic
while resolution is linear. The structural fix is to **allocate addresses by
tag** — if a tag is a prefix, every tag selector compiles to one rule and the
whole thing collapses to O(allowances) regardless of fleet size. Only Orbit can
do that, because only Orbit assigns addresses.

---

## 8. Update distribution

The incumbent polls once per minute, so its blocking SLA is "within 60 seconds".
Orbit layers four mechanisms; details and the measurement harness are in
[revocation.md](revocation.md).

1. **Long-poll / SSE** on `/agent/v1/watch` — sub-second when connected
2. **Poll fallback** with jitter — for hosts behind proxies that break long-poll
3. **Epoch piggyback** — every agent response carries the current epochs; a host
   seeing a newer epoch pulls immediately
4. **Short certificate lifetimes** — the only mechanism that works under
   partition, and therefore the real backstop

Fan-out between replicas uses Postgres `LISTEN`/`NOTIFY`. It is sufficient to
five figures of hosts and avoids operating a message broker on day one; revisit
if a single Postgres cannot hold the connection count.

---

## 9. Failure behaviour (non-negotiable)

**Orbit being down must never break the data plane.** Existing tunnels keep
working; hosts keep their certificates until expiry; the mesh is unaffected.

Make this a test, not an intention:

```
docker compose stop orbit
# assert: mesh connectivity unaffected for the full certificate lifetime
# assert: agent retries with backoff, logs, does not restart nebula
# assert: agent never deletes or truncates its config fragment on failure
```

The agent's failure rules:

- Never apply a partially-downloaded config.
- Write `.new` → `fsync` → atomic `rename` → `SIGHUP` → **verify** → commit.
- On verification failure, restore the previous fragment and `SIGHUP` again.
- If unreachable for longer than a threshold after applying epoch *N*, revert to
  *N−1*, then **quarantine** *N*. This is the guard against pushing a firewall
  rule that severs every host's path back to the control plane.

  The quarantine is what makes automatic rollback safe rather than a way to
  flap: without it the agent reverts, immediately polls, is handed the same
  generation, applies it, and breaks again. Implemented in
  `internal/agent` (`GuardPolicy`), with `ConfirmWithin` (10m default),
  `MinConfirm` (60s — a request completing milliseconds after SIGHUP proves
  nothing, since nebula reloads asynchronously), and `Quarantine` (30m).
- Provide `orbit agent freeze` as an operator escape hatch.

---

## 10. Threat model

| Threat | Mitigation |
|---|---|
| Stolen enrollment credential | Single-use, short TTL, bound to one host record, rate-limited, audited, optionally attestation-bound ([enrollment.md](enrollment.md)) |
| Compromised host | Block → blocklist epoch → push; short cert TTL bounds worst case. Host key never leaves the host, so theft requires host compromise |
| Read access to Orbit's database | No host private keys exist in it. CA private keys are in KMS. Enrollment credentials are stored hashed |
| Code execution in Orbit | **Worst case.** Attacker can sign anything the CA constraints allow. Mitigated by narrow per-network CAs (§1.2), KMS-side rate limits, and signing-operation alerting. Not fully mitigable — §1.1 |
| Compromised CA key | Full mesh compromise for that CA's scope. Requires CA rotation (§6). This is why keys live in KMS/HSM and CAs are scoped and short-lived |
| A network's CA minting identities in another | Immutable Issuer↔CA binding: an `Issuer` is bound to one CA and one signer at construction, and there is deliberately no method that selects a CA at signing time. Tested by `TestNetworkIsolation` |
| Resource exhaustion from one network | Watcher caps per network, enrollment rate limits, signing bounded by CA constraints |
| Network attacker | Agent API is overlay-only; Enroll API is TLS with credential binding |
| Rogue Orbit operator | Append-only audit log, alert on issuance outside normal patterns, require two-person approval for emergency CA rotation |

Explicitly **not** mitigated: an attacker with code execution in Orbit can mint
certificates within the compromised CA's scope until that CA is rotated. Nebula's
flat trust model offers no way to make an online signing key less than a root.
The README states this plainly rather than implying otherwise.

---

## 11. Where each part of this design lives

| Concern | Code |
|---|---|
| CA service: pluggable signer, scoped CAs, issuance, verification | `internal/ca` |
| Schema and repository layer | `internal/db`, `internal/store` |
| Enrollment, config rendering, agent apply | `internal/{nebulacfg,enroll,api,agent}` |
| Renewal at 50% TTL, atomic swap, rollback | `internal/agent` |
| Block, push, propagation measurement | `internal/notify`, `e2e/revocation_test.go` |
| Agent API on the overlay | `internal/mesh` |
| Admin API, roles and policy to firewall rules | `internal/api`, `internal/policy` |
| Lighthouse and relay generation, replica registry, convergence | `internal/api`, `internal/store` |
| Metrics | `internal/metrics` |
| Operator console | `internal/web` |

Propagation is the claim this design stands or falls on, so it is measured
rather than asserted: 5.24 s from block to tunnel teardown, of which 5 s is
nebula's own `connection_alive_interval`. `e2e/revocation_test.go` fails if that
regresses past its deadline.

Two things in this document are described but not implemented, and are marked as
such where they appear: SSO/OIDC (§4.4, where the identity seam is in place and
tokens are the supported path) and the two enrollment methods in
enrollment.md §4–5.

---

## 12. Non-goals

- **Forking Nebula.** Orbit imports upstream Nebula as a library and runs it
  unmodified. The moment it requires a patched client it inherits Nebula's
  entire maintenance burden, so the version is a go.mod line and nothing else.
  Note the distinction from §2.1: not forking is the non-goal, and running it
  in-process rather than supervising a separate binary is a deployment choice
  that does not touch it.
- **Reimplementing `dnclient`'s wire protocol.** It is undocumented and
  proprietary. Orbit's agent is its own thing.
- **Being a general-purpose CA.** Nebula certificates only.
- **Proxying data traffic.** Orbit is control plane exclusively. Lighthouses and
  relays are Nebula hosts that Orbit configures, not services it implements.
