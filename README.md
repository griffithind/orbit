# Orbit

An open-source control plane for [Nebula](https://github.com/slackhq/nebula) —
host lifecycle, enrollment, configuration distribution, and PKI.

Nebula ships an excellent data plane and leaves the control plane to you: you
provision a CA, distribute keys by hand, and hope you remember which host has
which certificate. Orbit is the missing half, self-hosted.

> **Status: the lifecycle is closed.** A host can be created, enrolled, brought
> onto a working mesh, rotate its certificate on a live tunnel, lose access
> within seconds of being blocked, and be decommissioned — measured, not
> asserted. Agents hold no credential: the control plane is itself a mesh member
> and the management API is unroutable from outside. Multiple replicas are
> discoverable and agents fail over between them.
>
> **Outstanding:** SSO/OIDC (needs an IdP choice), and the two enrollment
> methods in [docs/enrollment.md](docs/enrollment.md) §4–5, which are designed
> and not built.

---

## Design documents

| Document | Contents |
|---|---|
| [docs/deployment.md](docs/deployment.md) | Running it on one VM: bring-up order, CA key protection, backups, what survives an outage |
| [docs/design.md](docs/design.md) | Architecture, data model, API surfaces, CA custody and rotation, threat model |
| [docs/enrollment.md](docs/enrollment.md) | Enrollment methods, wire protocol, renewal, recovery, attack analysis |
| [docs/revocation.md](docs/revocation.md) | How blocking actually propagates, and how to measure it |

Read `design.md` §1 first. It documents six properties of Nebula's certificate
code that every other decision follows from, with file references — most
notably that **Nebula has no intermediate CAs**, which rules out the offline-root
pattern that most PKI designs assume.

Orbit is single-organization by design: one deployment manages its own networks.
A network is the unit of separation — its own CA, address space, and hosts — and
scaling past a few hundred means running more instances over disjoint subsets,
not partitioning inside one.

---

## What works today

`internal/ca` — the certificate authority service.

```go
// Signing goes through an interface, never raw key bytes. FileSigner is the
// supported path: a passphrase-encrypted key on local disk, with the file mode
// enforced at load.
signer, err := ca.NewFileSignerFromPath("/var/lib/orbit/ca.key", passphrase)

caCert, err := ca.CreateCA(ctx, signer, ca.CAParams{
    Name:      "acme-prod",
    Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
    Groups:    []string{"prod", "web", "db"},
    NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
})

issuer, err := ca.NewIssuer(ctx, caCert, signer)

hostCert, err := issuer.IssueHost(ctx, ca.HostParams{
    Name:      "web-01",
    Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.7/16")},
    Groups:    []string{"web"},
    PublicKey: hostPublicKey,          // generated on the host, never sent here
    NotBefore: now, NotAfter: now.Add(24 * time.Hour),
})
```

- **Pluggable signers.** `Signer` is a context-aware interface over Nebula's
  `cert.SignerLambda`. `FileSigner` is the supported path — key on local disk,
  encrypted at rest; `RemoteSigner` is the interface a KMS or HSM backend would
  implement; `NewMemorySigner` is for tests.
- **Scoped CAs.** Nebula enforces CA constraints on every signature and every
  verification. Since the online signing key is necessarily a root, a narrow CA
  is the only blast-radius control available.
- **Fails at issuance, not on peers.** Constraint violations, curve mismatches,
  and a signer paired with the wrong CA are all caught before signing, so they
  surface as an actionable error rather than as a certificate that mysteriously
  fails to verify across the fleet.
- **Verified against the real thing.** Every test ends by verifying through
  `cert.CAPool` — the same code every Nebula host runs.

```
go test ./...
```

Covers: issuance and verification on both curves, PEM round-trip, all five CA
constraint classes, blocklist revocation on both the cold and cached paths,
network isolation, mismatched-signer detection, validity clamping, and expiry.

`internal/db` + `internal/store` — schema, migrations, repositories.

```bash
make db-up          # development Postgres on :5433
make migrate        # apply the schema
make test           # store tests skip cleanly if Postgres is unreachable
```

Every mutation runs in a transaction; reads that need a consistent view use a
read-only one, so an accidental write fails loudly instead of committing:

```go
err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
    epoch, err := tx.BlockHost(ctx, hostID, "compromised")   // revoke + blocklist
    if err != nil {                                          // + suspend + bump
        return err                                           // + notify, atomically
    }
    return tx.AppendAudit(ctx, store.AuditEntry{
        ActorType: "user", Action: store.ActionHostBlocked,
    })
})
```

Invariants enforced by Postgres, not by Go — a control plane that mints
identities cannot rely on checks a concurrent request can race:

| Invariant | Mechanism |
|---|---|
| One active CA per network | partial unique index |
| One active cert per host **per cert version** | partial unique index (v1/v2 coexist during migration) |
| Overlay addresses unique within a network | `host_address` primary key |
| Enrollment credentials are single-use | conditional `UPDATE`, one statement |
| Cloud instance IDs enroll once | primary key on `(provider, instance_id)` |
| Audit log is append-only | no `UPDATE`/`DELETE` grant to `orbit_app` |
| Applied epochs never regress | `greatest()` on write |

The application connects as `orbit_app`, which holds no `CREATE` and cannot
rewrite the audit log. It is not the table owner, so a bug cannot alter the
schema and a compromise cannot quietly drop the evidence.

`internal/{nebulacfg,enroll,api,agent}` — config rendering, enrollment, HTTP, agent.

```bash
make db-up && make migrate
export ORBIT_ENROLL_PEPPER=$(head -c 32 /dev/urandom | base64)

go run ./cmd/orbitd bootstrap -dsn "$ORBIT_DSN"     # network, CA, role, admin token
go run ./cmd/orbitd serve     -dsn "$ORBIT_DSN" -agent-network "$ORBIT_NETWORK"

curl -H "Authorization: Bearer $ORBIT_TOKEN" -d '{...}' localhost:8080/v1/hosts
curl -H "Authorization: Bearer $ORBIT_TOKEN" -XPOST \
     localhost:8080/v1/hosts/$ID/enrollment-code

go run ./cmd/orbit-agent enroll -url http://localhost:8080 -code orb_1_… \
     -network prod -reload "systemctl reload nebula@prod"
```

The agent writes one complete `/var/lib/orbit/<slug>/nebula.yml` plus certificate
material and signals a
reload. It never starts, stops, or embeds nebula.

**Validate before touching anything live.** The applier stages a generation in a
temp directory and runs it through nebula's own `Main(configTest)` — loading the
PKI and building the firewall exactly as a running node would — before any file
moves into place. A config nebula would reject never reaches the running node.
Only after that does it back up, install, and reload; a failure past that point
restores the previous generation and reloads again.

**Configs are deterministic.** Identical inputs produce byte-identical YAML, so
an agent can hash the fragment to detect real change and a diff in review means
something actually changed.

**In fragment mode, nebula appends list values across config files.** An operator rule and an Orbit
rule both apply. There is no "deny by omission" and no way for the managed
fragment to remove a rule the operator wrote.

### Renewal

Agents renew at **50% of certificate lifetime** with deterministic per-host
jitter, leaving the entire second half to recover from failure before expiry.

```bash
go run ./cmd/orbit-agent run -network prod \
    -reload pid:/run/nebula.pid \
    -restart "systemctl restart nebula" \
    -verify-url http://10.42.0.1:8443/agent/v1/state
```

- **A fresh keypair is generated on every renewal** by default, bounding the
  value of a stolen key file to one certificate lifetime. `-reuse-key` keeps the
  existing key for hardware-backed identities that cannot be regenerated.
- **Jitter is derived from the host id, not randomness.** A random offset
  recomputed at each agent start would move the renewal time on every restart; a
  frequently restarting host could then renew far more often than intended, or
  keep pushing its deadline past expiry.
- **Post-apply verification drives rollback.** `-verify-url` points at the
  control plane's overlay address; if it is unreachable after the reload, the
  previous generation is restored and reloaded again. Without it, "applied" only
  means files were written and a signal was sent.
- **Address changes are refused, not silently ignored.** Nebula cannot hot-load
  a certificate whose networks changed (`pki.go reloadCerts`) — it logs a reload
  error and keeps running the old certificate until it expires. The agent
  detects this and demands a `-restart` rather than installing a certificate
  nebula will ignore.

### Revocation, measured

The central claim of a mesh control plane is that blocking a host removes its
access. `e2e/revocation_test.go` measures the whole path — block committed,
`NOTIFY` on commit, agent wakes, validates, installs, reloads, nebula tears the
tunnel down — and reads the end of it from **nebula's own hostmap**, not from
anything Orbit believes.

| Measurement | Result | Incumbent baseline |
|---|---|---|
| Push delivery to the agent | **9 ms** | up to 60 s |
| Block to tunnel torn down | **~5.3 s** | 60 s |

The full number is dominated by nebula's `timers.connection_alive_interval`
(5 s default), which is the floor no control plane can remove. Distribution is
single-digit milliseconds. Quote the full number — it is what an operator sees.

Push is Postgres `LISTEN`/`NOTIFY`: the transaction that advances an epoch also
publishes it, and Postgres delivers on commit, so a rolled-back block cannot
wake agents and a committed one cannot fail to. No broker on day one.

Degradation is graceful and loud: a server without a notifier answers `503` on
`/agent/v1/watch`, and the agent logs the fallback and switches to jittered
polling rather than hanging.

### No credentials on managed hosts

The control plane joins each network it manages as an ordinary nebula host, on a
userspace stack (no tun device, no root), and serves the agent API there:

```bash
orbitd serve -dsn "$ORBIT_DSN" \
    -mesh "$ORBIT_NETWORK=10.42.0.2" \
    -agent-port 8443
```

- **The agent API is on overlay listeners only** — never mounted on the public
  listener. The test asserts `404`, not `401`: a 401 would mean the route exists
  and only authentication stands between the internet and it.
- **Identity is the source address**, which nebula's firewall verifies against
  the peer's certificate on every packet. There is no token on any host to
  steal, and no shared secret to rotate.
- **The control plane's private key never touches disk.** Nebula accepts inline
  PEM for `pki.ca`/`cert`/`key`, so the key lives only in memory: a restart
  rotates it, a stolen disk yields nothing.
- **It accepts exactly one inbound port**, set by `internal/mesh` rather than
  inherited from a role — so a role edit can never widen what the control plane
  exposes to every managed host.
- **One listener per network.** Two networks may use the same prefix (`prod` and
  `staging` both on `10.42.0.0/16` is common), so a source address is only
  unambiguous within a network; the listener a request arrived on is what
  identifies which.

Enrollment still happens on the public endpoint — a host with no certificate has
no overlay to reach — and the agent learns its overlay endpoint from the
enrollment response.

### Operator API

Scoped bearer tokens over networks, CAs, roles, hosts, tokens, and audit logs.
Three validations happen at write time because each otherwise fails later and
less legibly:

```bash
# Rejected: nebula would accept this and silently drop the group constraint,
# opening SSH to every peer for every host with the role.
curl -H "Authorization: Bearer $ORBIT_TOKEN" -d '{
  "network_id":"...","name":"ssh",
  "firewall":{"inbound":[{"port":"22","proto":"tcp","groupss":["ssh"]}]}
}' localhost:8080/v1/roles
# 400  inbound rule 0: unknown field in firewall rule: json: unknown field "groupss"
```

- **Firewall rules are validated strictly** — unknown keys, bad ports, and rules
  that constrain nothing are all refused.
- **A CA must be constrained.** `networks` is required: nebula has no
  intermediate CAs, so an unconstrained CA can mint any identity in the mesh.
- **A role's groups must be a subset of the active CA's**, checked while the
  operator is looking at the role rather than later as a certificate error.

New CAs are created **pending**, never active — publishing into every trust
bundle and confirming convergence is a deliberate step, not something to skip
by accident.

Two destructive operations are worth calling out:

```bash
# Decommission a host: revokes its certificates, then removes the record.
curl -H "Authorization: Bearer $ORBIT_TOKEN" -XDELETE \
     "localhost:8080/v1/hosts/$HOST_ID?reason=hardware+returned"

# Retire a leaked token. Effective on the next request; there is no cache.
curl -H "Authorization: Bearer $ORBIT_TOKEN" -XDELETE \
     localhost:8080/v1/tokens/$TOKEN_ID
```

**Deletion revokes before it removes.** The other order would destroy the
certificate records naming the fingerprints to revoke, leaving a decommissioned
machine trusted until its certificate expired — a delete weaker than a block.
It requires `hosts:block` rather than `hosts:write`, so a token trusted to edit
hosts cannot reach the stronger outcome through a different verb.

**Revoked tokens stay listed**, with `last_used_at`. A row that disappeared
could not answer the question an incident actually asks: was it used, and was it
used after we revoked it.

**Losing every admin token is recoverable.** `POST /v1/tokens` requires a token,
so there is no API path back in — `orbitd token create` authenticates with the
database instead, and prints the plaintext on stdout alone so it pipes into a
secret store without touching shell history. Mint one at bring-up and store it
off the machine; the procedure is in
[docs/deployment.md](docs/deployment.md) §5.

### Failure containment

**The agent reverts a generation that breaks it.** A config can be structurally
valid, pass nebula's own config test, install cleanly, and still sever this
host's path home — a firewall rule dropping the agent port, a lighthouse list
that no longer resolves. Nothing local detects that at apply time. The agent
notices sustained loss of contact and puts the previous generation back.

```bash
orbit-agent run -network prod -reload "systemctl reload nebula@prod" \
    -restart "unit:nebula@prod" \
    -verify-url http://10.42.0.2:8443/agent/v1/state
```

Then it **quarantines** the generation that failed. Without that, rollback is a
loop: revert, poll, get handed the same config, apply, break again.

**Maintenance runs on every replica.** A 15-minute sweep prunes the blocklist
(otherwise it grows forever and ships in full to every host), removes spent
enrollment credentials, and reports certificates whose agents have stopped
renewing — the only signal that a fleet has quietly stopped rotating. Idempotent
and uncoordinated; no leader election.

**Enrollment is rate limited.** Public, unauthenticated, and expensive: every
request costs a keyed-hash lookup and, on success, a billable signing operation.
Per source address with a global ceiling, IPv6 bucketed by /64.

### Running more than one replica

Each replica registers the overlay endpoint it serves on and heartbeats. Agents
are handed the **live** list at enrollment and on every renewal, and rotate
through it when one stops answering.

```bash
# replica A                                    # replica B
orbitd serve -mesh "$T/$N=10.42.0.2" ...       orbitd serve -mesh "$T/$N=10.42.0.3" ...
```

No load balancer, no virtual address, no coordination between replicas. A
replica that dies stops being advertised when its heartbeat goes stale and its
row is removed by the maintenance sweep — there is no deregistration path to get
wrong. Failover lives on the agent, which costs one failed request before a host
notices and keeps working while the control plane is partly down.

Refreshing the list preserves which replica an agent is already using; resetting
everyone to the first entry on any membership change would herd the whole fleet
onto one replica.

### Watching it

`orbitd` serves Prometheus exposition on `127.0.0.1:9464/metrics` — localhost by
default because the output is fleet inventory. The fleet gauges are read from
Postgres at scrape time rather than kept in memory, so replicas agree and a
restart does not reset convergence to zero and page you on every deploy.

Four alerts cover most of it:

```
orbit_convergence_lag_seconds > 300     a host has been behind for 5 minutes
orbit_certificates_expiring_soon > 0    renewal is failing, before anyone drops off
orbit_epoch_listener_up == 0            push is down; everyone is polling
orbit_db_scrape_up == 0                 serving, but cannot reach Postgres
```

Everything is labelled by network only. Per-host labels would grow a time series
per machine; per-host detail belongs in the convergence endpoint, which is
queried when someone is looking:

```bash
curl -H "Authorization: Bearer $ORBIT_TOKEN" \
     "localhost:8080/v1/networks/$ORBIT_NETWORK/convergence?format=text"
```
```
config     epoch 42        1198/1204  99.5%
blocklist  epoch 18        1204/1204 100.0%

6 host(s) behind:
  HOST                         CONFIG   BLOCKLIST  LAST SEEN
  edge-07                      41       18         14m22s ago
  ...

rotating a CA past these hosts will cut them off
```

JSON remains the default; `format=text` (or `Accept: text/plain`) is for the
terminal, where this number is actually read.

### A console, when a terminal is the wrong place

`orbitd -ui-addr 8081` serves an operator console: convergence, hosts, the
rotation gates, the audit log, and the two controls an incident actually needs —
block a host, cut an enrollment code.

```bash
ssh -N -L 8081:127.0.0.1:8081 orbit-control     # http://127.0.0.1:8081/ui/
```

A bare port binds **loopback**, and binding it anywhere else without an `https://`
external URL is refused at startup rather than warned about. The listener carries
every host name and a control that removes a machine from the mesh, on the box
holding the root CA key.

Sign in with an ordinary Orbit API token — there is no second user database, no
second set of scopes, and no second thing to revoke. A session *references* its
token, so `DELETE /v1/tokens/{id}` closes every browser it opened on the next
request. Sessions default to **read-only**; a cookie jar holding a credential
that can mint certificate authorities is worth opting into rather than out of.

The cookie is `__Host-` prefixed and never accepted by `/v1` — a test mounts both
surfaces on one mux and asserts the isolation in both directions, because the
interesting failure is not the one you remember to write a handler for.

Server-rendered, no build step, no bundler, no JavaScript required: every screen
works with JS off, because the state where you need this most is the state where
things are already not working. Live updates arrive over SSE when they can.

### CA rotation

Nebula has no intermediate CAs, so the signing key is a root every host trusts
directly — rotation is the only recovery from a compromised one.

```bash
curl -XPOST .../v1/cas          -d '{"name":"ca-2","networks":["10.42.0.0/16"],...}'
curl      .../v1/networks/$N/convergence?format=text   # wait for hosts
curl -XPOST .../v1/cas/$CA2/activate                   # 409 while hosts are behind
#          (hosts renew onto CA2)
curl -XPOST .../v1/cas/$CA1/retire                     # 409 while certs are live
```

- **Creating a CA publishes it.** It advances the config epoch in the same
  transaction, so it reaches every trust bundle immediately as `pending`.
  Without that, convergence would report 100% having distributed nothing, and
  promoting would partition the fleet.
- **Activation refuses while hosts lag**, and the 409 names them.
  `{"acknowledge_cutoff": true}` overrides it for the key-compromise case, and
  is audited as `ca.force_activated` with the number of hosts cut off.
- **Retirement refuses while certificates are live.** `GET /v1/cas` reports
  `active_certificates` per CA so you can see when a rotation has finished.
- **Expired CAs retire themselves.** Safe by construction: nebula enforces
  `leaf.NotAfter <= ca.NotAfter`, so nothing an expired CA signed can still
  verify. It is the only automatic CA state change.

### Protecting the CA key on a self-hosted VM

Nebula has no intermediate CAs, so the signing key is a root of trust for the
whole mesh and it lives on your VM's disk. Three free measures bound that:

```bash
# 1. Encrypt at rest. Bootstrap does this automatically when a passphrase is
#    available, and warns loudly when it is not.
export ORBIT_CA_KEY_PASSPHRASE_FILE=/run/credentials/orbit.service/ca-pass
orbitd ca encrypt -key /var/lib/orbit/ca.key
```

On systemd, `LoadCredentialEncrypted=` puts a **TPM-sealed** secret at that
path, so a stolen disk image is useless without this machine's TPM. Docker's
`/run/secrets/` works the same way. Both also keep the passphrase out of `ps`
and out of anything that logs the environment.

2. **Permissions are enforced, not suggested.** A CA key with any group or other
   permission bit is refused at load. That mistake is otherwise silent, and it
   hands mesh-minting ability to every user on the box.

3. **Keep the CA narrow and short-lived.** Constraints bound what a leaked key
   can mint; a 90-day lifetime bounds how long. Rotation is what makes that
   practical rather than a recurring outage.

**What this does not protect against:** code execution in `orbitd` yields the
decrypted key, because the running process must hold it. No file-based scheme
changes that. Encryption protects against disk snapshots, backups, and detached
volumes — which are the realistic leak vectors on a cloud VM.

### Recovering a host that was offline too long

A host whose certificate expired cannot reach the overlay, so the normal renewal
path is closed to it. It falls back to the public endpoint and proves possession
of the key from its last certificate:

```bash
orbit-agent recover -network prod -reload "systemctl reload nebula@prod"
```

The proof is Diffie-Hellman rather than a signature — nebula host keys on
Curve25519 are X25519 and cannot sign. The server derives its ephemeral keypair
from the pepper and the nonce, so it stores no challenge state; the MAC binds
the *new* public key, so a captured proof cannot be replayed for a key an
attacker holds; and the key proved against comes from Orbit's own records, never
from the request.

Bad proof, unknown host, blocked host, and past-the-window all return the same
`401 recovery denied` — distinguishing them would let a caller enumerate which
hosts are recoverable.

Every recovery is audited and logged at warning level: routine recovery means
renewal is broken for that host, which is the thing actually worth fixing.

### Interop with `nebula-cert`

`cmd/interop` is a manual harness proving compatibility in both directions —
Orbit loads a CA that `nebula-cert ca` produced, mints a host certificate, and
`nebula-cert verify` accepts it:

```
nebula-cert ca -name interop-ca -networks 10.42.0.0/16 -groups prod,web \
              -duration 720h -out-crt ca.crt -out-key ca.key
orbit-interop                       # loads ca.key/ca.crt, writes host.crt
nebula-cert verify -ca ca.crt -crt host.crt
```

---

## Deploying

One VM runs Postgres, the control plane, and a lighthouse. Unit files are in
[`deploy/`](deploy); the full guide is [docs/deployment.md](docs/deployment.md).

Two things from it are worth knowing before you start:

**The control plane can be its own lighthouse**, which is the single-VM answer
and removes the ordering problem that separating them creates:

```bash
orbitd serve -mesh "$ORBIT_NETWORK=10.42.0.1" -lighthouse 203.0.113.10:4242
```

A lighthouse is not in the data path, so a restart is a brief discovery blip and
established tunnels are unaffected. `-relay` also exists but is off by default:
a relay *is* in the data path, on the machine holding the root CA key.

Both flags are **seeds**, applied only when the control plane's host record is
first created. After that the record governs, exactly as it does for every other
host, so moving the lighthouse role is an API call that takes effect without a
restart.

**`cert_ttl` is your recovery budget, not just a rotation cadence.** It is
simultaneously how long a partitioned host keeps trusting revoked peers *and*
how long you have to restore a broken control plane before hosts stop renewing.
For a single VM with no standby, 7 days is the right default — 12 hours is not
enough time to notice an outage and restore a database.

```
cert_ttl   partitioned host loses access   you have this long to restore
24h        24h                             ~12h
168h (7d)  7 days                          ~3.5 days
```

## Design commitments

**The control plane is never in the data path, and never a hard dependency.**
If Orbit is down, existing tunnels keep working and hosts keep their
certificates until expiry. This is a tested property, not an intention
([design.md](docs/design.md) §9).

**Agents hold no long-lived credential.** After enrollment, hosts talk to Orbit
over the Nebula overlay, and their identity is the source address — which
Nebula's firewall verifies against the peer's certificate on every packet
(`firewall.go:Drop`). The management API is never exposed to the internet, and
there is no token on disk to steal ([design.md](docs/design.md) §4.3).

**Host private keys are generated on the host and never transmitted.** There is
no code path that accepts one and no column to store one.

**Orbit works against upstream Nebula releases.** No fork, no patched client.

---

## Known limitations

Stated up front because they are properties of Nebula's trust model, not things
a control plane can engineer away:

- **An attacker with code execution in Orbit can mint certificates** within the
  compromised CA's scope until that CA is rotated. Nebula's flat trust model
  offers no way to make an online signing key less than a root. Scoped CAs,
  KMS custody, and short lifetimes bound the damage; they do not prevent it.
- **A partitioned host cannot learn about revocation.** Certificate lifetime is
  the revocation SLA for a disconnected host. Nothing else bounds it.
- **Blocking is not instantaneous.** The floor is Nebula's
  `connection_alive_interval` (~5 s) plus distribution time.
- **Changing a host's overlay address requires a restart**, not a reload —
  Nebula rejects a config reload whose certificate networks changed.

See [docs/revocation.md](docs/revocation.md) §6 for the full discussion.

---

## Prior art

- **Defined Networking's Managed Nebula** — the commercial product this is an
  open-source answer to. Its published behaviour (once-per-minute polling, "block
  propagates within 60 seconds") is the baseline to beat.
- **Headscale** — not code-reusable, but the model for how an open-source
  control plane for a commercial mesh should be positioned and structured.
- **smallstep/step-ca** — the source of the *provisioner* abstraction that
  Orbit's enrollment methods borrow.
- **losfair/supernova** — an earlier, minimal Nebula control plane. Useful as a
  scope reference.

## License

TBD — MIT or Apache-2.0 to match the ecosystem.
