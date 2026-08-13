# Deployment

Running Orbit on one ordinary VM.

Service files are **generated**, not copied: `orbitd bootstrap --write-unit`
writes the control plane's, and `orbit agent install` writes each machine's. A unit
file kept in a docs directory drifts — the flags change, the example does not,
and somebody pastes something that stopped working two releases ago.
[`deploy/`](../deploy) holds only what cannot be generated: the compose file and
an environment template.

---

## 1. What the pieces need

| Piece | Needs |
|---|---|
| Postgres 15+ | local is fine; the control plane is the only client. 15 is the floor: the schema uses `ON DELETE SET NULL (column)`, which 14 cannot parse |
| `orbitd` | a public TLS endpoint for enrollment; an overlay address on each network it serves |
| A lighthouse | **a stable public IP and an open UDP port** — the one hard requirement, and `orbitd` can be it |
| Managed memberships | outbound UDP; no inbound, no public address |

The lighthouse is the only component that must be publicly reachable, because
it is how memberships find each other. It can be the same VM as everything else, which
is the cheapest working topology:

```
        ┌──────────────── one VM ────────────────┐
        │  postgres                              │
        │  orbitd    :8080/tcp  public (enroll)  │
        │            :4242/udp  public           │  ← its own lighthouse
        │            10.42.0.1:8443 overlay      │  ← agent API
        └────────────────────────────────────────┘
                            ▲
                  UDP 4242  │  memberships punch to here, then talk directly
```

`orbitd` runs nebula in-process on a userspace stack, so there is no tun device,
no root, and no separate nebula service on this machine. Managed memberships run
nebula in-process too, inside `orbit agent run` — one binary and one service,
serving every network the membership has joined.

Put a reverse proxy in front of `:8080` for TLS. The agent API is **not** on
that listener — it lives only on the overlay — so nothing an unauthenticated
stranger can reach is exposed by it beyond enrollment.

---


## Before you start it

`orbitd doctor` runs every check `serve` would run, without starting anything.

```bash
orbitd doctor --dsn "$ORBIT_DSN" --addr :8080 --enroll-url https://orbit.example.com
```

It exists because `serve` validates as it goes, and validates `--addr` at the very
last statement — after the store is open, the vault is unsealed, the CA registry
is built and every mesh node has joined. A typo'd listen address therefore costs
a full startup and fails on the final line. `doctor` binds and releases each
address first, so the cheap mistakes are reported before the expensive work is
attempted.

Every check is read-only, so it is safe to run against a control plane that is
already serving. In particular it never applies a migration; it only compares
what is applied against what this binary bundles, which is also the one place
that will tell you the database was migrated by a *newer* orbitd than the one
you are about to start.

## 1a. Ports

| Port | Proto | Open to | Why |
|---|---|---|---|
| **4242-4257** | udp | the internet | Nebula, **one port per network**. 4242 is the first; a control plane serving one network uses only that |
| **8080** | tcp | the internet | Enrollment and admin. Put TLS in front and use 443 once you have a name |
| 22 | tcp | your addresses | ssh |
| 8443 | — | **nothing** | The agent API listens on `orbitd`'s in-process userspace stack. The kernel never sees it, so there is nothing to open and no way to expose it by accident |
| 9464 | tcp | loopback | Metrics. The output is fleet inventory |
| 8081 | tcp | loopback | The console. Reach it over `ssh -L` |
| 5432 | tcp | local | Postgres |

```bash
firewall-cmd --permanent --add-port=4242-4257/udp
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --reload
firewall-cmd --list-services   # confirm ssh survived before you drop the session
```

**Why a range.** Nebula's v1 wire header carries no network identifier — 16
bytes of version, type, subtype, reserved, remote index and message counter, and
the remote index is an index into *one* interface's hostmap. A received packet
therefore cannot be attributed to a network, so one UDP socket is one network
and a control plane on N networks binds N ports. `--mesh <uuid>=<addr>:<port>`
sets each one; omitting it takes `--nebula-port`, and two networks that both omit
it are refused at startup rather than colliding inside nebula.

Sixteen is the documented range because 4242 stays the first (a single-network
deployment is unchanged), and sixteen covers what a self-hosted control plane
plausibly runs — prod, staging, dev, a few per-tenant — while staying small
enough to write as one rule. Past that, run a second `orbitd` over a disjoint
set of networks, which is the scaling story regardless.

Opening a port is not listening on it. Only the networks passed to `--mesh` bind
anything; the rest refuse at the socket layer whatever the firewall says. If you
would rather open exactly what you use, open `4242` plus one per additional
network and revisit it when you add one.

Minimal images often ship without firewalld — `dnf -y install firewalld &&
systemctl enable --now firewalld` first, or use your provider's network firewall,
which has the advantage of filtering before packets reach a service you forgot
was listening.

Verify from somewhere else, and check the negative case too:

```bash
nc -zv  <host> 8080
nc -zuv <host> 4242   # and one per additional network: 4243, 4244, …
nc -zv  <host> 5432   # must FAIL
```

Postgres defaults to `listen_addresses = 'localhost'`, so the last one should
refuse regardless of the firewall. If it connects, fix that before anything else.

---

## 2. Postgres

Two roles. The application must not be the one that owns the tables.

```sql
CREATE DATABASE orbit;
-- orbit_app is created by the migrations; give it a password and nothing else.
```

```bash
orbitd migrate --dsn "postgres://postgres@localhost/orbit"
psql -c "ALTER ROLE orbit_app LOGIN PASSWORD '…'"
```

**On RHEL-family systems** (AlmaLinux, Rocky, RHEL) two defaults will stop you
here, and both look like something else:

`pg_hba.conf` ships `ident` for TCP connections from localhost, and there is no
identd running — so the app role's password is rejected no matter how correct it
is, with `Ident authentication failed`. Switch the two loopback lines:

```bash
PGHBA=/var/lib/pgsql/data/pg_hba.conf
sed -i -E '/^host[[:space:]]+all[[:space:]]+all[[:space:]]+(127\.0\.0\.1\/32|::1\/128)[[:space:]]+/ s/ident$/scram-sha-256/' "$PGHBA"
systemctl reload postgresql
```

Set the password *after* that, because how it is stored depends on
`password_encryption` at the time and has to match the method `pg_hba` now
demands.

And `sudo` resets `PATH` to `secure_path`, which does **not** include
`/usr/local/bin`. `sudo -u postgres orbitd migrate` fails with
`orbitd: command not found`; use the full path:

```bash
sudo -u postgres /usr/local/bin/orbitd migrate --dsn "postgres:///orbit?host=/var/run/postgresql"
```

Verify before going further — this exercises the role, the password, the `pg_hba`
method, and your DSN in one shot:

```bash
psql "$ORBIT_DSN" -c '\dt orbit.*' | head
```

`orbit_app` holds no `CREATE` and cannot `UPDATE` or `DELETE` the audit log. Run
the control plane as anything more privileged and a bug can alter the schema, a
compromise can erase its own tracks, and you will not find out until you need
the audit trail.

---

## 3. The keys

Nebula has no intermediate CAs, so a network's CA key is a root of trust for the
entire mesh. **It is not a file.** The CA signing key and the network identity
key are rows in Postgres, encrypted under a key encryption key (KEK) that the
database never sees. See [key-custody.md](key-custody.md).

That leaves exactly one secret for you to hold:

```bash
head -c 32 /dev/urandom | base64 > /tmp/kek
systemd-creds encrypt --name=kek --with-key=host+tpm2 /tmp/kek /etc/orbit/kek.cred
shred -u /tmp/kek
```

and one variable pointing at it — `ORBIT_KEK_PASSPHRASE_FILE`, or
`ORBIT_KEK_PASSPHRASE` for the direct form. The file form is what
`systemd-creds` produces: the passphrase is sealed to this machine's TPM and
appears as a file the unit can read, never as an environment variable that `ps`,
a crash dump, or `docker inspect` would carry.

`--with-key=host+tpm2` seals it to this machine's TPM, so a stolen disk image, a
snapshot, or a detached volume is useless without this host. Many cheap cloud
VMs expose no vTPM; `--with-key=host` still keeps the secret out of `ps` and out
of anything that logs the environment, but it will not protect a stolen image,
which is the threat `host+tpm2` exists for. Know which one you have.

### The property this preserves

> Read access to the database does not let an attacker mint a certificate.

An attacker needs the database **and** the KEK. That is the same two factors a
key file on this VM required, on the same two hosts — what changed is the count:
one secret per deployment instead of one key file per network, with nothing to
copy to a replica and nothing to drift.

Setting a wrong passphrase fails at **startup**, not at the first signing
operation. A replica that started cleanly and failed the first time somebody
added a machine would fail at the worst moment and be the hardest to attribute.

### What it means for backups

Two things, kept apart, and either alone is worthless:

1. the database
2. `ORBIT_KEK_PASSPHRASE`

Losing the passphrase destroys the network exactly as losing the database does —
every host re-enrolls by hand. §7 has the mechanics.

**What this does not protect against:** code execution in `orbitd` yields the
decrypted keys, because the process must hold them. Encryption covers the
storage layer — snapshots, backups, detached volumes, a leaked `pg_dump` — which
is where the realistic exposure is on a rented VM.

---

## 4. Bring-up

**The supported path is one command**, and everything below it is the same
sequence spelled out for a deployment that cannot use it:

```bash
curl -fsSL https://raw.githubusercontent.com/griffithind/orbit/main/scripts/setup-control-plane.sh \
    | sudo bash -s -- --public-ip 203.0.113.10
```

It does every step in this section — docker, ports, secrets, migrate,
bootstrap, start, break-glass — and is safe to re-run: existing secrets are
reused, and a bootstrapped network is not bootstrapped again. Prefer it. The
native path exists for a host where containers are not an option, and it is
where first deployments actually go wrong: `pg_hba`, firewalld, SELinux, unit
file syntax, file ownership.

### The same thing by hand

On a single VM the control plane is also the lighthouse, which removes the
awkward ordering that separating them creates.

```bash
# 1. Bootstrap. Prints the network id and an admin token (once). The CA and
#    identity keys are sealed into Postgres under the KEK — no key file, and
#    nothing to chown afterwards.
export ORBIT_KEK_PASSPHRASE_FILE=/etc/orbit/kek.plain
orbitd bootstrap --dsn "$ORBIT_DSN" \
    --network prod --cidr 10.42.0.0/16 --cert-ttl 168h \
    --write-unit --overlay-addr 10.42.0.1 --lighthouse 203.0.113.10:4242 \
    --enroll-url https://orbit.example.com/enroll/v1/enroll

# 2. Start it, as its own lighthouse. --write-unit above filled in the unit and
#    the env file from this bootstrap's own results, so there is nothing to
#    copy across and nothing to mistype.
systemctl enable --now orbit-control

# 3. Drop the plaintext passphrase; the unit reads the sealed credential.
shred -u /etc/orbit/kek.plain

# 4. Mint the break-glass token now, while everything works. See section 5.
orbitd token create --name break-glass --scopes '*'

# 5. Every machine from here. Reserve a place; it prints a single-use code.
orbit membership reserve --name web-01 --role web

# On the machine: install once, join once per network.
sudo orbit agent install
sudo orbit join --url https://orbit.example.com --network prod --code orb_1_…
```

`install` is a MACHINE-level action — it generates the device identity at
`/var/lib/orbit/device.key` and installs the service — and `join` is per
network. A machine on three meshes is installed once and joined three times; the
service rescans its root, so each join lands without a restart and without
dropping the tunnels of the networks it already serves.

Omit `--code` and the machine lands in `orbit membership pending` for an operator
to authorize. That is the better shape for anything handed to a person, because
no secret has to travel to it — and it is the only shape available when the
machine is provisioned before anyone knows what it will be called.

`--lighthouse` is a **seed**, not a setting. It applies only when the control
plane's own membership is first created; after that the membership is the source
of truth, exactly as it is for every other machine. That is why there is no
`--lighthouse=true`: a public address cannot be discovered from behind NAT, so
the operator states it once, and a lighthouse nobody can reach is worse than
none because every host keeps dialling it.

A control plane that is its own lighthouse needs a **fixed** UDP port —
`--nebula-port`, which defaults to 4242. Nebula refuses `am_lighthouse` with no
port rather than starting into a state where every host is told to reach it
somewhere it is not listening, and Orbit checks the same thing first so the
error names the flag and the membership rather than a nebula config field.

**The address belongs to the machine, the port to the membership.** What other
machines dial is derived, not stored: every public address on the `device`,
paired with that `membership`'s port. So changing where a machine is reachable
is one command that fixes every network it lights, rather than one edit per
membership with a wrong one leaving a lighthouse advertising a dead address:

```bash
# Where this machine is reachable. Hosts or names, never ports.
orbit device set-addrs lh-01 203.0.113.20

# What it is, in this network.
orbit membership set lh-01 --lighthouse
```

`--advertise-port` on `membership set` exists for the one case the derivation
cannot infer: a machine behind port forwarding, where the port that reaches it
is deliberately not the port it binds. Leave it unset otherwise.

`orbitd` logs the roles actually in force at startup, read from the record — and
warns if you passed a seed flag it ignored, rather than letting you believe it
took.

### Why lighthouse and not relay

`--relay` exists and is off by default, and that asymmetry is deliberate.

A **lighthouse** answers queries and coordinates hole punching. It is not in the
data path. Restarting the control plane briefly interrupts discovery for memberships
that do not already have a tunnel; established tunnels carry on. That is a
seconds-long blip, and worth it to run one thing instead of three.

A **relay** forwards other memberships' traffic — on the machine holding the mesh's
root CA key, spending its bandwidth and CPU, and a restart drops that traffic
rather than delaying a handshake. Run a separate relay when you need one.

### Moving the lighthouse off later

Handing the role to a dedicated host is a normal change, not a migration:

```bash
# 1. Enroll the new lighthouse with its public address.
# 2. Stand the control plane down. No restart, no flag.
curl -XPATCH .../v1/memberships/$CONTROL_PLANE_HOST_ID \
     -d '{"is_lighthouse":false}'
```

Only the role is cleared. The machine's public address stays on the `device`,
because it is still true — the control plane is still reachable there, it just
no longer asks anyone to dial it. Clearing it would be a second, unrelated
change (`orbit device set-addrs $NAME` with no addresses).

The config epoch advances, every agent stops listing the old address on its next
poll, and the control plane picks up the new lighthouse the same way — it
refreshes its own configuration on an epoch change like any other host.

### Reaching a network that cannot run Orbit

A machine in the mesh can forward for a prefix that is not in the overlay — a
Raspberry Pi in front of a lab network, a jump box in front of a VPC.

**The CA has to permit it, and that is decided once.** Nebula requires the
gateway's certificate to carry the prefix, and a CA constrains what it will
sign. There is no default, deliberately: a CA that quietly permitted a range
would grant routing authority nobody asked for.

```bash
orbitd bootstrap --network prod --cidr 10.42.0.0/16 \
    --unsafe-networks 192.168.88.0/24,10.90.0.0/16
```

**Widening it later is a new CA and a rotation**, because the constraint is
signed and a signature cannot be edited. Rotation is a rehearsed operation
(§6 of [design.md](design.md)) — the new bundle reaches every machine before the
new CA signs anything — but it is a scheduled change, so it is worth listing the
prefixes you might ever route while you are here.

Then, per gateway:

```bash
orbit route add lab-pi 192.168.88.0/24
```

The route takes effect at that gateway's next renewal, because the prefix has to
be in its certificate. A second gateway for the same prefix is the whole of high
availability — nebula load-balances across them by weight and falls to a
survivor when one stops answering:

```bash
orbit route add spare-pi 192.168.88.0/24 --weight 5
```

**Who may use it is ordinary policy.** A routed subnet is a destination like any
other:

```yaml
allow:
  - src: [role:laptop]
    dst: [cidr:192.168.88.0/24]
    proto: any
```

**Forwarding and NAT are handled for you**, on a Linux gateway. The agent
enables IP forwarding and installs a masquerade rule when a route asks for one,
in an nftables table it owns whole:

```bash
nft list table inet orbit     # exactly what Orbit did, in nft's own syntax
```

Removal is `nft destroy table inet orbit`, which `orbit leave` runs —
it needs no record of what was in the table, so it works even if the rules were
edited. Nothing Orbit adds goes into a chain anything else writes to. IP
forwarding is left enabled on uninstall, because a container runtime probably
wants it too.

A **Linux** gateway. A Mac can use routes — nebula installs them itself — but
cannot advertise one; the agent refuses rather than pretending.

### Exit nodes

An exit node is a route for `0.0.0.0/0`, and a machine takes one deliberately:

```bash
orbit route add lab-pi 0.0.0.0/0 --masquerade
orbit exit-node ls laptop
orbit exit-node use laptop <route-uuid>
orbit exit-node off laptop
```

Nobody gets a default route by accident — it is rendered only for the machine
that chose it. Choosing is a control-plane call rather than a local edit,
because the agent runs only what the control plane signed.

Two limits worth knowing:

- **Advertising still requires Linux.** Forwarding and NAT are implemented for
  Linux only; a Mac refuses rather than pretending. Using an exit node works on
  both — Linux through `so_mark` and an `ip rule`, macOS by pinning nebula's
  socket to the physical default route's interface. Both are installed and
  removed by the agent.
- **Choosing does not grant.** Policy still decides whether that membership may
  reach `0.0.0.0/0` through that gateway. Choosing one it may not use produces a
  default route that carries nothing.

### A dedicated lighthouse, provisioned unattended

A lighthouse is the machine you least want to finish by hand: a fixed-address
box in a datacentre, brought up from a template. The reservation carries what it
will **be**, not only what it will be **called**, so there is no follow-up call
and no window in which the machine is up and the fleet has been told there is no
lighthouse:

```bash
orbit membership reserve --name lh-01 --lighthouse --public-addr 203.0.113.20
```

Hand the printed code to cloud-init. When the machine redeems it, the membership
comes into existence already a lighthouse, the address lands on the machine's
`device` record, and every other host picks it up on its next poll.

`--public-addr` is required with `--lighthouse` for a machine Orbit has not met. A
lighthouse nobody can reach is worse than none — every host keeps dialling it —
and reservation time is the last moment an operator is present to say where it
will be. If the machine has already joined another network it already has its
addresses, and `orbit device set-addrs` is the way to change them.

### Separating them from the start

If you want the control plane out of the data path entirely, the ordering
matters: `orbitd` joins the overlay as a nebula host, but reaching the overlay
needs a lighthouse, which has to be enrolled by a running `orbitd`.

1. Start `orbitd` with **no** `--mesh` — enrollment and admin work, the agent API
   does not exist yet, and it says so at startup.
2. Reserve and bring up the lighthouse as above, start its nebula.
3. Restart `orbitd` with `--mesh`.

---

## 5. The break-glass token

### What it is not for

Break-glass is about **an operator locked out of the admin API**. It has nothing
to do with a machine locked out of the mesh, and the two are worth keeping
apart because they have different causes and different answers:

| Locked out | Cause | Way back |
|---|---|---|
| A **machine** | its certificate expired while it was offline | re-run `orbit join` — the device key never expires |
| A **person** | every admin token expired, revoked, or lost | `orbitd token create`, which authenticates with the database |

The device key removed the first entirely (`enrollment.md` §6.1), and removed
nothing from the second. A fleet can be perfectly healthy — every tunnel up,
every machine renewing on schedule — while no human can add a machine, rotate a
CA, or block a stolen laptop. That is precisely the situation this section
exists for.

One caveat on "the device key never expires": it removes *credential expiry* as
a cause of lockout, not *control-plane availability*. A machine still needs the
control plane to be up and its database reachable, and a blocked device or a
suspended membership is still refused — which is the point of both.

### Why it needs its own credential

`POST /v1/tokens` requires a token. So the one failure it cannot help with is
losing every admin credential — a token revoked in error, an expiry nobody
tracked, or an identity provider that gates the API and is itself unreachable
(design.md 4.5 has the in-mesh Keycloak version of that). There is no API path
back in, by construction.

`orbitd token create` is the way back. It authenticates with the database, not
with the API:

```bash
orbitd token create --name break-glass --scopes '*' | \
    op item create --category=password --title='Orbit break-glass' password=-
```

The plaintext is the only thing on stdout — everything else goes to stderr — so
it pipes straight into a secret store without ever appearing in shell history or
in a file.

**This grants nothing the DSN did not already carry.** `orbit_app` holds INSERT
on `orbit.api_token` because `POST /v1/tokens` needs it, so anyone who can run
this could already have written the same row by hand with a SHA-256 they
computed themselves. The command makes the supported path convenient rather than
opening a new one — and unlike the hand-written row, it leaves an audit entry.

### The procedure

**1. Mint one at bring-up**, immediately after `orbitd bootstrap`, and store the
plaintext **outside the mesh and off this machine** — a password manager, not
`/etc/orbit`, not a file on the VM whose failure you are planning for.

**2. Give it `*` and no expiry.** Both are deliberate. A break-glass credential
that quietly expired is not one, and a narrower scope is a bet about which
failure you will have.

**3. Rotate the day-to-day tokens, not this one.** Ordinary work should use
scoped tokens minted through the API; this exists to get you back to the point
where you can do that.

**4. Escrow the KEK beside it, once there is one.** [key-custody.md](key-custody.md)
§4.1 moves the CA and identity keys into Postgres under a single key-encryption
key. That is the right trade for HA and it changes what a lost secret costs:
today losing a CA key file costs one network's CA, and afterwards losing the KEK
costs **every CA key and every identity key at once**.

The network identity key is the worst case, because it is the one key that can
never be rotated — its hash is the network ID every machine stores. Losing it
does not just require re-issuing certificates; it retires the network's identity.

So the KEK belongs wherever the break-glass token is, and **not** wherever the
database backups are. A backup and a KEK in the same place is a backup that is
sufficient on its own, which is the property §7 relies on not being true.

**5. Test it on a schedule** — quarterly is enough. An untested recovery path is
a belief, not a capability:

```bash
ORBIT_BREAK_GLASS=$(op read 'op://Private/Orbit break-glass/password') \
    make check-break-glass
```
```
OK    break-glass token valid
      name    break-glass
      scopes  *
      expires never
```

It exits non-zero on any problem, so it works as a cron job or a CI step. The
token is passed through the environment rather than as an argument — an argument
is visible in `ps` to every user on the box — and is never printed.

**Checking that a request returns 200 is not enough**, which is why this calls
`/v1/whoami` rather than any convenient endpoint. A token whose scopes were
narrowed still authenticates and still returns 200 everywhere it is allowed; it
would fail only at the moment it was needed. The check compares the scopes it
gets back:

```
FAIL  token no longer holds '*' (has: memberships:read)
```

Each failure is distinguished, because they need different responses: `401`
means revoked, expired, or a database restored from a backup predating the
token; `cannot reach` means the control plane is down, which is a different
problem from the token being bad. It also warns 30 days before an expiry
(`ORBIT_WARN_DAYS`), on the theory that a break-glass token should not have one
at all and learning about it afterwards is the entire failure.

The script is POSIX `sh` and `curl` — no `jq`. It has to run on a machine that
may be having a bad day, and a recovery check that depends on tooling is one
more thing that can be missing when it is needed.

**5. Rotate it after any real use**, because a credential that has been read
out of a vault under pressure has been seen by people and possibly pasted into
places:

```bash
orbitd token create --name break-glass-2 --scopes '*'   # new one first
orbit token revoke $OLD_ID                            # then the old one
```

Minting the replacement before revoking the old one is the order that cannot
lock you out halfway.

### Watching for misuse

A `*` token that never expires is a standing risk, and the answer is that it is
observable rather than hidden. Every use updates `last_used_at`, and creation is
audited even from the command line:

```bash
orbit token ls
orbit audit --action token.created
```

```
system  ops-admin  token.created  {"via":"orbitd token create","name":"break-glass"}
```

An offline-created token is attributed to `system`, not to a user: there is no
authenticated actor on a command line, and the OS username in `actor_display` is
a hint about a shell session rather than proof of anything. `last_used_at`
moving on a break-glass token nobody reports using is worth an immediate look.

`GET /v1/whoami` answers the same question from the other direction — which
credential is this shell holding — and needs no scope, since describing a caller
to itself reveals nothing it does not already have:

```bash
orbit whoami
```

---

## 6. Certificate lifetime is your recovery budget

The single most important number, and it is a trade-off with no free side.

`cert_ttl` is simultaneously:

- the **revocation SLA for a partitioned host** — one that cannot reach the
  control plane keeps trusting its peers until its certificate expires, and
  nothing shortens that; and
- the **time you have to fix a broken control plane** before memberships start
  failing to renew and drop off the mesh.

| `cert_ttl` | Partitioned host loses access within | You have this long to restore |
|---|---|---|
| 24h | 24h | ~12h |
| **168h (7d)** | 7 days | **~3.5 days** |
| 720h (30d) | 30 days | ~15 days |

For a single VM with no standby, **7 days is the right default** and is what the
bring-up above uses. Twelve hours of slack is not enough time to notice an
outage, get to a computer, and restore a database. Take 24h only when you have a
second replica and a tested restore.

Note that this is a bound on *silent* failure only: a membership that can still reach
the control plane gets revocations in about five seconds.

---

## 7. Backups

Three things, with very different consequences.

| Lose | Consequence | Recovery |
|---|---|---|
| **Database** | Devices, memberships, certificates, blocklist, audit trail | Restore. Without a backup: every machine joins again and is authorized by hand |
| **CA key** | Cannot issue or renew anything | Recoverable *if you notice in time* — see below |
| **KEK passphrase** | Every CA key and identity key becomes unreadable | **Nothing.** The database holds only ciphertext. Escrow it — see §5 |
| **Control plane device key** | The control plane's own membership no longer names a device it holds | Restore, or delete that membership and let it rejoin — see below |
| **`ORBIT_KEK_ARGON_MEMORY_MIB`**, if raised | The KEK derives to a different value | **Nothing distinguishes this from a wrong passphrase.** The parameter is not stored beside the salt; record it with the passphrase |

**This table is the backup set.** `scripts/setup-control-plane.sh` and
`deploy/compose.yml` each say "two things" and mean the two that cannot be
reconstructed; they point here for the whole list. Two more facts belong to the
*restore*, not the backup, and are covered in §10:

- The replica's membership is found by overlay address and refused if the name
  differs, so a restore onto a host with a **different hostname** needs
  `orbitd serve -name orbit-control-<old-hostname>`.
- `-lighthouse` seeds public addresses only at creation, so a restore onto a
  **different public IP** keeps advertising the old one to the whole fleet.
  Fix it with `orbit device set-addrs` before agents need to find it.

```bash
# Nightly is enough; certificates are re-issuable, the membership inventory is not.
pg_dump orbit | age -r "$BACKUP_KEY" > orbit-$(date +%F).sql.age
# This dump already contains every CA key and identity key — as CIPHERTEXT, and
# that is the whole design. What it does NOT contain, and must not, is the KEK
# passphrase. Escrow that separately, somewhere the TPM-sealed copy is not: a
# sealed credential does not survive the machine it is sealed to. See section 5.
#
# There is no key file to copy. `file://` signer refs were removed rather than
# deprecated, so a deployment cannot be half in the database and half on disk.
# The control plane is a machine on its own network, so it has a device key too.
# Small, never rotated, and not secret in the way the CA key is — it cannot mint
# anything — but losing it makes this control plane a different machine.
cp /var/lib/orbit/device.key device.key.backup
```

**Losing the CA key is survivable, and the window is one certificate lifetime.**
Nothing about a lost key stops the existing mesh working. Create a new CA with a
new key, publish it (creating a CA pushes it to every trust bundle), let memberships
converge, then activate it — memberships renew onto it. That is the ordinary rotation
in [design.md §6](design.md#6-ca-rotation), and it works as long as memberships are
still up and still renewing, which is true until their current certificates
expire. Miss that window and every host must re-enrol.

**Losing the control plane's device key is a nuisance, not an outage.** It is
the machine's identity, not an authority: nothing it holds can issue anything.
On the next start `orbitd` generates a new one, and the membership it recorded
for itself still names the old device. Delete that membership and let it be
recreated, or restore the file. Nothing else in the fleet is affected, because
no other machine ever verified it.

**The data plane survives the control plane's death.** Orbit is not in the
traffic path. If this VM burns down, every existing tunnel keeps carrying
traffic until certificates expire. That is the property that makes a single-VM
deployment defensible, and `cert_ttl` is exactly how much of it you get.

---

## 8. Watching it

Three things carry the load: metrics, the convergence endpoint, and a short list
of log lines.

### Metrics

`orbitd` serves Prometheus exposition on **`127.0.0.1:9464/metrics`** by
default. It binds to localhost deliberately — the output enumerates network
names, host counts, and blocklist sizes, which is fleet inventory. Move it to an
overlay address (`--metrics-addr 10.42.0.1:9464`) to scrape it from another
machine, or `--metrics-addr ""` to turn it off.

The fleet gauges are read from Postgres **at scrape time**, not held in memory.
That is why two replicas report identical numbers and why a restart does not
reset convergence to zero and page you during every deploy.

Every rule below names what to do when it fires. A signal with no written action
is how this table came to alert for two years on
a `reason="recover"` series on the certificates-issued counter — a label value
nothing has ever passed to `Metrics.CertificateIssued`, so the alert could not
fire and nobody noticed, because nobody had to say what they would do about it. ADR-0008 is the decision that produced this
table; it is also where the reasoning for each threshold lives.

| Alert when | Why, and what to do |
|---|---|
| `orbit_hosts_config_converged < orbit_hosts_total` for 15m | Hosts are behind and staying behind. **This is the one that catches a stuck fleet**, and it is not the same as the lag gauge below — see the note after this table. Check `orbit_config_reverts_total` first: a revert means the pushed generation broke hosts and they are running the previous one. |
| `orbit_convergence_lag_seconds > 300` | A host has been behind AND silent for five minutes. Catches a machine that has stopped talking; it cannot catch one that talks and refuses to apply. |
| `orbit_hosts_clock_skewed > 0` | A machine's clock is more than a minute from the control plane's. Nebula validates certificate windows against wall time with no leeway, so such a host rejects its own brand-new certificate — the apply fails, the loop rolls back, and the failure reads as a bad configuration rather than a bad clock. Fix NTP on the host; `orbit status` names it there too. |
| `orbit_hosts_data_plane_down > 0` | Nebula is not running on a host whose agent is healthy. It polls, it reports an applied epoch, and every other gauge here counts it as converged — it carries no traffic. Systemd owns nebula on that host; look there, not at the control plane. |
| `orbit_ca_min_remaining_seconds < 604800` (7d) | The active signer expires in a week. At zero, enrolment and renewal stop for the whole network at once. Create and activate a replacement — `orbit ca create` then `orbit ca activate`, which requires convergence first. |
| `orbit_certificates_expiring_soon > 0` | Renewal is failing for someone, well before they drop off. The control plane cannot renew on a host's behalf — it holds the key — so this is a per-host investigation. `orbit_certificate_min_remaining_seconds` says how long there is. |
| `increase(orbit_renewals_failed_total[15m]) > 0` | Renewals are being refused. Successes were always counted and failures only logged, so without this a fleet that had stopped renewing looked like one that had stopped needing to, until the row above tripped weeks later. |
| `time() - orbit_maintenance_last_success_seconds > 3600` | The maintenance sweep has stopped. Blocklist pruning and expired-CA detection stop with it, silently. Zero means one has never completed since this process started. |
| `orbit_epoch_listener_up == 0` | Push is down and every agent on this replica has fallen back to polling. Convergence goes from seconds to a poll interval. Do NOT deploy this rule with `--no-push`, where the gauge reads 0 by design. |
| `orbit_db_scrape_up == 0` | Serving, but cannot reach Postgres. |
| `increase(orbit_config_reverts_total[1h]) > 0` | A pushed generation severed hosts and their guard reverted it. More than one host means the push broke the fleet; those hosts run the previous generation and have quarantined the new one for 30 minutes. |
| `increase(orbit_agent_poll_fallback_total[1h]) > 0` | The watcher cap was reached. Note this is a one-way door per agent process: raising `--max-watchers` does not bring those agents back, only restarting them does. |

**Why two convergence rules, and why the first one is the real alert.**
`orbit_convergence_lag_seconds` is derived from the device's `last_seen_at`,
which every poll stamps — including a poll from a host that then refuses to
apply. So it measures SILENCE, not staleness. A host polling every thirty
seconds while quarantining a generation, or one restored by `unblock` that never
enrolled, pins that gauge under one poll interval forever and the 300-second
rule can never fire for it. The converged-count comparison does move, which is
why it is the page. Both are kept: the lag gauge is still the fastest signal for
a machine that has genuinely gone quiet.

Also exported, and deliberately not alerted on: `orbit_config_epoch`,
`orbit_blocklist_epoch`, `orbit_hosts_total`,
`orbit_hosts_blocklist_converged`, `orbit_blocklist_entries`,
`orbit_certificate_min_remaining_seconds`, `orbit_watch_connections`,
`orbit_enrollments_total{result}`, `orbit_certificates_issued_total{reason}`,
`orbit_epoch_notifications_total{kind}`, and the standard Go runtime collectors.
Enrolment failures are the loudest of these and are still not a page: the
enrolment endpoint is public and unauthenticated, so a scanner produces them,
and an alert on other people's typos is one an operator learns to close.

Everything is labelled by network only. Per-host labels would grow a time series
per machine and make Prometheus the most expensive part of a deployment that
otherwise runs on one small VM; per-membership detail is in the convergence endpoint,
which is queried when someone is actually looking.

### Convergence

```bash
# Check this before any CA rotation, and after any block.
orbit converge
```
```
config     epoch 42        1198/1204  99.5%
blocklist  epoch 18        1204/1204 100.0%

6 host(s) behind:
  HOST                         CONFIG   BLOCKLIST  LAST SEEN
  edge-07                      41       18         14m22s ago

rotating a CA past these memberships will cut them off
```

### The web console

`orbitd --ui-addr 8081` serves an operator console. Off unless you ask for it, and
a bare port binds **loopback** — the listener carries every host name, every
overlay address, and a control that cuts a membership off the mesh, on the machine
holding the mesh's root CA key.

```bash
ssh -N -L 8081:127.0.0.1:8081 orbit-control    # then http://127.0.0.1:8081/ui/
```

Binding it anywhere else without an `https://` `--ui-url` is **refused at
startup**, and not only on principle: the session cookie is `__Host-` prefixed
and therefore `Secure`, so a browser will not store it over plain http on a
non-loopback origin. The login form would appear to work and silently return you
to itself.

**Sign in with an ordinary Orbit API token.** There is no second user database.
Sessions default to **read-only** — the common use is checking convergence from
a phone, and a cookie jar holding a credential that can create certificate
authorities is worth avoiding. Untick it to act.

A session *references* its token rather than copying its scopes, so
`orbit token revoke` closes every browser it opened, on the next request:

```bash
orbit token revoke $TOKEN_ID     # every console signed in with it is out
```

That is the big hammer, and it stops the operator's shell and their CI along
with the browser. Closing a laptop left in a cafe should not require revoking a
credential three other things are using, so sessions can be ended one at a time —
from the **API tokens** page, or from a terminal:

```bash
orbit session ls                 # token, address, browser, last activity
orbit session revoke $SESSION_ID # that browser only; the token keeps working
```

The terminal form is not a convenience. The operator whose laptop is missing
reaches for a shell, and the browser they need to close may be the only one they
had — a control that exists solely in the console is unavailable in exactly the
situation it was built for. Listing is `tokens:read`, ending one is
`tokens:write`: the same pair that guards the token, because revoking the token
already does the larger version of this.

The list is live sessions only. A session that expired, was signed out, or went
idle is absent rather than greyed out: the question the page answers is what can
reach the control plane at this moment. The history — who signed in, from where
— is in the audit log, which outlives these rows; they are swept within twelve
hours of dying.

Every screen works with JavaScript disabled — forms are real forms, links are
real links. Live updates are an enhancement, not a requirement.

One behaviour worth knowing: following a link into the console from chat or a
ticket lands on the login page even with a valid session, because the cookie is
`SameSite=Lax` and the first navigation is cross-site. A reload signs you
straight in.

### Log lines worth an alert

Most of these now have a metric alongside them. Keep both: a counter tells you
something happened, the log line tells you to which host.

| Message | Means |
|---|---|
| `host deleted and its certificates revoked` | a decommission; check it was intended |
| `token revoked itself; this request was its last` | end of a credential rotation, or someone locked themselves out |
| `certificate is overdue for renewal` | a membership has stopped rotating; it will drop off at expiry |
| `CA activated before convergence` | someone forced a rotation; memberships were cut off |
| `active certificate authority has expired` | the network's signer outlived itself; enrollment and renewal fail until a replacement CA is created and activated. The sweep deliberately does not retire it — retiring is a rotation step and cannot be undone through the API |
| `host reverted a pushed generation` | that host applied a config and then could not reach the control plane, so its guard rolled back. More than one means the push severed the fleet |
| `reverted to the previous generation` | a pushed config broke a membership and it rolled back |
| `CA key written UNENCRYPTED` | fix before anything else |
| `epoch listener dropped` | push is down; agents fell back to polling |
| `agent API disabled` / `no --mesh configured` | memberships cannot poll, renew, or receive revocations |

The maintenance sweep logs a summary every 15 minutes when it does anything.

---

## 9. Sizing

Measured, in `e2e/scale_test.go`:

- Rows are free. Memberships, certificates, and audit entries cost Postgres and
  nothing else.
- Each network `orbitd` **joins** costs ~28 goroutines and ~0.33 MB idle — it is
  a full nebula instance. Low hundreds of joined networks per process.
- Long-poll watchers cost one connection and one goroutine per agent, capped by
  `--max-watchers` (5000/network default). Over the cap, agents fall back to
  polling rather than being refused.

**Memory, measured.** An earlier version of this section said `orbitd` peaked at
**2 GB** during startup and that a 1 GB VM would not start. That was wrong, and
the paragraph said why without drawing the conclusion: the deployment it came
from was crash-looping on a bug, so the figure was a restart-churn artifact
rather than a working control plane.

Measured directly, running the e2e binary with `/usr/bin/time -l`:

| What | Peak RSS |
|---|---|
| Two real nebula nodes + a control plane + Postgres pools | **108 MB** |
| Four networks joined, same process | **242 MB** |

And the marginal cost of a network is **0.36 MB of heap** (`TestMeshJoinCost`
prints it), so a hundred networks is tens of megabytes, not gigabytes.

So: **2 vCPU / 2 GB is comfortable** with Postgres sharing the box, and the
constraint is Postgres and headroom rather than nebula. Two vCPUs rather than
one because gvisor's packet processing, Postgres, and Go's collector contending
for a single core produce latency spikes that read as "push is down" when
nothing is wrong.

The number to actually watch is a control plane that is RESTARTING, which is
what produced the original 2 GB: repeated stack bring-up churns memory in a way
steady state does not. Alert on restarts, not on RSS.

The lighthouse's bandwidth is what to watch if memberships cannot punch and fall back
to relaying through it.

---

## 10. Upgrades

```bash
systemctl stop orbit-control
install -m755 orbitd /usr/local/bin/orbitd                   # NEW binary first
orbitd migrate --dsn "postgres://postgres@localhost/orbit"   # then migrate, with it
systemctl start orbit-control
```

**Install before you migrate.** The order used to be the other way round, and it
could not work: `orbitd migrate` runs whatever binary is on the path, and before
the install that is the *old* one, whose embedded migration set is the old set.
It applied nothing and printed "database is up to date"; the new binary then
served against an un-migrated database. `serve` now refuses to start in that
state rather than failing later on the first request that touches a new column —
see `docs/adr/0026-a-process-that-disagrees-with-the-schema-refuses-to-serve.md`.

`orbitd doctor` compares the applied migration set to the bundled one by name,
and says which side is ahead.

**Rehearse the restore quarterly**, alongside `make check-break-glass`:

```bash
ORBIT_DSN=postgres://postgres@localhost/orbit \
ORBIT_KEK_PASSPHRASE_FILE=./kek.pass make check-restore
```

It dumps read-only, restores into a scratch database it creates and drops, and
proves two things a written procedure cannot: that the schema this binary
expects is what comes back, and that the vault opens with the passphrase **and
Argon parameters you actually have**. A correct passphrase with a mismatched
`ORBIT_KEK_ARGON_MEMORY_MIB` fails exactly like a wrong one — that is why the
parameter is in the backup set above, and finding it out here is the point.

Migrations are forward-only by design: a down migration against a database
holding certificate state loses an audit trail rather than recovering anything.

Across a migration, replicas upgrade together: a replica still running the old
binary will refuse to start once the schema has moved. Agents are not affected —
the surfaces they talk to decode tolerantly, so a newer agent against an older
replica degrades rather than failing.

The control plane being down does not disturb the mesh. Agents log a failed poll
and keep their current configuration; existing tunnels are unaffected.

**One exception, and it is the reason not to co-locate the lighthouse with the
control plane on a network you cannot afford to lose.** Nebula holds learned
peer addresses in memory only, and the sole persisted underlay knowledge is
`static_host_map`, which lists lighthouses. So if the control plane and the
lighthouse are the same machine and it is down, established tunnels carry on —
but any host that RESTARTS in that window loses every learned remote and can
reach exactly one thing: the lighthouse that is down. Discovery does not resume
until it comes back. See `docs/adr/0032-discovery-survives-the-lighthouse.md`,
including why the obvious fix conflicts with config signing.

Nebula and the agent upgrade independently — that is the point of supervising
the stock binary rather than embedding it.

---

## 11. Second replica, when you want one

```bash
orbitd serve --mesh "$ORBIT_NETWORK=10.42.0.3" ...   # a different overlay address
```

Each replica registers the endpoint it serves and heartbeats; agents are handed
the live list at enrollment and renewal and rotate through it on failure. No
load balancer, no virtual address, no coordination. A replica that dies stops
being advertised when its heartbeat goes stale.

Both replicas can run the maintenance sweep — the jobs are idempotent and
uncoordinated.

The database is then the single point of failure, which is a normal problem with
normal answers.

**Each replica needs one secret: the KEK passphrase.**

```bash
ORBIT_KEK_PASSPHRASE_FILE=/run/credentials/orbit.service/kek
```

That is the whole of it. The CA keys and network identity keys live encrypted in
Postgres, so a replica reads them from the database it is already connected to —
there are no key files to copy and nothing to keep in step through a CA rotation.

A replica with the **wrong** passphrase fails at startup, not at signing time.
That is what the verifier in `orbit.kek` is for: without it a mistyped passphrase
would produce a control plane that starts cleanly, serves reads, and fails the
first time somebody adds a machine — days after the mistake, with nothing
connecting the two.

There is no other mode. `orbitd` says so at startup, once:

```
key vault open; private keys are stored encrypted in the database
```

and a control plane that cannot open the vault does not start. Both were true
choices once; keeping keys on disk was removed rather than deprecated, because
two custody schemes meant two things to back up, two ways to lose a network, and
a replica that could silently hold a stale key.
