# Deployment

Running Orbit on one ordinary VM. Unit files are in [`deploy/`](../deploy).

---

## 1. What the pieces need

| Piece | Needs |
|---|---|
| Postgres 15+ | local is fine; the control plane is the only client. 15 is the floor: the schema uses `ON DELETE SET NULL (column)`, which 14 cannot parse |
| `orbitd` | a public TLS endpoint for enrollment; an overlay address on each network it serves |
| A lighthouse | **a stable public IP and an open UDP port** — the one hard requirement, and `orbitd` can be it |
| Managed hosts | outbound UDP; no inbound, no public address |

The lighthouse is the only component that must be publicly reachable, because
it is how hosts find each other. It can be the same VM as everything else, which
is the cheapest working topology:

```
        ┌──────────────── one VM ────────────────┐
        │  postgres                              │
        │  orbitd    :8080/tcp  public (enroll)  │
        │            :4242/udp  public           │  ← its own lighthouse
        │            10.42.0.1:8443 overlay      │  ← agent API
        └────────────────────────────────────────┘
                            ▲
                  UDP 4242  │  hosts punch to here, then talk directly
```

`orbitd` runs nebula in-process on a userspace stack, so there is no tun device,
no root, and no separate nebula service on this machine. Managed hosts run the
stock nebula binary with an agent alongside it.

Put a reverse proxy in front of `:8080` for TLS. The agent API is **not** on
that listener — it lives only on the overlay — so nothing an unauthenticated
stranger can reach is exposed by it beyond enrollment.

---

## 2. Postgres

Two roles. The application must not be the one that owns the tables.

```sql
CREATE DATABASE orbit;
-- orbit_app is created by the migrations; give it a password and nothing else.
```

```bash
orbitd migrate -dsn "postgres://postgres@localhost/orbit"
psql -c "ALTER ROLE orbit_app LOGIN PASSWORD '…'"
```

`orbit_app` holds no `CREATE` and cannot `UPDATE` or `DELETE` the audit log. Run
the control plane as anything more privileged and a bug can alter the schema, a
compromise can erase its own tracks, and you will not find out until you need
the audit trail.

---

## 3. The CA key

Nebula has no intermediate CAs, so this key is a root of trust for the entire
mesh. It lives on this VM's disk; encrypt it.

```bash
head -c 32 /dev/urandom | base64 > /tmp/ca-pass
systemd-creds encrypt --name=ca-pass --with-key=host+tpm2 \
    /tmp/ca-pass /etc/orbit/ca-pass.cred
shred -u /tmp/ca-pass
```

`--with-key=host+tpm2` seals the passphrase to this machine's TPM: a stolen disk
image, a snapshot, or a detached volume is useless without this host. Most cheap
cloud VMs expose a vTPM; if yours does not, use `--with-key=host`, which still
keeps the secret out of `ps` and out of anything that logs the environment.

`orbitd bootstrap` encrypts the key automatically when
`ORBIT_CA_KEY_PASSPHRASE_FILE` is set, and **warns loudly when it is not** —
because an unencrypted key is a failure nothing else surfaces. Everything works.

For an existing plaintext key: `orbitd ca encrypt -key /var/lib/orbit/ca.key`.

Permissions are enforced, not suggested: a key with any group or other bit set
is refused at load.

**What this does not protect against:** code execution in `orbitd` yields the
decrypted key, because the process must hold it. Encryption covers the storage
layer — snapshots, backups, detached volumes — which is where the realistic
exposure is on a rented VM.

---

## 4. Bring-up

On a single VM the control plane is also the lighthouse, which removes the
awkward ordering that separating them creates.

```bash
# 1. Bootstrap. Prints the network id, an admin token (once), and the -mesh flag.
export ORBIT_CA_KEY_PASSPHRASE_FILE=/etc/orbit/ca-pass.plain
orbitd bootstrap -dsn "$ORBIT_DSN" \
    -network prod -cidr 10.42.0.0/16 \
    -ca-key /var/lib/orbit/ca.key \
    -cert-ttl 168h

# 2. Start it, as its own lighthouse. Nothing else to install, nothing to
#    enroll first.
orbitd serve -mesh "$ORBIT_NETWORK=10.42.0.1" \
    -lighthouse 203.0.113.10:4242

# 3. Mint the break-glass token now, while everything works. See section 5.
orbitd token create -name break-glass -scopes '*'

# 4. Every host from here is the same two commands.
orbit host create -name web-01 -addr 10.42.0.7 -role web && orbit host code web-01
orbit agent enroll -url https://orbit.example.com -code orb_1_…
```

`-lighthouse` is a **seed**, not a setting. It applies only when the control
plane's host record is first created; after that the record is the source of
truth, exactly as it is for every other host. That is why there is no
`-lighthouse=true`: a public address cannot be discovered from behind NAT, so
the operator states it once, and a lighthouse nobody can reach is worse than
none because every host keeps dialling it.

Roles thereafter change through the API and take effect without a restart:

```bash
orbit host set lh-01 -lighthouse -static-addrs 203.0.113.20:4242
```

`orbitd` logs the roles actually in force at startup, read from the record — and
warns if you passed a seed flag it ignored, rather than letting you believe it
took.

### Why lighthouse and not relay

`-relay` exists and is off by default, and that asymmetry is deliberate.

A **lighthouse** answers queries and coordinates hole punching. It is not in the
data path. Restarting the control plane briefly interrupts discovery for hosts
that do not already have a tunnel; established tunnels carry on. That is a
seconds-long blip, and worth it to run one thing instead of three.

A **relay** forwards other hosts' traffic — on the machine holding the mesh's
root CA key, spending its bandwidth and CPU, and a restart drops that traffic
rather than delaying a handshake. Run a separate relay when you need one.

### Moving the lighthouse off later

Handing the role to a dedicated host is a normal change, not a migration:

```bash
# 1. Enroll the new lighthouse with its public address.
# 2. Stand the control plane down. No restart, no flag.
curl -XPATCH .../v1/hosts/$CONTROL_PLANE_HOST_ID \
     -d '{"is_lighthouse":false,"static_addrs":[]}'
```

The config epoch advances, every agent stops listing the old address on its next
poll, and the control plane picks up the new lighthouse the same way — it
refreshes its own configuration on an epoch change like any other host.

### Separating them from the start

If you want the control plane out of the data path entirely, the ordering
matters: `orbitd` joins the overlay as a nebula host, but reaching the overlay
needs a lighthouse, which has to be enrolled by a running `orbitd`.

1. Start `orbitd` with **no** `-mesh` — enrollment and admin work, the agent API
   does not exist yet, and it says so at startup.
2. Create and enroll the lighthouse with its public address, start its nebula.
3. Restart `orbitd` with `-mesh`.

---

## 5. The break-glass token

`POST /v1/tokens` requires a token. So the one failure it cannot help with is
losing every admin credential — a token revoked in error, an expiry nobody
tracked, or an identity provider that gates the API and is itself unreachable
(design.md 4.5 has the in-mesh Keycloak version of that). There is no API path
back in, by construction.

`orbitd token create` is the way back. It authenticates with the database, not
with the API:

```bash
orbitd token create -name break-glass -scopes '*' | \
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

**4. Test it on a schedule** — quarterly is enough. An untested recovery path is
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
FAIL  token no longer holds '*' (has: hosts:read)
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
orbitd token create -name break-glass-2 -scopes '*'   # new one first
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
orbit audit -action token.created
```

```
system  iraklisk  token.created  {"via":"orbitd token create","name":"break-glass"}
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
- the **time you have to fix a broken control plane** before hosts start
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

Note that this is a bound on *silent* failure only: a host that can still reach
the control plane gets revocations in about five seconds.

---

## 7. Backups

Three things, with very different consequences.

| Lose | Consequence | Recovery |
|---|---|---|
| **Database** | Host records, certificates, blocklist, audit trail | Restore. Without a backup: every host re-enrols by hand |
| **CA key** | Cannot issue or renew anything | Recoverable *if you notice in time* — see below |
| **Enrollment pepper** | Outstanding enrollment codes stop working | Nothing to do; they expire in 15 minutes anyway |

```bash
# Nightly is enough; certificates are re-issuable, the host inventory is not.
pg_dump orbit | age -r "$BACKUP_KEY" > orbit-$(date +%F).sql.age
# The CA key is already encrypted at rest. Copy it as-is, and store the
# passphrase somewhere the TPM-sealed copy is not — a sealed credential does
# not survive the machine it is sealed to.
cp /var/lib/orbit/ca.key ca.key.backup
```

**Losing the CA key is survivable, and the window is one certificate lifetime.**
Nothing about a lost key stops the existing mesh working. Create a new CA with a
new key, publish it (creating a CA pushes it to every trust bundle), let hosts
converge, then activate it — hosts renew onto it. That is the ordinary rotation
in [design.md §6](design.md#6-ca-rotation), and it works as long as hosts are
still up and still renewing, which is true until their current certificates
expire. Miss that window and every host must re-enrol.

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
overlay address (`-metrics-addr 10.42.0.1:9464`) to scrape it from another
machine, or `-metrics-addr ""` to turn it off.

The fleet gauges are read from Postgres **at scrape time**, not held in memory.
That is why two replicas report identical numbers and why a restart does not
reset convergence to zero and page you during every deploy.

| Metric | Alert when |
|---|---|
| `orbit_convergence_lag_seconds` | `> 300` — a host has been behind for 5 minutes |
| `orbit_certificates_expiring_soon` | `> 0` — renewal is failing for someone, well before they drop off |
| `orbit_epoch_listener_up` | `== 0` — push is down, every agent has fallen back to polling |
| `orbit_db_scrape_up` | `== 0` — serving, but cannot reach Postgres |
| `orbit_agent_poll_fallback_total` | any increase — watcher cap reached or the network path changed |
| `orbit_certificates_issued_total{reason="recover"}` | any increase — recovery is not routine; renewal is broken for that host |

Also exported: `orbit_config_epoch`, `orbit_blocklist_epoch`,
`orbit_hosts_total`, `orbit_hosts_config_converged`,
`orbit_hosts_blocklist_converged`, `orbit_blocklist_entries`,
`orbit_certificate_min_remaining_seconds`, `orbit_watch_connections`,
`orbit_enrollments_total{result}`, and the standard Go runtime collectors.

Everything is labelled by network only. Per-host labels would grow a time series
per machine and make Prometheus the most expensive part of a deployment that
otherwise runs on one small VM; per-host detail is in the convergence endpoint,
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

rotating a CA past these hosts will cut them off
```

### The web console

`orbitd -ui-addr 8081` serves an operator console. Off unless you ask for it, and
a bare port binds **loopback** — the listener carries every host name, every
overlay address, and a control that cuts a host off the mesh, on the machine
holding the mesh's root CA key.

```bash
ssh -N -L 8081:127.0.0.1:8081 orbit-control    # then http://127.0.0.1:8081/ui/
```

Binding it anywhere else without an `https://` `-ui-url` is **refused at
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
| `certificate is overdue for renewal` | a host has stopped rotating; it will drop off at expiry |
| `host recovered after certificate expiry` | renewal is broken for that host — recovery is not routine |
| `CA activated before convergence` | someone forced a rotation; hosts were cut off |
| `active certificate authority has expired` | the network's signer outlived itself; enrollment and renewal fail until a replacement CA is created and activated. The sweep deliberately does not retire it — retiring is a rotation step and cannot be undone through the API |
| `host reverted a pushed generation` | that host applied a config and then could not reach the control plane, so its guard rolled back. More than one means the push severed the fleet |
| `reverted to the previous generation` | a pushed config broke a host and it rolled back |
| `CA key written UNENCRYPTED` | fix before anything else |
| `epoch listener dropped` | push is down; agents fell back to polling |
| `agent API disabled` / `no -mesh configured` | hosts cannot poll, renew, or receive revocations |

The maintenance sweep logs a summary every 15 minutes when it does anything.

---

## 9. Sizing

Measured, in `e2e/scale_test.go`:

- Rows are free. Hosts, certificates, and audit entries cost Postgres and
  nothing else.
- Each network `orbitd` **joins** costs ~28 goroutines and ~0.33 MB idle — it is
  a full nebula instance. Low hundreds of joined networks per process.
- Long-poll watchers cost one connection and one goroutine per agent, capped by
  `-max-watchers` (5000/network default). Over the cap, agents fall back to
  polling rather than being refused.

A 1 vCPU / 1 GB VM comfortably runs the control plane, Postgres, and a
lighthouse for a few hundred hosts. The lighthouse's bandwidth is what to watch
if hosts cannot punch and fall back to relaying through it.

---

## 10. Upgrades

```bash
systemctl stop orbit-control
orbitd migrate -dsn "postgres://postgres@localhost/orbit"   # forward-only
install -m755 orbitd /usr/local/bin/orbitd
systemctl start orbit-control
```

Migrations are forward-only by design: a down migration against a database
holding certificate state loses an audit trail rather than recovering anything.

The control plane being down does not disturb the mesh. Agents log a failed poll
and keep their current configuration; existing tunnels are unaffected.

Nebula and the agent upgrade independently — that is the point of supervising
the stock binary rather than embedding it.

---

## 11. Second replica, when you want one

```bash
orbitd serve -mesh "$ORBIT_NETWORK=10.42.0.3" ...   # a different overlay address
```

Each replica registers the endpoint it serves and heartbeats; agents are handed
the live list at enrollment and renewal and rotate through it on failure. No
load balancer, no virtual address, no coordination. A replica that dies stops
being advertised when its heartbeat goes stale.

Both replicas can run the maintenance sweep — the jobs are idempotent and
uncoordinated.

The database is then the single point of failure, which is a normal problem with
normal answers.
