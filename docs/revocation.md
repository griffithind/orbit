# Revocation Propagation

The central security claim of a mesh control plane is: *when I block a host, it
loses access.* This document specifies how fast that actually happens, why, and
how to measure it rather than assert it.

The incumbent's published behaviour is that a blocked host is distrusted "within
60 seconds", which follows directly from a once-per-minute poll. Beating that
measurably is the highest-value thing Orbit can do.

---

## 1. The mechanism Nebula gives us

There is no CRL and no OCSP. Revocation is a list of SHA-256 certificate
fingerprints delivered as ordinary configuration:

```yaml
pki:
  blocklist:
    - c99d4e650533b92061b09918e838a5a0a6aaee21eed1d12fd937682865936c72
  disconnect_invalid: true
```

`pki.go:loadCAPoolFromConfig` loads these into the CA pool on every config load,
including `SIGHUP` reloads.

Enforcement happens in two places, and it matters that it is two:

**At handshake.** `handshake_manager.go:certVerifier` calls
`CAPool.VerifyCertificate`, which checks the blocklist first
(`ca_pool.go:verify`). A blocked peer cannot establish a new tunnel.

**On live tunnels, on a timer.** `connection_manager.go:isInvalidCertificate`
runs for every tunnel every `timers.connection_alive_interval` (5 seconds by
default):

```go
err := caPool.VerifyCachedCertificate(now, remoteCert)
if err == nil {
    return false
} else if err == cert.ErrBlockListed {
    hostinfo.logger(cm.l).Info("Remote certificate is blocked, tearing down the tunnel", …)
    return true
```

This is the important one. Without it, blocking would only prevent *new*
tunnels while an established session continued indefinitely.

Note the asymmetry, which is easy to get wrong:

- **Blocklisted** → tear down, unconditionally.
- **Expired or otherwise invalid** → tear down **only if `pki.disconnect_invalid`
  is set**.

Orbit therefore always emits `disconnect_invalid: true`. Without it, the
expiry-based backstop in §4 silently does nothing, and a certificate that has
been expired for a month keeps its tunnel alive.

`internal/ca`'s `TestBlocklistRevocation` pins both the cold and cached
verification paths against the real `cert.CAPool`.

## 2. What this means

Two consequences follow, and they are the whole design problem:

1. **Revocation latency equals config-distribution latency.** There is no
   authoritative online check a peer can make. Every host enforces from its own
   local copy of the list.

2. **A partitioned host enforces nothing new.** A host that cannot reach Orbit
   keeps trusting the peers it already trusts, indefinitely. No amount of push
   infrastructure fixes this. Only certificate expiry does.

Revocation is therefore not one mechanism but four, layered so that each covers
the previous one's failure mode.

---

## 3. Four layers

```
     block issued
          │
          ├─ L1 push (long-poll/SSE)   ~100–500 ms   connected hosts
          ├─ L2 epoch piggyback        ≤ 1 RTT       hosts mid-request
          ├─ L3 poll fallback          ≤ interval    long-poll broken
          └─ L4 certificate expiry     ≤ cert TTL    partitioned hosts
```

### L1 — Push

`GET /agent/v1/watch` is held open. When any epoch advances, the response
returns immediately and the agent fetches the new state.

Fan-out across control-plane replicas uses Postgres `LISTEN`/`NOTIFY`: the
transaction that writes the blocklist entry also issues `NOTIFY orbit_epoch`,
so every replica wakes every watcher it holds. This avoids operating a message
broker on day one and is sufficient into the five figures of hosts. Revisit when
a single Postgres cannot hold the connection count.

Implementation notes that matter:

- Hold the connection with a **timeout shorter than the shortest idle timeout in
  the path** — 30 seconds is a safe default against most proxies and NATs.
- Send a heartbeat comment so intermediaries do not consider the stream idle.
- Cap concurrent watchers **per network** (`-max-watchers`); otherwise one large
  network exhausts the connection pool for every other one on the deployment.
  The cap fails soft: an agent that cannot get a slot falls back to polling.
- The watch endpoint is on the overlay, so a blocked host loses its tunnel and
  therefore its own watch connection. That is fine and expected: the
  *other* hosts are the ones that need the update.

### L2 — Epoch piggyback

Every agent API response carries the current epochs:

```json
{ "config_epoch": 42, "blocklist_epoch": 18 }
```

An agent that observes an epoch newer than its applied one fetches immediately.
This closes the window where a host is mid-request when a block lands, and it
converges hosts that missed a push without waiting for the poll interval.

Cheap to implement, and it turns every request into an opportunistic sync.

### L3 — Poll fallback

Long-poll fails behind some corporate proxies and some mobile stacks. Agents
fall back to polling `GET /agent/v1/state` on an interval with jitter.

Default 60 seconds, matching the incumbent — the point is that this is Orbit's
*worst* connected case, not its normal one.

Jitter is mandatory: a fleet enrolled simultaneously will otherwise poll
simultaneously forever.

### L4 — Certificate expiry

**The only layer that works under partition, and therefore the real backstop.**

With a 24-hour certificate lifetime, a host that never hears from Orbit again
still loses access within 24 hours. Nothing else provides that bound.

This is why `design.md` argues for short lifetimes even though they cost more
signing operations. The recommended defaults:

| Certificate TTL | Renew at | Worst-case revocation under partition |
|---|---|---|
| 24 h | 12 h | 24 h |
| 7 d | 3.5 d | 7 d |
| 30 d | 15 d | 30 d |

Pick per network. A laptop fleet should be at 24 hours. A set of servers in a
datacentre with reliable connectivity can tolerate 7 days. Anything beyond 30
days means revocation is effectively unbounded for a partitioned host, and the
UI should say so in those words.

Signing cost at 24-hour TTL is one operation per host per 12 hours: for 10,000
hosts, roughly 20,000 KMS operations per day. That is negligible in money and
well within default rate limits, but it is worth confirming against your
provider's per-second quota before choosing an aggressive TTL for a large fleet.

---

## 4. The blocking flow

```
POST /v1/hosts/:id/block
  │
  ├─ transaction:
  │    host.state ← suspended
  │    certificate.state ← revoked        (all active certs for the host)
  │    INSERT blocklist_entry(fingerprint, reason, epoch = nextval)
  │    network.blocklist_epoch ← that epoch
  │    INSERT audit_log
  │    NOTIFY orbit_epoch, '<network_id>'
  │
  ├─ every replica wakes its watchers for that network
  ├─ agents fetch, write config.d/50-orbit.yml, SIGHUP
  └─ nebula reloads the CA pool; within ≤5 s the connection manager
     tears down any tunnel to the blocked certificate
```

Note the final ~5 seconds is Nebula's own `connection_alive_interval` and is not
something Orbit controls. Include it in the reported number rather than quoting
only the distribution time; the honest metric is *block issued → tunnel torn
down*, not *block issued → config written*.

### 4.1 Blocklist growth

The blocklist is distributed to every host in every config, so it grows without
bound if entries are never removed.

**Prune entries once the revoked certificate has expired.** A certificate past
its `NotAfter` is already rejected by `ca_pool.go:verify` before the blocklist is
consulted; keeping the fingerprint adds bytes and no security.

With a 24-hour TTL this keeps the blocklist proportional to *recent* revocations
rather than to all history — typically a handful of entries. This is another
argument for short lifetimes: long-lived certificates mean a permanently growing
blocklist in every host's config.

Pruning runs in `internal/sched`, on a 15-minute sweep by default, with a grace
period past expiry (clock skew between the control plane and a host makes
"expired" fuzzy at the boundary, and a stale fingerprint costs bytes where a gap
costs trust). The same sweep removes spent enrollment credentials and reports
certificates whose agents have stopped renewing.

Every replica runs it. The jobs are idempotent and uncoordinated: two control
planes racing to delete the same already-expired rows is harmless, and leader
election would add a failure mode for nothing.

---

## 5. Measuring it

This is the part to build alongside the feature, not after. An unmeasured
propagation claim is a marketing claim.

### 5.1 Convergence endpoint

```http
GET /v1/networks/:id/convergence

{ "config_epoch": 42, "blocklist_epoch": 18,
  "hosts_total": 1204,
  "converged": 1198,
  "lagging": [ { "host_id": "host_…", "name": "edge-07",
                 "applied_blocklist_epoch": 17,
                 "last_seen_at": "2026-08-03T20:58:11Z" } ],
  "p50_ms": 180, "p95_ms": 420, "p99_ms": 1900 }
```

Convergence is computed from `host.applied_blocklist_epoch`, which agents report
via `POST /agent/v1/report` after a successful `SIGHUP`. **Report after applying,
not after fetching** — otherwise the metric measures download latency and hides
the failure mode where a config was fetched but never took effect.

This endpoint also gates CA rotation (`design.md` §6 step 3).

### 5.2 Measured results

`e2e/revocation_test.go` implements the harness below. Numbers from a local
run (2 observers, real nebula nodes, userspace device):

| Measurement | Result | Baseline |
|---|---|---|
| Push delivery (block to new generation at the agent) | **9 ms** | up to 60 s |
| Full propagation (block to tunnel torn down) | **5.24 s / 5.34 s** | 60 s |

The full number is dominated by nebula's own `timers.connection_alive_interval`
(5 s default): the connection manager re-checks certificates on that timer, so
roughly that much is unavoidable and no control plane can remove it.
Distribution itself is single-digit milliseconds.

Quote the full number, not the 9 ms. The honest metric is *block issued to
tunnel gone*, which is what an operator observes.

### 5.3 End-to-end benchmark harness

Nebula's own e2e suite (`e2e/router`) builds a full in-memory mesh with
simulated UDP and no real network, which makes a deterministic propagation test
practical:

```
1. stand up Orbit against an ephemeral Postgres
2. enrol N simulated hosts (N ∈ {10, 100, 1000})
3. establish a full mesh; assert connectivity
4. t₀: POST /v1/hosts/:victim/block
5. for each remaining host, record t₁ = the moment its tunnel to the victim
   is torn down (observable via Control.ListHostmapHosts)
6. report the distribution of t₁ − t₀
```

Assert against the incumbent baseline:

```
p50  < 1 s
p95  < 2 s
p99  < 5 s        (dominated by connection_alive_interval)
max  < 60 s       (poll fallback — must never be exceeded when connected)
```

Run it in CI at N=10 for every PR, and at N=1000 nightly. A regression here is a
security regression, not a performance one, and should fail the build.

### 5.4 Metrics to export

| Metric | Type | Why |
|---|---|---|
| `orbit_blocklist_epoch` | gauge, per network | current authoritative epoch |
| `orbit_hosts_converged` | gauge, per network | numerator for convergence |
| `orbit_convergence_lag_seconds` | histogram | the real SLO |
| `orbit_watch_connections` | gauge, per network | pool exhaustion early warning |
| `orbit_agent_poll_fallback_total` | counter | how many hosts lost long-poll |
| `orbit_cert_expiry_seconds` | histogram | catches stalled renewal before outage |

Alert on: any host lagging the current epoch by more than 5 minutes; any host
whose certificate has under 25% of its lifetime remaining (renewal is failing);
and any increase in `poll_fallback` (something in the network path changed).

---

## 6. Honest limitations

State these in the README. They are properties of Nebula's trust model, not
Orbit bugs, and users will find them regardless.

1. **A partitioned host cannot learn about revocation.** Only expiry bounds it.
   Certificate TTL *is* the revocation SLA for disconnected hosts, and the UI
   should present it that way when an operator picks a lifetime.

2. **Blocking is not instantaneous, and cannot be.** The floor is Nebula's
   `connection_alive_interval` (~5 s) plus distribution time.

3. **An attacker with code execution on a host keeps its private key.** Blocking
   revokes the certificate, not the key. Until the block converges, a stolen key
   remains usable against any peer that has not yet received the update.

4. **Orbit being unreachable does not revoke anything.** By design
   (`design.md` §9), the mesh keeps working when the control plane is down. The
   corollary is that an attacker who can partition Orbit from the fleet freezes
   revocation until certificates expire. This is the strongest argument for
   short TTLs, and it is worth saying out loud rather than burying.
