# Orbit

A self-hosted control plane for [Nebula](https://github.com/slackhq/nebula).

Nebula ships an excellent data plane and leaves the control plane to you. You
generate a CA, sign certificates by hand, copy configuration files around, and
track which host holds which key in a spreadsheet. When someone leaves, you find
out how much of that you actually wrote down.

Orbit is the other half: enrollment, certificate issuance and renewal,
configuration distribution, firewall policy, and revocation — with an API, a
CLI, and a web console. It runs Nebula unforked, as a library, so a managed host
is one binary and one service.

```bash
orbit membership reserve -name web-03 -role web        # → orb_1_…, single use

sudo orbit agent install                               # once per machine
sudo orbit agent join -url https://orbit.example.com \
    -network prod -code orb_1_…                        # once per network

orbit membership block web-03                          # off the mesh in ~5s
```

Or with nobody holding a code: the machine asks, and you say yes.

```bash
sudo orbit agent join -url https://orbit.example.com -network prod
orbit membership pending                          # what is waiting
orbit membership authorize <id>
```

---

## Install

From [releases](https://github.com/griffithind/orbit/releases). Every binary is
statically linked with no runtime dependencies.

```bash
curl -fsSL https://raw.githubusercontent.com/griffithind/orbit/main/scripts/install.sh | sh
```

It detects the platform, verifies against `SHA256SUMS`, and installs to
`/usr/local/bin`. Add `--control-plane` on the machine that will run `orbitd`,
and `--version X.Y.Z` to pin. It enrolls nothing and starts nothing: the steps
that change a machine are `orbit agent install` and `orbitd bootstrap`, and
those should be run deliberately rather than by a pipe.

| Binary | Platforms | Runs on |
|---|---|---|
| `orbit` | macOS, Linux · amd64, arm64 | your laptop, and every managed host as `orbit agent run` |
| `orbitd` | Linux · amd64, arm64 | the control plane, including `orbitd migrate` |

They stay separate for one reason: `orbitd token create` mints a `*` token
straight from the database, bypassing every scope check — it is the documented
break-glass path — and that does not belong on an operator laptop or on every
managed host. `orbitd` also links gvisor for its userspace network stack, which
no managed host needs.

Or from source — Go 1.26 and nothing else:

```bash
git clone https://github.com/griffithind/orbit && cd orbit && make build
```

---

## Quickstart

One VM, acting as its own lighthouse. This is a complete working mesh.

```bash
# Control plane. -write-unit leaves a systemd unit and an env file ready to go.
orbitd migrate -dsn "postgres://postgres@localhost/orbit" -app-password '<secret>'
orbitd bootstrap -dsn "$ORBIT_DSN" -network prod -cidr 10.42.0.0/16 \
    -write-unit -enroll-url https://orbit.example.com/enroll/v1/enroll \
    -overlay-addr 10.42.0.1 -lighthouse 203.0.113.10:4242
systemctl enable --now orbit-control

# Mint the break-glass token now, while everything works.
orbitd token create -name break-glass -scopes '*'
```

Or skip the host entirely — `deploy/compose.yml` runs the control plane and
Postgres as two containers, which removes `pg_hba`, firewalld, SELinux, unit
files, and the CA key's file mode from the problem.

Every machine after that: reserve a place from your laptop, then set the machine
up and join it.

```bash
orbit membership reserve -name web-01 -role web        # prints the code

# On the machine. install is once; join is once per network.
sudo orbit agent install
sudo orbit agent join -url https://orbit.example.com -network prod -code orb_1_…
```

`install` generates the machine's device identity and installs the service;
`join` adds one network, and the service picks it up without a restart. A
machine on three meshes is installed once and joined three times.

An address is allocated when the machine arrives; `-addr` on the reservation
pins one for the cases that need it. Drop the `-code` and the machine waits in
`orbit membership pending` for you to authorize it — the better shape for a
laptop handed to somebody, because no secret has to travel to it.

To see what a machine is doing — every network it joined, whether its data plane
is up, when it last reached the control plane — ask the agent on it:

```bash
sudo orbit status                      # every network this host joined
sudo orbit peers                       # the tunnels it actually holds
sudo orbit why 10.42.0.9 -port 5432    # and why it can or cannot reach one
```

From your laptop, the same question with two memberships is answered by the control
plane, in both directions at once:

```bash
orbit why web-01 db-01 -proto tcp -port 5432
```

`status` is the agent's own view; `peers` is nebula's hostmap, which is the one
thing the control plane cannot tell you; `why` separates an expired
certificate from a missing tunnel from a denying rule, which all look identical
from `ping`.

[docs/deployment.md](docs/deployment.md) has the whole of it — bring-up order,
sealing the CA key to a TPM, backups, alerts, and what survives an outage.

---

## What it does

**A machine has one identity, and it generates it itself.** At first start the
agent writes a device key to `/var/lib/orbit/device.key`. Nobody issues it,
nothing expires it, and it is the same key across every network that machine
joins and every control plane it talks to. Joining is a signature over that key,
so **no secret has to travel** — and a machine whose mesh certificate expired can
still reach the control plane, because reaching it uses something no clock can
invalidate. There is no recovery command, because there is nothing to recover
from: re-run `orbit agent join`.

**Enrollment without shared secrets.** The mesh keypair is generated on the
machine and only the public half is sent. A reservation code, when one is used at
all, is single-use with a 15-minute TTL. Nothing that could sign a certificate is
ever on the wire, and there is no code path that accepts a private key or a
column to store one in.

**Devices and memberships are different things.** A device is a machine; a
membership is that machine *in* a network. A laptop on three meshes is one device
with one disk-encryption state and three memberships. `orbit device ls` reports
posture — disk encryption, secure boot, firewall, TPM presence, read natively
with no second agent — and each signal is a tri-state where *unknown* never
collapses into *no*. Blocking a **device** refuses it everywhere on the control
plane, immediately and with no propagation; suspending a **membership** removes
it from one network.

**Renewal on a live tunnel.** Agents renew at 50% of certificate lifetime, with
per-host jitter derived from the host id — deterministic, so a fleet enrolled in
one batch does not renew in one batch. The swap is atomic and the previous
generation is kept for rollback.

**Revocation that is measured, not asserted.** Blocking a membership advances an epoch,
Postgres `NOTIFY` wakes every agent, and the fingerprint lands in every peer's
blocklist. End to end: **5.24 seconds** from the API call to tunnel teardown, of
which 5 s is Nebula's own `connection_alive_interval`. An e2e test fails if that
regresses.

**No credentials on managed machines.** The agent API is not on the public
listener — it lives on the overlay itself, and the control plane is a mesh member
like any other host. A host authenticates by the certificate it is already using
to send the packet, which Nebula's firewall verifies before any rule match.
There is no agent token to leak, rotate, or forget.

**Firewall policy as one document.** A network-wide policy of `allow` rules over
tags and roles compiles to per-host Nebula firewall rules. Because Nebula
validates a peer's claimed source address against its certificate, address-based
rules are exactly as strong as group-based ones — so the compiler emits
addresses, and a policy change takes effect without reissuing a certificate.

**Convergence you can see.** Every configuration generation is an epoch, and
memberships report the epoch they have *applied*, not the one they fetched. CA
rotation refuses to activate while any are behind, because activating past them cuts
them off.

**Failure containment.** An agent that applies a generation and cannot verify it
reverts to the previous one, reports that it did, and quarantines the failed
generation so it does not loop.

**A console, for when a terminal is the wrong place.** `orbitd -ui-addr 8081`
serves convergence, hosts, rotation gates, and the audit log. Server-rendered,
no build step, works with JavaScript disabled. Sign in with an ordinary API
token; sessions default to read-only and reference the token rather than copying
its scopes, so revoking the token closes every browser it opened.

---

## How it works

```
        ┌──────────────── control plane ─────────────────┐
        │  postgres                                      │
        │  orbitd  :8080/tcp  public — enrollment only   │
        │          :4242/udp  public — lighthouse        │
        │          10.42.0.1:8443  OVERLAY — agent API   │
        └────────────────────────────────────────────────┘
                            ▲
                  UDP 4242  │  hosts punch, then talk directly
                            │
     ┌──────────────────────┴──────────────────────┐
     │  managed host                               │
     │    orbit agent run                          │
     │      └─ nebula (unforked, in-process)       │
     │           one per joined network            │
     └─────────────────────────────────────────────┘
```

One binary and one service per host, serving every network it has joined —
including networks run by control planes that have never heard of each other.
Each keeps its own directory, certificate, and Nebula instance, because two
overlays cannot share a UDP port or a tun device.

The agent heals itself: a network whose directory is not ready is retried with
backoff, and a Nebula that failed to start or has died is restarted at the top
of every poll. The trade for running Nebula in-process is that an agent crash
now takes this host's tunnels with it until the service manager restarts it —
seconds, with `Restart=always`.

`orbitd` runs Nebula in-process on a userspace stack, so the control plane needs
no tun device and no root.

**The control plane is never in the data path and never a hard dependency.** If
Orbit is down, existing tunnels keep working and hosts keep their certificates
until expiry. That is a tested property, not an intention.

Which makes `cert_ttl` a recovery budget rather than just a rotation cadence: it
is simultaneously how long a partitioned host keeps trusting revoked peers *and*
how long you have to restore a broken control plane before hosts stop renewing.

| `cert_ttl` | Partitioned host loses access in | You have this long to restore |
|---|---|---|
| 24h | 24 hours | ~12 hours |
| 168h (7d) | 7 days | ~3.5 days |

For a single VM with no standby, 7 days is the right default. Twelve hours is
not enough time to notice an outage, get to a computer, and restore a database.

Size the control plane at **2 vCPU / 2 GB**, with Postgres sharing it. Nebula's
userspace stack is cheap — 108 MB peak for a process running two real nodes, and
0.36 MB of heap per additional network, both measured.
[docs/deployment.md](docs/deployment.md) §9 has the numbers and how they were
taken.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/model.md](docs/model.md) | **Start here.** The three nouns — device, network, membership — and which one owns which fact |
| [docs/deployment.md](docs/deployment.md) | Running it: bring-up order, CA key protection, break-glass, backups, alerts |
| [docs/design.md](docs/design.md) | Architecture, data model, API surfaces, CA custody and rotation, threat model |
| [docs/enrollment.md](docs/enrollment.md) | Joining, reservations, the wire protocol, renewal, attack analysis |
| [docs/design-device-identity.md](docs/design-device-identity.md) | Why a machine generates its own identity, and what that removes |
| [docs/policy-model.md](docs/policy-model.md) | How Nebula's firewall enforces, what a certificate can carry, and how policy compiles |
| [docs/revocation.md](docs/revocation.md) | How blocking propagates, and how to measure it |
| [docs/credential-model.md](docs/credential-model.md) | Device credential vs user credential. The user half is designed, not built |
| [docs/key-custody.md](docs/key-custody.md) | Where the CA and identity keys live, why a second replica does not work yet, and what to do about it |
| [docs/diagnostics.md](docs/diagnostics.md) | The agent status socket behind `orbit status`, `peers` and `why` |

Read `model.md` first — it is short, and every other document assumes its three
nouns. Then `design.md` §1, which documents six properties of Nebula's certificate
code that every other decision here follows from, with file references — most
importantly that **Nebula has no intermediate CAs**, which rules out the
offline-root pattern most PKI designs assume and makes the CA *be* the network.

Orbit is single-organization by design: one deployment manages its own networks.
A network is the unit of separation — its own CA, address space, and hosts — and
scaling past a few hundred means running more instances over disjoint subsets,
not partitioning inside one.

---

## Security

- The application connects as `orbit_app`, which holds no `CREATE` and cannot
  `UPDATE` or `DELETE` the audit log. A migration asserts this and fails if the
  grant ever appears.
- The CA signing key and each network's identity key are stored **encrypted in
  Postgres**, under a key derived from a passphrase the database never sees. A
  leaked `pg_dump`, a read replica, or an SQL-injection bug yields ciphertext.
  `systemd-creds --with-key=host+tpm2` seals that passphrase to the machine, so a
  stolen disk image is useless without that host. Keys on disk remain supported
  and get the same encryption and a file-mode check at load.
- Admin credentials are scoped bearer tokens. Revocation takes effect on the next
  request — authentication reads the database every time rather than caching
  identities.
- `/metrics` and the console bind loopback by default. Binding the console
  anywhere else without an `https://` external URL is refused at startup.

Please report vulnerabilities privately through GitHub Security Advisories
rather than a public issue.

---

## Limitations

Stated up front because they are properties of Nebula's trust model, not things
a control plane can engineer away:

- **An attacker with code execution in Orbit can mint certificates** within the
  compromised CA's scope until that CA is rotated. Nebula's flat trust model
  offers no way to make an online signing key less than a root. Scoped CAs,
  short lifetimes, and rehearsed rotation bound the damage; they do not prevent
  it. An offline root is not available as a mitigation — nebula has no
  intermediate CAs, so every CA is a root.
- **A partitioned host cannot learn about revocation.** Certificate lifetime is
  the revocation SLA for a disconnected host. Nothing else bounds it.
- **Blocking a membership is not instantaneous.** The floor is Nebula's
  `connection_alive_interval` (~5 s) plus distribution time. Blocking a *device*
  is immediate at the control plane and does not touch live tunnels — the two are
  different actions with different effects, and both are usually wanted.
- **Posture is asserted, not proven.** The agent reads disk encryption, secure
  boot, firewall state and TPM presence natively, and reports them over a
  connection authenticated by a key that also gates network access. That makes a
  report *attributable*; it does not make it true. Attestation is not built.
- **Changing a host's overlay address requires a restart**, not a reload — Nebula
  rejects a configuration reload whose certificate networks changed.

[docs/revocation.md](docs/revocation.md) §6 has the full discussion.

Designed but not implemented, and marked as such where they appear: SSO/OIDC
([design.md](docs/design.md) §4.4) and two of the three enrollment methods
([enrollment.md](docs/enrollment.md) §4–5).

---

## Maturity

**This is early software.** The tests are thorough and run against a real
Postgres and real Nebula tunnels, with no mock layer — the constraints this
design rests on live in Nebula's own code, and a mock would encode our belief
about them rather than the behaviour. CI fails if the database tests silently
skip.

What it does not have is production hours. Pilot it on infrastructure you
own rather than putting a fleet behind it. Two gaps are worth naming: there is
no rolling-upgrade procedure yet for schema changes across replicas, and
restoring from backup has not been exercised end to end.

---

## Prior art

- **Defined Networking's Managed Nebula** — the commercial product this is an
  open-source answer to. Its published behaviour (once-per-minute polling, block
  propagation within 60 seconds) is the baseline to beat.
- **Headscale** — not code-reusable, but the model for how an open-source
  control plane for a commercial mesh should be positioned.
- **smallstep/step-ca** — the source of the *provisioner* abstraction Orbit's
  enrollment methods borrow.
- **losfair/supernova** — an earlier, minimal Nebula control plane, useful as a
  scope reference.

---

## Development

```bash
make db-up          # development Postgres in Docker
make migrate
make check          # gofmt, vet, and the full suite
make release-ready  # everything the release workflow checks, before tagging
```

Release notes live in [CHANGELOG.md](CHANGELOG.md), not in the tag message: git
strips markdown headings from a tag annotation unless `--cleanup=verbatim` is
passed, and notes in a file are reviewable before they are published. The
release refuses to publish without a section for the version being tagged.

The store and e2e tests skip themselves when Postgres is unreachable, so
`go test ./...` stays useful without Docker. CI treats a skip as a failure.

---

## License

MIT — see [LICENSE](LICENSE). Every dependency is permissively licensed;
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) lists them.

Orbit is not affiliated with or endorsed by Slack Technologies. Nebula is MIT
licensed and used unmodified.
