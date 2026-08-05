# Changelog

Release notes live here rather than in the tag message. Git strips every line
beginning with `#` from a tag annotation unless `--cleanup=verbatim` is passed,
which silently removes markdown headings — and a release page is markdown. Notes
in a file are also reviewable in a pull request before they are published, which
a tag message is not.

The release workflow reads the section matching the tag and refuses to publish
without one.

## v0.4.0

The largest release so far: the data model was rebuilt, the mesh learned to
carry routes and exit nodes, and hosts resolve each other by name. Read the
breaking section before upgrading — an existing deployment cannot.

### Breaking

- **An existing network cannot be upgraded in place.** Orbit is now P-256 only,
  and a certificate's curve cannot be changed — nebula refuses a certificate
  whose curve differs from its signer's. Migration `0021` therefore refuses to
  run while any CURVE25519 network exists, and says so rather than corrupting
  one. The way forward is a new network and a re-join of every machine.

- **The data model is devices, networks and memberships.** A machine is a
  device with a key it generated; joining a network creates a membership. Names,
  addresses and roles hang off the membership, public addresses off the device.
  Several columns moved and `POST /v1/hosts` is gone; reservations replaced
  enrollment codes.

- **Hardware-backed keys were removed** — TPM, PKCS#11, Secure Enclave. They
  were measured rather than assumed, and `tpm2-pkcs11` cannot do the ECDH nebula
  needs, so the feature could not have worked for the thing it existed for.

- **Building Orbit now needs a submodule.** Nebula is built from
  `github.com/griffithind/nebula`, one commit ahead of upstream, pinned at
  `third_party/nebula`. Clone with `--recurse-submodules`, or run
  `git submodule update --init` in an existing checkout.

### Added

- **Routes.** A gateway forwards for a prefix that cannot run nebula — a Pi in
  front of a lab network, a jump box in front of a VPC. Two gateways offering
  the same prefix is high availability: nebula does weighted ECMP and fails over
  with no coordination. `orbit route add|ls|rm`.

  Authority is in the CERTIFICATE, not the database. A CA carries the prefixes
  its subordinates may claim, so a row an attacker can write grants nothing.
  Set it with `orbit ca create -unsafe-networks`; it is signed, so widening it
  later is a new CA and a rotation.

- **Exit nodes.** A route for `0.0.0.0/0`, taken deliberately by one machine:
  `orbit exit-node use|off|ls`. Rendered only for the membership that chose it,
  because a default route captures everything and nobody should get one by
  accident. Works on Linux and macOS.

- **Mesh DNS.** Every host resolves `<name>` and `<name>.<network>.internal`
  from a name table carried in its signed configuration — no lighthouse
  resolver, no round trip, and a name carries the same proof as a certificate
  path. The agent serves it locally and forwards the rest to the resolvers the
  machine had before.

- **A host-state layer.** Gateways get IP forwarding and NAT in an nftables
  table Orbit owns whole, and exit-node users get the policy routing that
  `listen.so_mark` exists to be matched by. Everything installed is removed by
  name, so uninstall works even if the rules were edited.

- **`orbit ca create`.** Minting a CA was previously possible only at bootstrap
  or through a hand-written HTTP request, which made adding a routed prefix —
  necessarily a new CA — impossible from the CLI.

- **`orbit status` shows what the machine was told to do**: routes, exit node,
  forwarding, NAT and resolver, read from the verified configuration so it
  answers "did the instruction arrive" separately from "did it take".

### Changed

- **Nebula loads only what the control plane signed.** The configuration is
  verified and handed to nebula in memory; a root user editing the file on disk
  changes nothing.

- **One UDP port per network.** Nebula's wire header carries no network
  identifier, so one socket serves exactly one network. Ports 4242-4257 are the
  documented range.

### Fixed

- **`make demo` could never have worked.** It authenticated as `orbit_app`, a
  role created `NOLOGIN` with a password nothing sets. It also exported
  `ORBIT_ENROLL_PEPPER`, retired long ago and read by nothing.

- **`orbit membership reserve` printed `-url -`** into a command meant to be
  pasted onto the machine being enrolled.

- **`orbit route add <reserved-name>` said "no host named X".** A reservation is
  not a membership until the machine joins, and the error now says so instead of
  sending an operator hunting for a typo.

- **The device-key error named a temporary file** that never existed, rather
  than the destination and the flag that moves it.

- **A control plane's own listen port was never recorded**, so nothing could
  render a config that dialled it.

- **Cross-clock liveness comparison.** Replica liveness compared a database
  `now()` against a Go `time.Now()`, which is skew-sensitive; six call sites and
  two error-swallowing paths were affected.

## v0.3.5

### Fixed

- **A wrong `--public-ip` on the first run was permanent.** The setup script
  reused `.env` wholesale, which is right for secrets and wrong for addresses: a
  first run with the usage text's example address wrote it in, and every later
  run reused it however many times the correct one was passed. The control plane
  then advertised a lighthouse nobody could reach — hosts enrolled fine, never
  completed a handshake, and every agent call timed out, which reads as a
  firewall problem. Addresses passed on the command line now win; secrets and
  the network id are still preserved.

  Correcting `.env` is only half of it, so the script now says the other half
  out loud: `-lighthouse` is a seed that applies once, at host-record creation,
  and after that the RECORD is what agents are told to dial. A changed address
  on an already-bootstrapped network needs
  `orbit host set <control-plane> -static-addrs <addr>`, and hosts that enrolled
  against the old one cannot receive that correction over an overlay they never
  joined — they have to re-enroll.

- **v0.3.4 was tagged on a red test.** The compose check added in v0.3.2 only
  understood *published* ports, so it flagged the admin CLI reaching a control
  plane that binds 8080 directly under host networking. The compose file was
  correct; the test was not. It now accounts for both ways a port reaches the
  host, and still fails on the original bug.

## v0.3.4

### Added

- **The admin CLI is reachable from compose.** Both binaries have always been in
  the image, and `orbit` was effectively unreachable: the obvious command,
  `docker compose run --rm orbitd orbit host code web-01`, swallows `orbit` as
  an argument to orbitd's entrypoint and prints orbitd's usage — which reads
  exactly like the binary not being in the image at all.

  There is now an `orbit` service sharing the same image, behind a `cli` profile
  so `docker compose up` does not try to run a command that exits as though it
  were a service. `docker compose run` enables a targeted service's profile by
  itself, so nothing needs a `--profile` flag:

      docker compose run --rm orbit host create -name web-01 -addr 10.42.0.7 -role default
      docker compose run --rm orbit host code web-01

  It runs on host networking and defaults `ORBIT_URL` to the control plane
  beside it, so the common case needs only a token.

## v0.3.3

### Fixed

- **The setup script could finish without handing over the admin token.** Two
  causes, either of which loses a secret `orbitd bootstrap` prints exactly once.

  `docker compose run` allocates a pseudo-TTY by default, and a TTY-attached
  container's output does not reliably reach a pipe — so the `| tee` that was
  meant to capture the token could capture nothing while the run reported
  success. Every `compose run` now passes `-T`.

  And the token was only ever shown where it was generated, then scrolled past
  behind compose's progress output, `docker compose up -d`, and the readiness
  loop; the closing summary named a file rather than printing it. Both tokens
  are now printed in the summary, and the script fails loudly if bootstrap
  yields no token rather than continuing to a cheerful "Done".

  A re-run over an already-bootstrapped network now says so and gives the
  command to mint a replacement, instead of implying a token was issued. It no
  longer mints a break-glass token on every re-run either — a trail of untracked
  `*` tokens is the opposite of what one is for.

## v0.3.2

Deployment fixes and a secrets-handling fix, all found by running v0.3.1 on a
real host. The compose file could not reach its own database, so this is the
first release where `docker compose up` actually works.

### Fixed

- **The setup script wrote secrets into an unignored working tree.**
  `scripts/setup-control-plane.sh` checks the repository out to `/opt/orbit` and
  writes `ca-pass` and `bootstrap-output.txt` beside the compose file — it has
  to, because compose resolves `file: ./ca-pass` relative to itself. Neither was
  gitignored, so a `git add -A` on a control plane would have committed the
  mesh's CA passphrase and both admin tokens. Both are ignored now, and a test
  derives the list from the script so a new secret cannot escape quietly.

- **The compose file could never reach its own database.** `orbitd` runs with
  `network_mode: host`, which takes it off the compose network — so it cannot
  resolve `postgres` by service name, and the only address the two share is the
  host's loopback. Postgres published nothing, so every `orbitd` command failed
  with `connection refused` against a database the same run had just reported
  healthy. Postgres now publishes `127.0.0.1:5432` — loopback only, because the
  bare `5432:5432` form binds every interface and Docker's port rules bypass
  firewalld.

### Added

- **`scripts/setup-control-plane.sh`** — one script that takes a fresh
  RHEL-family host to a running control plane: docker, firewall, secrets,
  migration, bootstrap, and start. Safe to re-run; secrets already in `.env` are
  reused rather than regenerated, because rotating the database password after
  the role exists locks the control plane out of its own data with nothing
  saying why.

  It sets `ca-pass` to uid 65532 rather than root. Compose bind-mounts a
  file-backed secret with the host's ownership and mode, so a passphrase left
  `0600 root` is unreadable by a container running as nonroot — and the failure
  is "permission denied" on a path that looks correct from a root shell.

  It also falls back to `docker compose build` when no image can be pulled,
  since the publish job is newer than the compose file that pulls from it.

## v0.3.1

Three defects in the deployment paths v0.3.0 introduced, all found by walking a
fresh host rather than by a test. Nothing else changed: same binaries, same
behaviour once running.

### Fixed

- **The container wrote the CA key into a throwaway container.** `orbitd
  bootstrap` defaults `-ca-key` to the relative path `ca.key`, and the image set
  no `WORKDIR`, so it resolved under `/home/nonroot` rather than in the
  `/var/lib/orbit` volume — meaning `docker compose run --rm orbitd bootstrap`
  wrote the mesh's root CA key into a container that was then deleted. Nothing
  fails at the time: the network works until the first certificate renewal, at
  which point nothing can issue one and every host has to re-enrol by hand. The
  image now works in the volume and owns it, so the default is correct.

- **Nothing published the container image.** `deploy/compose.yml` names
  `ghcr.io/griffithind/orbit`, and no workflow ever built or pushed it — so
  `docker compose up -d` failed on the pull and only `--build` worked. A compose
  file naming an image that does not exist is worse than one with no image at
  all, because the failure reads as a registry problem. The release workflow now
  builds and pushes linux/amd64 and linux/arm64 to GHCR, tagged with both
  spellings of the version (`0.3.1` and `v0.3.1`) plus `latest`.

- **`orbitd bootstrap -write-unit` produced a unit that could not start.** The
  generated unit runs as `User=orbit` and nothing created that account, so
  `systemctl enable --now orbit-control` failed with "Failed to determine user
  credentials" — a message naming neither the flag nor the missing user.
  Bootstrap now creates the system account, and prints the two `chown` commands
  the service needs to read its CA key and write its state directory. Found
  while writing a fresh-host runbook for v0.3.0; on v0.3.0 the workaround is one
  `useradd --system` before `systemctl enable`.

## v0.3.0

The deployment path was the worst part of Orbit, and this release rewrites it.
A managed host is now **one binary and one service** — no separate `nebula` to
install, no version to keep in step, no per-network unit. The control plane
generates its own unit and env file. There is an install script and a container
image.

It also adds the first diagnostics: `orbit status`, `orbit peers` and
`orbit why`.

**This release is breaking.** Read the upgrade notes at the bottom before
taking it — hosts running v0.2.x template units need a deliberate step.

### Nebula runs inside the agent

`orbit agent run` no longer supervises a stock `nebula` process; it links Nebula
as a library and runs one instance per joined network in-process. Nebula is
unforked, at the version pinned in `go.mod`.

What this buys: one artifact per host, no `PATH` to get wrong, no `-restart`
spec naming a systemd instance, and no skew between the configuration Orbit
renders and the binary that loads it. Validation before an apply is now exact
rather than a guess about a host binary's version.

What it costs, stated plainly: an agent crash now takes the data plane with it,
where two processes under two units failed independently. Nebula's security
fixes also ship on Orbit's release cadence rather than on yours.

What it does **not** cost is the property people usually mean by "the data plane
survives": a control plane outage still leaves every host holding its
certificate and its tunnels, because nothing in that path involves the control
plane.

`orbit agent run` no longer accepts `-nebula`, `-reload` or `-restart`.

### One process and one unit for every network

A host on three networks used to run three agents under three template unit
instances. It now runs one process under one unit, `orbit-agent.service`,
serving every network under `/var/lib/orbit`.

The templated unit was wrong in a way that looked right: a systemd template is
one shared file, so baking a directory into it meant installing a second network
silently repointed the first network's instance at the second's directory — two
healthy-looking units serving one network. The unit now names no network at all,
and adding one is enrolling into a new directory.

### The agent recovers on its own

- A network whose setup fails is retried with backoff instead of being skipped
  for the life of the process. A directory not yet mounted was previously
  permanent until somebody noticed.
- One broken network no longer stops the others.
- Nebula is healed on every tick: an instance that failed to start at boot, or
  died since, is restarted rather than waiting for a new generation that on a
  settled network never comes.
- A control plane outage leaves the agent polling and saying so, rather than
  exiting.

### Installing and running it

- **`orbit agent install`** enrolls a host, writes the service definition, and
  starts it — systemd on Linux, a LaunchDaemon on macOS. `orbit agent uninstall`
  reverses it.
- **`orbitd bootstrap -write-unit`** writes `/etc/orbit/orbit.env` (0600, holding
  the DSN and the enrollment pepper) and `/etc/systemd/system/orbit-control.service`
  from values bootstrap already knows. Assembling those by hand is where a real
  deployment produced an empty `ORBIT_NETWORK`, which systemd expanded to
  `-mesh =10.42.0.1` and reported as sixty lines of flag help.
- **`scripts/install.sh`** detects the platform, verifies against `SHA256SUMS`,
  and installs to `/usr/local/bin`. It enrolls nothing and starts nothing.
- **A container image and `deploy/compose.yml`** for the control plane, which
  removes `pg_hba`, firewalld, SELinux, unit files and the CA key's file mode
  from the problem.

### Diagnostics

When a tunnel did not come up, the answer used to be "read the logs" — a poor
answer on a host whose problem is that it cannot reach whatever would tell it.

- **`orbit status`** — every network this host joined, whether its data plane is
  up and why not, when it last reached the control plane, and which states it is
  stuck in. A network that failed to start appears carrying its error.
- **`orbit peers`** — the tunnels this host actually holds, from Nebula's own
  hostmap. The one thing the control plane cannot tell you.
- **`orbit why <peer>`** — identity, path and policy reported separately,
  because an expired certificate, a missing tunnel and a denying rule look
  identical from `ping`. A denial carries the near misses.
- **`orbit why <src> <dst>`** — against the control plane, both directions from
  the stored policy. Nebula enforces outbound on the sender and inbound on the
  receiver, so a flow passes only if both agree, and no single host can compute
  that.

These read a root-owned unix socket at `/var/lib/orbit/agent.sock`, read-only.
The rule matching is shared between the agent and the server so the two cannot
give contradictory answers, and it is cross-checked against two real Nebula
instances exchanging real TCP connections.

### Fixes

- **A host stayed `enrolled` forever.** The transition to `active` was written
  on one side and never triggered from the other, so a host that had enrolled,
  applied its configuration and reported back still showed as never having run.
- **The control plane did not report its own applied configuration.** It is a
  mesh member like any other host, and convergence counted it as permanently
  behind.
- **Unbounded shutdown waits** in `mesh.Node.Close` and `Store.Close`. A CI job
  found the first by hanging for ten minutes; the second turned a failed startup
  into what looked like a hang with no error anywhere.

### Documentation

- `docs/policy-model.md` — what Nebula's firewall actually enforces, with file
  references; what a certificate can carry; measured costs of address-compiled
  policy at fleet scale; and where the policy model can go.
- `docs/diagnostics.md` — the status socket and the commands on it.

### Upgrading from v0.2.x

**Managed hosts.** The per-network template units are gone. On each host:

```bash
systemctl disable --now 'orbit-agent@*'   # whatever instances exist
systemctl disable --now 'nebula@*'        # the supervised nebula, if any
sudo orbit agent install -url https://<control-plane> -code <new-code> -network <slug>
```

`agent install` writes the new single unit and starts it. Existing directories
under `/var/lib/orbit` are picked up as they are; a host already enrolled does
not need a new certificate, only the new unit — but minting a fresh enrollment
code is the simplest way to be sure the state file matches this version.

**The control plane.** `orbitd` is compatible in place. Re-running
`orbitd bootstrap -write-unit` on an existing network regenerates the unit and
env file without touching the database. Hand edits to either are lost, which is
the intended behaviour.

**Removed flags.** `orbit agent run -nebula`, `-reload` and `-restart` no longer
exist. Anything passing them fails at startup rather than silently ignoring them.

## v0.2.1

Fixes three bugs found by deploying v0.2.0 to a real host. All three are on the
control plane; managed hosts are unaffected.

### A control plane that is also a lighthouse could not start

`orbitd serve` renders its own nebula configuration, and `-nebula-port` never
reached it — the flag was applied to every managed host's config and to nothing
else. With `am_lighthouse` set from the host record and `listen.port` left at 0,
nebula refuses the config:

```
lighthouse.am_lighthouse enabled on node but no port number is set in config
```

That is the single-VM topology from the README, so it affected the most common
way to run this.

The port now reaches the control plane. Orbit also catches the contradiction
itself and says what caused it, rather than passing through a message that names
a nebula field: the port comes from a flag and the lighthouse role from a
database row, so nothing else compared the two.

### A failed startup looked like a hang, with no error anywhere

`Store.Close` calls `pgxpool.Close`, which waits for every pooled connection to
be released — and the epoch notifier holds one parked in `WaitForNotification`.
Nothing bounded that wait.

`Close` runs from a defer in `serve()`. So any startup failure after the store
opened returned an error, ran the defer, blocked forever, and never reached the
line in `main()` that prints the error. The process presented as hung with an
empty log, and systemd SIGKILLed it at `TimeoutStopSec` on every restart. The
bug above was invisible behind this one for an entire afternoon.

`Close` now gives the pool five seconds. Abandoning connections at exit costs
nothing — the process is going away and Postgres reaps the backends when the
sockets close. Never returning costs the error message.

### Deployment docs, corrected against a real host

The guide had never been followed on a fresh machine. Doing that turned up four
things it got wrong and one it stated backwards:

- **`sudo` drops `/usr/local/bin`.** RHEL-family `secure_path` excludes it, so
  every `sudo -u postgres orbitd …` in the guide failed with `command not found`.
- **`pg_hba.conf` uses `ident` for localhost TCP**, with no identd running, so
  the app role could not authenticate no matter what its password was.
- **Minimal images have no `firewall-cmd`**, and the guide had no firewall
  section at all. There is now a port table, including the one port that needs
  nothing opened because it lives on the userspace stack.
- **`bootstrap` cannot run as the service account** — the CA passphrase is
  `0400 root` in a `0700 root` directory. Run it as root and hand the key over
  afterwards.
- **Sizing said a 1 GB VM was comfortable.** It will not start. The numbers in
  that section are marginal costs per network and per watcher; nothing had ever
  measured the baseline, which is Nebula's userspace network stack, observed
  peaking at 2 GB. The section now says 2 vCPU / 4 GB and marks steady-state
  memory as uncharacterised rather than implying it is known.

### Guarding the shape of the bug rather than the instance

`mesh.Config` is built from a struct literal in one place and completed in
another, and a field missing from both is silently zero. `ListenPort` was
missing from both. A test now walks the struct with reflection and fails on any
field `cmd/orbitd` never sets — it found `Heartbeat` on its first run, where
zero happens to be a safe default, so that is now assigned explicitly rather
than left to look identical to the case that was a defect.

## v0.2.0

### Breaking: four binaries became two

`orbit-agent` and `orbit-migrate` no longer exist. Everything they did is a
subcommand.

| was | is |
|---|---|
| `orbit-agent enroll` | `orbit agent enroll` |
| `orbit-agent run` | `orbit agent run` |
| `orbit-agent recover` | `orbit agent recover` |
| `orbit-migrate -dsn …` | `orbitd migrate -dsn …` |

Installing three roles took four downloads, and two of the four were separate
for no reason that survived being looked at. `orbit-migrate` ran on the control
plane host against the same Postgres as `orbitd`; the privilege boundary that
matters is between two DSNs, and no executable boundary was enforcing it. The
agent and the admin CLI already shipped from one repo at one version.

**Upgrading.** Install `orbit` over `orbit-agent` on each managed host and point
the unit at it:

```bash
sudo install orbit /usr/local/bin/
sudo sed -i 's|/usr/local/bin/orbit-agent run|/usr/local/bin/orbit agent run|' \
    /etc/systemd/system/orbit-agent@.service
sudo systemctl daemon-reload && sudo systemctl restart orbit-agent@prod
```

The unit keeps its name. It names the service, not a binary, so a host that
already has it enabled stays enabled.

`orbit` and `orbitd` stay separate deliberately: `orbitd token create` mints a
`*` token straight from the database, bypassing every scope check — the
break-glass path — and that belongs on neither a laptop nor a managed host.
`orbitd` also links Nebula and gvisor, so merging would put a userspace TCP/IP
stack behind `go install ./cmd/orbit`.

### The agent validates with your Nebula, not one it carries

It used to link Nebula and run the config test in-process. That copy was
whatever Orbit was compiled against, while the host runs a stock binary of its
own version — so the check could pass a configuration the real binary rejects,
which is the exact failure validation exists to prevent, or refuse one it would
have accepted.

It now runs `nebula -test -config`. Use `-nebula` if the binary is not on PATH.

An agent that cannot find Nebula applies anyway and says so in the log. Being
unable to ask is not the same as being told no, and a host that refused every
generation because Nebula moved would never converge. A bad generation is still
reverted and quarantined after verification fails.

Side effect: a managed host went from 18.1 MB across two downloads to 10.0 MB
across one.

### Fixed

- `mesh.Node.Close` waited forever for Nebula's shutdown, so `orbitd` could fail
  to finish stopping and turn a restart into a SIGKILL. Every such wait is now
  bounded, with a test that fails if an unbounded one reappears.
- The third-party licence manifest was generated from whatever the local module
  cache happened to hold, so it described 58 of 147 modules and differed between
  machines. It is now computed from what actually links into the released
  binaries: 40 modules, all permissive.
- Every binary answers `version`. `orbit-agent` carried a hardcoded `0.1.0` that
  it reported to the control plane on enrollment, so `host.agent_version` was
  that string regardless of the build.

## v0.1.0

First release.

A self-hosted control plane for Nebula: enrollment, certificate issuance and
renewal, configuration distribution, firewall policy, revocation, an admin CLI,
and an operator console.

Measured rather than asserted: 5.24 seconds from a block API call to tunnel
teardown, of which 5 s is Nebula's own `connection_alive_interval`.

Early. The tests run against a real Postgres and real Nebula tunnels with no
mock layer, but the software has no production hours. Pilot it on infrastructure
you own. There is no rolling-upgrade procedure yet for schema changes across
replicas, and the restore path has not been exercised end to end.

Not implemented, and documented as such: SSO/OIDC, and two of the three designed
enrollment methods.
