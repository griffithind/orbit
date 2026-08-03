# Changelog

Release notes live here rather than in the tag message. Git strips every line
beginning with `#` from a tag annotation unless `--cleanup=verbatim` is passed,
which silently removes markdown headings — and a release page is markdown. Notes
in a file are also reviewable in a pull request before they are published, which
a tag message is not.

The release workflow reads the section matching the tag and refuses to publish
without one.

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
