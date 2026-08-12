# Changelog

Release notes live here rather than in the tag message. Git strips every line
beginning with `#` from a tag annotation unless `--cleanup=verbatim` is passed,
which silently removes markdown headings — and a release page is markdown. Notes
in a file are also reviewable in a pull request before they are published, which
a tag message is not.

The release workflow reads the section matching the tag and refuses to publish
without one.

## Unreleased

**This release requires a fresh database, and changes the CLI, the admin API and
where the KEK passphrase is stored.** Nothing is deployed yet and there is no
upgrade path from v0.4.5 — see ADR-0005.

Two headlines. The agent daemon had been running a code path that skipped most
of what the agent does. And four security defects are fixed, of which two are
serious: any enrolled host could obtain a certificate for any other member of
its network, and any token that could manage tokens could grant itself
everything.

### Security

- **A vanished exit node silently reverted a host to its own internet.**
  `NetworkRoutes` filters gateways to enrolled-or-active, so suspending or
  blocking an exit gateway removed the route from every consumer's render — and
  rendering nothing meant the consumer fell back to its physical default. A
  machine that chose an exit node for privacy then sent its traffic in the clear,
  with no signal anywhere. The control plane now renders
  `orbit.exit_node_unreachable`, and the agent installs unreachable routes for
  the two default halves so that traffic fails instead of leaking. Losing
  internet access is a support call; losing it silently to the clear is an
  incident nobody opens. See ADR-0016.

- **Reverse lookups of overlay addresses went to the public internet.**
  `dig -x 10.42.0.9` was forwarded, telling an ISP or corporate resolver an
  address from the operator's own mesh — and there was nothing out there to
  find, since nobody else is authoritative for them. PTR is now answered
  locally from the same table the forward direction uses.

- **No DNS rebinding protection.** Upstream answers were relayed verbatim, so a
  public name could resolve into the overlay and be treated by a browser as a
  local-network host. An answer pointing into the network's own CIDRs is now
  refused rather than stripped: an answer with the offending records removed
  says the name exists and is somewhere else, which is a lie of a different
  shape. See ADR-0029.

- **An enrollment code alone could mint a certificate.** `orbit agent enroll`
  re-issues to a membership that already exists, and the request carried no
  signature — so whoever held the code, from a CI log or a scrollback buffer,
  got a certificate issued over a public key **they** chose, for a machine
  somebody else owns. The `claim` path has required a device signature all
  along. Enrollment now does too, checked against the key the membership already
  names, and checked *before* the code is spent so a bad signature cannot burn a
  live code. See ADR-0024.
  A code also locks after five rejected attempts, counted in Postgres against
  the code itself — the enrollment limiter is keyed by source address and lives
  in one process, so it neither survives a rotating source nor counts across
  replicas. And `membership reserve` no longer takes an unbounded lifetime from
  the request body: reservations auto-authorise on redemption, so an arbitrary
  TTL is an unattended admission credential with no expiry. Capped at 24 hours.

- **`orbit device block` did not stop the device getting certificates.**
  `ResolveAgentHost` resolved an agent by overlay address through `membership`
  and `membership_address` and never touched `orbit.device`, so a blocked device
  kept renewing every twelve hours, indefinitely. `docs/credential-model.md`
  promised that block "refuses a device everywhere on the control plane
  immediately", and that promise is the whole argument for holding device keys
  in plaintext on disk. Blocking a device now also blocks every membership it
  holds, which revokes the certificates and puts the fingerprints on the
  blocklist. See ADR-0023.

- **A quarantined host refused revocations for up to thirty minutes.** The
  revert guard keyed on the config epoch alone, and blocking a host advances the
  BLOCKLIST epoch and nothing else — so a revocation arrived carrying the same
  config epoch the guard was refusing and was refused with it. The revert then
  rolled the installed blocklist back to its pre-revocation value. A blocklist
  can only withdraw trust in a peer, never in the host's own certificate, so it
  can never be the generation that broke us; the guard now keys on both epochs.
  See ADR-0025.

- **A gateway's firewall silently narrowed, minutes after `orbit route add`.**
  Nebula treats an omitted `local_cidr` as "any address" only while the host's
  certificate carries no unsafe networks; once it does, the rule narrows to the
  host's own overlay addresses and everything the host forwards is dropped.
  Orbit puts a gateway's routes into that certificate, so forwarding worked and
  then stopped when the next certificate arrived — and `orbit why` reported
  ALLOW for the rules nebula was dropping. See ADR-0021.

- **Choosing an exit node leaked the other address family.** `exit_route_id` is
  a single row, and a gateway offering both `0.0.0.0/0` and `::/0` produces two,
  so a dual-stack host could tunnel IPv4 and send IPv6 in the clear. Refused
  now, naming the missing prefix. See ADR-0016.

- **Split DNS never happened.** The Linux applier took a `global` flag, named it
  `_`, and made Orbit the resolver of last resort unconditionally — so every
  host sent its entire query stream, corporate and personal included, to the
  mesh resolver. The flag is honoured. See ADR-0013.

- **A mesh name could shadow a public one.** Membership names were free text up
  to 253 bytes and are published into the resolver answered authoritatively, so
  a membership called `login.microsoftonline.com` shadowed the real one for the
  whole network. Names are now one DNS label. See ADR-0029.

- **Host state survived a kill.** Everything Orbit writes outside its own
  directory — the nftables table, the policy route, the firewalld zone
  assignment, the macOS resolver settings — outlived the process, so a host that
  was SIGKILLed kept forwarding and NAT-ing for a mesh it may no longer be on.
  The agent now sweeps all of it by name at start, before anything is applied.
  See ADR-0015.

- **Any enrolled host could take over any other host in its network.** The agent
  API authenticates by source address alone, and resolved that address through a
  helper that honours `X-Forwarded-For` when `-trust-forwarded-for` is set. That
  flag is for the public listener behind a reverse proxy — an ordinary
  deployment — and `orbitd` builds the overlay listener's config by copying the
  public one, so enabling it for the proxy enabled it for a socket that has no
  proxy in front of it and never will.

  `POST /agent/v1/renew` takes its identity from that address and issues a
  certificate for a public key the request supplies, with no proof of
  possession. One header was therefore a complete identity takeover, laterally,
  from inside the mesh the product exists to segment. Identity now reads the
  peer address and nothing else; three tests hold it there, one of them static
  because the check cannot be exercised without a database.

- **A token could mint a token stronger than itself.** `POST /v1/tokens` wrote
  the requested scopes to the database unread — no check that the caller held
  what it was granting, and no check that the scope exists. `tokens:write` was
  therefore the only scope that mattered: a CI credential allowed to rotate its
  own key could ask for `*` and get it. A caller may now grant only what it
  holds, and an unknown scope is refused by name. Bootstrap is unaffected, since
  `orbitd` writes the first token through the database directly.

- **One noisy client could rate-limit enrolment for everyone.** The limiter
  checked the global ceiling before the per-key one, and `rate.Limiter.Allow`
  spends a token whether or not the request is served — so a source already over
  its own limit kept draining the global budget with requests that were about to
  be refused anyway. 600 refusals a minute from one address locked out every
  other client. The rejections were the attack.

- **A certificate authority could be created with no certificate.** The errors
  from marshalling and fingerprinting a new CA were discarded, and both columns
  are `NOT NULL` without being non-empty — so the failure mode was not an error
  but a CA row with an empty certificate, returned as 201 and published into
  every host's trust bundle as a blank entry. Checked now, and the schema
  refuses it.

- **The KEK passphrase is no longer written beside the database it protects.**
  `scripts/setup-control-plane.sh` put it in `.env`, next to the database
  passwords, in the directory that also carries the database volume — so the
  default state on disk was a backup and the key that opens it, together.
  Anyone who archived that directory took both. It is written to `./kek.pass`
  now, and compose reads it through `ORBIT_KEK_PASSPHRASE_FILE`, which also
  keeps it out of `docker inspect`. **Existing deployments must move the value
  out of `.env` into `kek.pass` before upgrading.**

### Fixed

- **`make test-netns` ran zero tests.** It pointed at `./internal/agent/` while
  the tests it names live in `./internal/agent/hostcfg/` — the agent split moved
  them and the target did not follow. `go test` with a `-run` matching nothing
  prints "no tests to run", exits 0 and reports `ok`, so the gate had been green
  while testing nothing. It now runs the whole package with no `-run` filter,
  and fails if anything skips or if nothing ran.

- **The exit-node escape hatch could not resolve its own way out.** It marks
  connections to the enrolled public endpoint so the recovery path stays outside
  the tunnel — but `Dialer.Control` runs *after* Go has resolved the address,
  and the resolver's own packets carry no mark. On a host whose exit route was
  the broken thing, the lookup went into the tunnel, failed, and the hatch never
  fired: dead in exactly the situation it exists for. The agent now learns the
  endpoint's addresses while the overlay is healthy and matches against those.

  That also removes a `net.LookupHost` from every dial. The old comparison never
  matched on its first term — `Control` sees a resolved IP while the enrolled
  endpoint is a name — so every connection the transport made, including every
  steady-state overlay poll, went through a blocking lookup inside the connect
  path. See ADR-0016.

- **The daemon ran a loop that skipped revocation, self-heal and host
  configuration.** Two loops existed. The daemon drove `Loop.Tick` on a ticker;
  `Loop.Run` was the one with the push channel, the config-integrity self-heal
  and host reconciliation. Both were built, both were tested, and the daemon
  called the wrong one — so roughly 1,200 lines of nftables programming, policy
  routing, the DNS resolver and the exit-node escape hatch never executed in
  production.

  Revocation was bounded by a one-minute poll instead of the notifier. The e2e
  test measuring propagation called `Loop.Run` directly, so the suite was
  timing a path the daemon does not take: it reported the README's ~5 seconds
  while operators got roughly 65.

- **`orbit why` could say traffic was permitted when it was not.** The CA term
  in the firewall matcher was written as a negative guard and failed OPEN. For a
  `ca_sha`-only rule against a query carrying no CA name, the final comparison
  was `"" != ""` — false — so the guard never fired and a rule pinned to a CA
  the peer was not issued by reported the traffic as allowed. It is now the
  positive disjunction nebula's grammar specifies, `(ca_sha OR ca_name)`, and
  answers "needs the peer's issuing CA" rather than guessing.

- **Enrolment could deadlock the connection pool.** `Store.Open` parsed the DSN
  and configured nothing, leaving `MaxConns` at pgxpool's `max(4, NumCPU)` with
  no statement, lock, or idle-in-transaction timeout. Enrol opens a transaction
  whose certificate path reads through `Store.Read`, which acquired a SECOND
  connection while holding the first — so with `MaxConns` enrolments in flight,
  none could finish. A cache hid it until the cache was cold, which is a restart
  or a CA rotation. Nested reads now join the open transaction, and the pool has
  sizes and timeouts.

- **Unblocking a host could block CA rotation for that network permanently.**
  `UnblockHost` set every host to `active`, including hosts that had never
  enrolled and hosts that hold no address. Convergence counts
  `state IN ('enrolled','active')`, so such a host sat in the denominator and
  could never report an epoch — and convergence is the gate on CA rotation. The
  state is now derived from what the host actually has: a live certificate, an
  allocated address, or neither.

- **`orbit agent run -h` started the agent instead of printing help.** Five
  commands parsed with `_ = fs.Parse(args)`, discarding the error, so `-h`
  returned `flag.ErrHelp` into a blank identifier and execution carried on into
  the command body. An unknown flag was ignored the same way.

- **Shell completion offered flags that do not exist, and hid ones that do.**
  It listed the common flags in a literal of its own: that literal said
  `--yes` where the code registers `-y`, so pressing tab produced a flag the
  command rejects. It also offered `--token-file` for `orbit status`, which
  talks to the local agent socket and has never taken one, while offering none
  of `orbit membership ls`'s own seven filters. Every command now declares its
  flags to the command tree, and completion asks the tree.

- **Fourteen messages told operators to run a command that does not exist.**
  `join` was promoted from `orbit agent join` to `orbit join` and the strings
  handing out the old spelling were not updated — the error from `agent run`
  with no networks, the install hint, the reserve handout in both the CLI and
  the web UI, and orbitd's bootstrap output.

- **Adding or removing a network CIDR could lose a concurrent change**, and
  three other places where the store could quietly answer with stale or wrong
  state.

### Changed

- **`orbit route add <gw> 0.0.0.0/0` now enables NAT by default.** Without it
  the internet has no route back to an overlay address, so an exit node created
  without `-masquerade` could not work. Pass `-masquerade=false` to opt out.

- **Membership names must be a single DNS label** — 63 characters, letters
  digits and hyphens. Existing names containing a dot will be refused on the
  next join.

- **`orbitd serve` refuses to start when its embedded migration set disagrees
  with the database**, by name rather than by count. It used to start cleanly
  and fail later on the first request touching a new column. `orbitd doctor`
  reports which side is ahead, and recognises a database predating the migration
  collapse instead of claiming a newer binary migrated it.

- **Upgrade order changed: install the new binary first, then migrate with it.**
  `orbitd migrate` runs whatever is on the path, so migrating before installing
  ran the old binary's old migration set and printed "database is up to date".

- **The agent surface decodes tolerantly; the admin API stays strict.** A newer
  agent talking to an older replica took a hard 400 on any added field and could
  neither retry nor fail over, which is the direction a rolling upgrade takes.

- **Only one network per host configures host state.** The nftables table, route
  table and ip rule are named once per machine, so two networks that both wanted
  them destroyed and rebuilt each other's rules once per reconcile, silently.
  The lowest slug wins and the others say so.

- **A relay now needs a public address**, the precondition a lighthouse has
  always had.

- **`orbitd serve` gains `-name`**, for restoring onto a host with a different
  hostname.

- **The KEK can be rotated.** `orbitd kek rotate` re-seals every stored secret
  under a new passphrase and replaces the salt and verifier, in one transaction.
  The documentation had claimed this worked since it was written; the primitives
  existed and nothing called them. One transaction is the design rather than
  tidiness — a partial rotation leaves secrets under two keys and a control
  plane that will not start, with every CA key present and unreadable.

  Rotation is offline and needs the database, because it needs the current
  passphrase to read what it rewrites. Every replica must be given the new
  passphrase before it next starts.

- **The browser console works behind a load balancer.** Its CSRF form token was
  an HMAC under a key generated per process, so a form rendered by one replica
  was refused by another — every time, not merely after a restart. The key is
  derived from the KEK now, so every replica computes the same bytes and none
  are stored. `docs/design.md` said to run N replicas behind a load balancer and
  the console was the one surface that could not.

- **Two control planes given the same overlay address are refused.** The check
  that was supposed to catch this compared names, and the default name was
  derived from the very address it refereed — so both replicas computed the same
  name, the refusal never fired, and the second silently adopted the first's
  membership. Both then issued certificates for one overlay IP. The name is the
  machine's hostname now.

- **`orbit policy check -host` is `-membership`**, and the endpoint behind it
  takes `?membership=` rather than `?host=`. It was the last flag in the tree
  still using the old noun.

- **The schema is one migration.** Twenty-six sequential migrations were
  collapsed into `0001_initial.sql`. Equivalence was proved through the
  catalogs rather than by reading a dump — 173 columns, 100 constraints, 58
  indexes, 184 grants and 3 triggers identical — but an existing database has
  the old migration names recorded and will not accept this. Start a new one.

  Sixteen constraints still named `host_*` after the host-to-membership rename
  are now named for the table they are on. Those names reach operators:
  the store puts the constraint name into the error it returns.

- **The CLI is noun-verb, in a table.** `orbit join` and `orbit leave` are
  promoted to the top level; `host` is `membership` everywhere, including
  `orbit policy check -membership` (was `-host`) and the admin API's
  `?membership=` (was `?host=`). `--flag` is the documented spelling. Usage,
  aliases and hidden commands come from one table rather than from each
  command's own printing.

- **`internal/agent` is seven packages.** It was 9,941 lines in one; the core
  is now 2,561, beside `generation`, `hostcfg`, `dataplane`, `status`,
  `posture` and `paths`. None of the six imports the agent.

- **One package names the files nebula reads.** The control plane rendered
  `pki.ca`, `pki.cert` and `pki.key` into the config it signs, and the agent
  decided independently where to write them — two sets of string literals that
  agreed with nothing enforcing it. A rename on either side would have signed
  every host a config naming a file the agent does not write.

### Added

- **Clock skew is measured, reported and alertable.** The agent compares its
  clock to the control plane's on every poll — the `Date` header was already
  there — warns on a transition, shows it in `orbit status`, and reports it so
  `orbit_hosts_clock_skewed` can answer "which machines have bad clocks"
  fleet-wide. Nebula validates certificate windows against wall time with no
  leeway, so a machine a minute slow rejects its own brand-new certificate and
  the failure reads as a bad configuration. Counted rather than labelled per
  host, per ADR-0008's rule on cardinality. See ADR-0031.

- **Four metrics that close failures nothing measured**:
  `orbit_hosts_data_plane_down` (a host whose agent is healthy and whose nebula
  is not — it polls, reports an applied epoch, and every other gauge counted it
  as converged), `orbit_ca_min_remaining_seconds` (an expired signer stops
  enrolment and renewal network-wide and had one log line),
  `orbit_maintenance_last_success_seconds` (a stopped sweep is invisible, and
  blocklist pruning stops with it), and `orbit_renewals_failed_total` (successes
  were counted and failures logged, so a fleet that had stopped renewing looked
  like one that had stopped needing to).

  The alert rules in `docs/deployment.md` are rewritten around them, and each
  rule now names what to do when it fires. One rule was removed rather than
  rewritten: it alerted on a label value nothing has ever emitted, so it could
  not fire, and an operator following the runbook had a gap shaped like
  coverage. A test now checks every metric and label value the docs name against
  the code that declares and emits them.

- **`orbit netcheck`** — DNS, TCP, TLS and clock skew against the control
  plane, for when nothing works yet and `status` has nothing to report.
- **`orbit why`** — whether traffic to a peer would pass, and which rule
  decides.
- **`orbit api`** — any route the CLI has not wrapped, with the profile, URL
  and token already resolved, so the token stays out of shell history.
- **`orbitd doctor`** — runs what `serve` runs, before `serve` starts, instead
  of validating `-addr` at the last statement after the store is open.
- **Shell completion** for bash, zsh and fish.
- **Six ADRs** recording what this work rests on, in `docs/adr/`.
- **CI fails on unreachable code**, on two gates: unreachable from the binaries
  (with a documented allow file), and unreachable even counting tests (no
  exemptions). CI also compiles every platform the tree has build tags for,
  after a package split left a file behind that neither the CI runner nor a
  developer Mac compiled.

## v0.4.5

Reporting fixes. A healthy fleet no longer describes itself as a broken one, and
the agent names the commands for the platform it installed on.

### Fixed

- **`last seen` was frozen at enrolment.** The control plane recorded a host on
  enrol and on join, and the agent posts a report only when something CHANGED —
  so a machine that is healthy and up to date reported nothing ever again. A
  host polling every thirty seconds read as hours stale, which is backwards from
  the one thing that column exists to say, and it made every other reading in
  the fleet view suspect.

  Every poll now records that the machine was heard from, and only that.
  Liveness is not convergence: a poll proves a host is alive, while what it has
  APPLIED is what its reports say. Advancing an epoch on a poll would make the
  control plane believe a generation was confirmed because a host asked about
  it, which is how the unreachable-guard reverts something nobody confirmed.

- **Macs reported no operating system.** Device facts read `PRETTY_NAME` from
  `/etc/os-release`, which darwin does not have, so every Mac showed a blank OS
  while Linux hosts reported themselves — which reads as an agent that is not
  reporting rather than a file that is not there. `sw_vers` now names them.

- **Every instruction said `systemctl`.** The agent has always rendered a
  launchd plist on darwin and a systemd unit on Linux, but nothing printed the
  difference, so a Mac was told to run a command it does not have.
  `orbit agent install` and `orbit status` now name the restart and status
  commands for the manager actually in use.

### Added

- **`orbit device ls` shows the agent version.** Versions are device-scoped by
  design — a laptop on three networks runs one agent — so that listing is where
  "what is everything running" is answered. It was previously visible only per
  membership, where one machine appears once per network.

## v0.4.4

Routes now take effect when you add them, gateways forward on hosts that run a
firewall, and a network's routes can be listed without knowing whose they are.

### Fixed

- **Adding a route did nothing for days.** A route is authority only once it is
  in the gateway's CERTIFICATE — nebula reads unsafe networks from there and
  nowhere else. Adding one left the gateway holding a certificate that did not
  carry the prefix, while the control plane had already rendered that route into
  every consumer's configuration. `orbit route add` returned success, every
  other machine was told to reach a network through that gateway, and the
  gateway refused to carry it until its ordinary renewal — roughly half a
  certificate lifetime later.

  The mechanism already existed and was wired to one input: enrolment pulls
  renewal forward when a host's ADDRESS changed after its certificate was
  issued. Routes are the same shape and were not checked. They are now, on
  addition and on withdrawal — a gateway still carrying a prefix in its
  certificate is still authorised to route it, whatever the table says.

- **A gateway on Fedora, RHEL or any firewalld host dropped every forwarded
  packet.** Orbit enabled IP forwarding and masqueraded, but the filter path
  still decides whether a packet lives, and on those hosts that verdict belongs
  to firewalld. `orbit status` reported the gateway forwarding and NATing —
  both instructions had arrived and both had been applied — while nothing got
  through.

  It is not fixed with a rule in Orbit's own table, which was the first attempt.
  nftables runs every base chain at a hook in priority order and `accept` only
  means "continue to the next chain"; only `drop` is terminal. So the frontend
  owns the verdict and the only way past it is to ask the frontend: the tun
  joins firewalld's trusted zone, or gets a ufw route rule, or — where nothing
  owns the verdict — needs nothing, because Orbit's table is then sufficient.
  Each is one named object, removed on uninstall.

- **`orbit membership reserve` printed a join command that returned 404.** It
  echoed the control plane's `-enroll-url`, which is the full path an agent
  POSTs to, while `orbit agent join -url` takes the origin and appends the path
  itself.

- **`orbit exit-node ls` truncated the route id** it then told you to pass to
  `orbit exit-node use`, so the command's own next step could not be satisfied
  from its output. With one route on offer the hint is now the whole command.

### Added

- **`orbit route ls` with no argument lists the whole network**, with the
  gateway that offers each prefix. Routes were reachable only per membership, so
  answering "what does this network route" required already knowing which
  machine to ask. Backed by the same query configuration rendering reads, so the
  listing cannot disagree with what hosts are configured from.

## v0.4.3

Setup script fixes, all three found by running it on a clean host. v0.4.2's
script cannot complete via the documented `curl ... | sudo bash`; this is the
version to install from.

### Fixed

- **`docker compose run` consumed the rest of the script.** The supported way to
  run the setup is `curl ... | sudo bash`, which puts the SCRIPT ITSELF on
  stdin. `docker compose run` attaches stdin to the container and reads it, so
  the first such command swallowed everything below it, bash reached EOF, and
  the run stopped.

  It stopped with status 0. The database was migrated and bootstrap, the `.env`
  write-back and `compose up` never ran — leaving a healthy Postgres, an empty
  `ORBIT_NETWORK`, no admin token, no control plane, and no error to search for.
  `-T` does not prevent this; it only disables TTY allocation. Every
  `docker compose run` now redirects from `/dev/null`.

- **The script did not fetch the nebula submodule.** Neither `git clone` nor
  `git checkout` brings one, and `go.mod` replaces nebula with
  `third_party/nebula`, so building the image locally failed on a missing file.
  Only on the fallback path — taken exactly when the published image cannot be
  pulled, which is what happens while a release's image job is still running.

## v0.4.2

Deployment fixes. Nothing in the agent or control plane changed; if you have not
run `deploy/compose.yml` or `setup-control-plane.sh` yet, this is the version to
start from.

### Fixed

- **The compose file carried a second CA passphrase that was never read.** It
  set `ORBIT_CA_KEY_PASSPHRASE_FILE` to a `./ca-pass` file the setup script
  generated, alongside `ORBIT_KEK_PASSPHRASE` from `.env` — two independently
  random secrets. Only one was ever used: that variable is a compatibility alias
  from before the CA key moved into Postgres, read only when the KEK names are
  unset.

  Inert, and hazardous. Had `ORBIT_KEK_PASSPHRASE` ever been empty — an `.env`
  edited by hand, a variable dropped by a wrapper — the control plane would have
  silently fallen back to a different passphrase and failed to decrypt anything
  it had stored, which reads as a corrupt database rather than a missing
  variable. The file, its secret mount and its ownership dance are gone; one
  secret, in `.env`.

- **The control plane's device key did not survive a restart.** The image
  declares `VOLUME /var/lib/orbit` and compose named no volume for it, so Docker
  created an anonymous one — orphaned whenever the container is recreated, which
  `compose up -d` does on any configuration change. The control plane came back
  as a different device on its own network each time. The volume is now named.

- **`make demo` authenticated as a role that cannot log in**, and exported
  `ORBIT_ENROLL_PEPPER`, retired long ago and read by nothing.

- **The container image would not build** when `go.mod` replaced nebula with the
  submodule; carried over from v0.4.1 for anyone who skipped it.

- The compose header documented `orbit host create` and `orbit host code`, verbs
  the membership refactor removed.

## v0.4.1

### Fixed

- **The container image would not build.** The Dockerfile copies `go.mod` and
  `go.sum` on their own so a source change does not refetch the dependency
  graph, then runs `go mod download`. As of v0.4.0 that file replaces nebula
  with `./third_party/nebula`, and `go mod download` resolves every replacement
  before fetching anything — so it failed on a missing `go.mod` in a directory
  the image had not copied yet.

  Only the image was affected. Every other build already has the whole tree, so
  nothing local, in CI, or in the release binaries could see it.

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
