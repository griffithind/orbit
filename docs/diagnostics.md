# Orbit — Diagnostics

Design for `orbit status`, `orbit peers` and `orbit why`.

---

## 1. The gap

Every comparable product treats diagnostics as a first-class part of the node
CLI. Tailscale ships `status`, `ip`, `ping`, `netcheck`, `whois`, `debug` and
`bugreport`; NetBird ships `status` and a `debug` group including
`debug trace`, which explains firewall rule processing.

Orbit ships none. When a tunnel does not come up, the answer today is "read the
logs". That is the largest usability gap in the CLI, and it is now cheap to
close: because the agent runs Nebula in-process, it holds the `*nebula.Control`
and that type already exposes what these commands need —
`ListHostmapHosts`, `GetHostInfoByVpnAddr`, `PrintTunnel`, `QueryLighthouse`,
`GetCertByVpnIp` (`control.go:219-332`). Upstream surfaces the same calls over
an SSH debug server; we need no SSH server and no new dependency.

---

## 2. Transport

**One Unix socket at `<root>/agent.sock`**, serving HTTP.

One socket, not one per network, because the agent is a single process serving
every joined network — the same reason there is a single service unit. The
network is a path parameter, not a separate endpoint.

HTTP over a Unix socket rather than a bespoke protocol: `net/http` is already a
dependency, the paths are versionable, and `curl --unix-socket` is a debugging
tool we get for free.

**Mode 0600, root-owned.** The socket exposes the full hostmap and every peer's
certificate, which is a map of the network; on a shared host that is a real
disclosure. Root is already required to run the agent, so this costs nothing
today. Relaxing it to a group is a deliberate later flag, not a default.

**Version 1 is read-only.** `Control` also offers `CloseTunnel`,
`SetRemoteForTunnel` and `CloseAllTunnels`. None of them are exposed. Keeping
v1 read-only means the blast radius of a permissions mistake is disclosure
rather than control, and it lets the socket be added without a security review
of a mutation surface.

The listener is created by `agent run` after the networks are discovered and
removed on shutdown. A stale socket file from a killed process is unlinked
before binding — a bind failure on a stale path is a startup failure operators
cannot diagnose, which is precisely the class of problem this feature exists to
remove.

---

## 3. Endpoints

```
GET /v1/status
GET /v1/networks/{slug}/peers
GET /v1/networks/{slug}/explain?peer=&proto=&port=
```

`/v1/status` returns, per network: the slug, the agent's state, the certificate
(name, groups, networks, not-after), the applied and available config and
blocklist epochs, the time and outcome of the last poll, the last error if any,
the Nebula generation and whether it is running, and the peer count. That set is
chosen so that the three failure modes an operator actually hits — the control
plane is unreachable, the certificate has expired, Nebula is not running — are
each visible without a second command.

`/v1/networks/{slug}/peers` returns the hostmap: for each peer, name and VPN
addresses from its certificate, current remote, whether traffic is relayed and
through whom, certificate expiry, and the message counter. This is
`ListHostmapHosts` reshaped; `ControlHostInfo` (`control.go:60`) already
carries all of it.

`/v1/networks/{slug}/explain` is described below.

---

## 4. `orbit why`

The differentiator, and the one that needs care to avoid being confidently
wrong.

Reachability has three independent layers, and a useful answer reports all
three separately rather than collapsing them into one verdict:

**Identity.** Is our certificate valid and unexpired? Which groups does it
carry? If a tunnel exists, the same for the peer's certificate. A certificate
that expired an hour ago explains everything downstream of it, and is invisible
in a connectivity test.

**Path.** Is there a tunnel (`GetHostInfoByVpnAddr`)? What is the current
remote? Is it relayed? If there is no tunnel, does the lighthouse know the peer
(`QueryLighthouse`)? This separates "policy says no" from "we never found each
other", which look identical from `ping`.

**Policy.** Which of our rules could admit traffic to this peer on this
protocol and port — and if none, say so plainly.

### 4.1 Reading the policy layer honestly

The agent holds the *rendered* Nebula configuration, not a `policy.Ruleset`.
The explainer parses the firewall section back out of the applied configuration,
which is better than consulting what we believe we sent: it explains what is
actually in force, including anything an operator added in `ModeFragment`.

Matching mirrors the grammar in [policy-model.md §1.2](policy-model.md):

```
proto AND port AND (ca_sha OR ca_name) AND local_cidr AND (group OR host OR cidr)
```

**This is a second implementation of Nebula's matcher, and second
implementations drift.** `FirewallTable.match` is unexported and
`Firewall.Drop` needs a `*HostInfo` we cannot construct, so there is no way to
delegate. The mitigation is a cross-check rather than a promise: an e2e test,
built with Nebula's `e2e_testing` tag, establishes real tunnels, sends a corpus
of packets across a matrix of protocols, ports and group memberships, and
asserts that the explainer's verdict agrees with whether the packet actually
arrived. A divergence is a test failure, not a support ticket.

### 4.2 What a local answer cannot know

Our outbound rules are half the story. The peer enforces its own inbound rules
against our certificate, and nothing on this host can read them. `orbit why`
must say so rather than reporting "allowed" and leaving the operator to discover
the other half by experiment.

The complete answer belongs to the control plane, which holds both compiled
rulesets:

```
orbit why <src> <dst> [-proto tcp] [-port 5432]     # admin, bidirectional, authoritative on policy
orbit why <peer>      [-proto tcp] [-port 5432]     # node-local, one direction, live path state
```

This split falls out of the CLI survey: node-local commands answer about *this
machine* and live state; admin commands answer about *the network* and
configured intent. Neither is a substitute for the other — the control plane
knows what policy says and nothing about whether a handshake completed.

---

## 5. Commands

```
orbit status                      # all networks, one screen
orbit peers [-network <slug>]     # hostmap table
orbit why <peer> [-proto] [-port] # local explanation
```

`-json` on all three. The human format is the default because these are read by
people under time pressure; the JSON is for scripts and for `bugreport` later.

`orbit status` with no agent running must say "the agent is not running" and
exit non-zero, rather than failing to dial a socket. The command exists to
diagnose a broken host, so its own failure mode has to be legible.

---

## 6. Order of work

1. ~~The socket, `/v1/status`, and `orbit status`.~~ **Built.**
   `internal/agent/status.go` and `cmd/orbit/status.go`.
2. `/v1/networks/{slug}/peers` and `orbit peers`. Pure reshaping of
   `ControlHostInfo`.
3. The explainer, its cross-check test, and node-local `orbit why`.
4. Control-plane `orbit why <src> <dst>`, which needs no new agent surface —
   it reads compiled rulesets the server already has.

Step 2 is mechanical. Step 3 is where the risk is, and it should not ship
without the cross-check in 4.1.

### 6.1 What step 1 settled

Two things were decided in code rather than here, and both are load-bearing
enough to record.

**The socket is bound with a connect-first check, never an unconditional
unlink.** Clearing the path outright lets a second agent bind over a running
first one: both processes look healthy, status requests go to whichever won,
and the loser keeps serving networks nobody can see. Only a refused connection
proves the path is a leftover. `TestALiveSocketIsNotStolen` holds it.

**The report re-reads the state file rather than reading `Loop.State`.** The
tick goroutine mutates that field, so reading it from the socket's goroutine is
a data race, and holding a lock across a tick would let a slow control plane
block the command that exists to report on it. Reading the file is also the
more honest answer: it is what survives a restart, and it is what the control
plane was last told.

A third followed from the first two: a network that never finished setup gets a
slot before it starts, so it appears in the report carrying its error. A
registry populated only on success would omit precisely the host this command
is run against.
