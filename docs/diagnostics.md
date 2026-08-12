# Orbit — Diagnostics

The agent status socket, and the commands built on it: `orbit status`,
`orbit peers`, and `orbit why` in both its local and bidirectional forms.

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

and one on the control plane's admin API, for the bidirectional form:

```
GET /v1/networks/{ref}/reachability?src=&dst=&proto=&port=     policy:read
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
remote? Is it relayed? What underlay addresses do we know for the peer, whether
or not any answered — "we know four and none worked" and "we have never heard of
it" have opposite causes and used to print identically.

> Asking the lighthouse directly (`QueryLighthouse`) would separate "policy says
> no" from "we never found each other", which look identical from `ping`. That
> call is NOT wired: this paragraph described it as though it were for long
> enough that ADR-0014 was written about the gap. It belongs with the UDP leg
> ADR-0032 adds to `orbit netcheck`, and until one of them lands, the honest
> answer to "does the lighthouse know this peer" is that Orbit cannot tell you.

**Policy.** Which of our rules could admit traffic to this peer on this
protocol and port — and if none, say so plainly.

### 4.1 Reading the policy layer honestly

> Two things in this section were wrong and are corrected in §6.3: Nebula does
> the parsing, and the cross-check needs no build tag. The reasoning below is
> kept because the conclusion — that the matcher must be held honest by
> observation rather than by promise — is what drove the design.

The agent holds the *rendered* Nebula configuration, not a `policy.Ruleset`. It
asks about what is actually in force, including anything an operator added in
the configuration nebula was actually handed, rather than what we believe we sent.

Matching mirrors the grammar in [policy-model.md §1.2](policy-model.md):

```
proto AND port AND (ca_sha OR ca_name) AND local_cidr AND (group OR host OR cidr)
```

**The matcher is a second implementation of Nebula's, and second
implementations drift.** `FirewallTable.match` is unexported and
`Firewall.Drop` needs a `*HostInfo` we cannot construct, so there is no way to
delegate the verdict. The mitigation is a cross-check rather than a promise:
`e2e/why_test.go` boots two real Nebula instances, opens real TCP connections
across a matrix of ports, and asserts the explainer agreed with what happened.
A divergence is a test failure, not a support ticket.

### 4.2 What a local answer cannot know

Our outbound rules are half the story. The peer enforces its own inbound rules
against our certificate, and nothing on this host can read them. `orbit why`
must say so rather than reporting "allowed" and leaving the operator to discover
the other half by experiment.

The complete answer belongs to the control plane, which holds both compiled
rulesets:

```
orbit why <src> <dst> [--proto tcp] [--port 5432]     # admin, bidirectional, authoritative on policy
orbit why <peer>      [--proto tcp] [--port 5432]     # node-local, one direction, live path state
```

This split falls out of the CLI survey: node-local commands answer about *this
machine* and live state; admin commands answer about *the network* and
configured intent. Neither is a substitute for the other — the control plane
knows what policy says and nothing about whether a handshake completed.

---

## 4.3 `orbit netcheck`

The layer below everything else in this document.

`status`, `peers` and `why` all read the agent's socket, so all three need an
agent that started. `netcheck` needs nothing: no token, no overlay, no agent. It
is what to run when the answer to "why is this not working" is that the machine
cannot reach the control plane at all.

Four checks, reported separately because they send an operator to four different
places:

| check | a failure means |
|---|---|
| `dns` | the name does not resolve from here. Note a host using mesh DNS may have a resolver that is itself behind the overlay |
| `tcp` | nothing is listening, or a firewall drops it. Not an authentication failure |
| `tls` | the chain does not verify from this host — a private CA has to be in the system trust store |
| `clock` | see below |

The agent itself is reported as `--` rather than `FAIL` and does not affect the
exit status, because netcheck is meant to be useful on a machine that has not
been set up yet.

Clock skew is measured against the control plane's own `Date` header rather than
against NTP, because the control plane is what will refuse this host's
certificate and its opinion of the time is the one that matters. The tolerance
is two minutes: issuance backdates by one (`ca.ValidityFor` takes a skew
allowance), so a minute is survivable and more is not — past that a freshly
issued certificate has a `NotBefore` this host believes is in the future, and
nebula refuses it.

That failure is worth calling out because of how it presents. A wrong clock
breaks enrolment and renewal and reports itself as a certificate error, which
sends whoever is debugging to the CA — the one place the fault is not. Nothing
else in the system says "your clock is wrong".

Exit status is 0 when everything real passed, 1 otherwise, so `orbit netcheck`
works as a health check without parsing its output.

## 5. Commands

```
orbit status                        # all networks, one screen
orbit peers [--network <slug>]       # hostmap table
orbit why <peer>      [--proto] [--port]   # this host: identity, path, its own rules
orbit why <src> <dst> [--proto] [--port]   # the control plane: both directions
```

`orbit why` dispatches on the number of operands rather than on a mode flag,
because it is one question — may these two talk — asked from the two places
that can answer parts of it.

`--json` on all of them. The human format is the default because these are read by
people under time pressure; the JSON is for scripts and for `bugreport` later.

`orbit status` with no agent running must say "the agent is not running" and
exit non-zero, rather than failing to dial a socket. The command exists to
diagnose a broken host, so its own failure mode has to be legible.

---

## 6. Order of work

1. ~~The socket, `/v1/status`, and `orbit status`.~~ **Built.**
   `internal/agent/status/status.go` and `cmd/orbit/status.go`.
2. ~~`/v1/networks/{slug}/peers` and `orbit peers`.~~ **Built.**
   `Embedded.Peers` and `cmd/orbit/peers.go`.
3. ~~The explainer, its cross-check test, and node-local `orbit why`.~~
   **Built.** `internal/agent/explain.go`, `e2e/why_test.go`,
   `cmd/orbit/why.go`.
4. ~~Control-plane `orbit why <src> <dst>`.~~ **Built.**
   `internal/api/reachability.go` and `whyBetween` in `cmd/orbit/why.go`.

All four are done.

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
registry populated only on success would omit precisely the membership this command
is run against.

### 6.2 What step 2 settled

**A stopped data plane is an answer, not an error.** `Embedded.Peers` returns
`ErrNebulaNotRunning` rather than an empty slice, and `orbit peers` renders
that as the headline. An empty peer table reads as "this host is isolated",
which is a different problem with a different remedy from "nebula never
started" — and returning a 500 would have made the command fail on exactly the
host it is most useful on.

**A network that has not started is not a 404.** The host has joined it, so
saying it does not exist would send an operator looking for a typo instead of
at the reason it is down. A slug that was never joined *is* a 404, and the two
carry different exit codes (0 and 5).

**Pending peers are a separate list.** A peer stuck mid-handshake is the
signature of a firewall, a lighthouse that does not know it, or a clock skew —
and merging it into the established list would hide it among peers that work.

**The hostmap is sorted before it leaves the agent.** nebula iterates a Go map,
so without this, two runs against an unchanged mesh print different orders and
an operator comparing memberships is reading a shuffle.

One thing came for free and was worth taking: `Embedded` had recorded *why*
nebula last exited since it was written, and nothing read it. `Status` now
carries it, so "nebula NOT running" arrives with the bound port or the refused
configuration attached instead of sending the reader to a log.

### 6.3 What step 3 settled

**Nebula parses; Orbit only matches.** §4.1 assumed the explainer would read
the firewall section out of the applied YAML. It does not, and it should not:
that would be *two* re-implementations, and the parser is the larger and
fiddlier one — port ranges, `port: fragment`, the `group`/`groups` flattening,
ICMP's coerced ports, the `local_cidr` default that depends on unsafe networks.

`nebula.AddFirewallRulesFromConfig` is exported and takes any
`nebula.FirewallInterface`, so handing it a collector makes **nebula** the
parser. Every quirk above stays upstream's problem and stays correct when
upstream changes it. Only the matching is ours, which is a much smaller and
better-specified surface than §4.1 assumed.

**The cross-check runs without root.** §4.1 proposed Nebula's `e2e_testing`
build tag; that turned out unnecessary. `overlay.NewUserDeviceFromConfig` plus
`service.New` boots a full Nebula instance on a userspace stack, so
`e2e/why_test.go` runs *two* of them, opens real TCP connections between them
through real firewall tables, and asserts the explainer predicted what
happened. `Drop` does not care what the device is, so the firewall under test
is the real one. It runs in ordinary CI.

The test also asserts its own matrix produced **both** verdicts. A tunnel that
never came up would make every port unreachable, the explainer would agree on
"no" everywhere, and the test would go green having compared nothing.

**Undecidable is not denied.** Without a tunnel there is no peer certificate on
this host, so a rule selecting by group, host or CA cannot be evaluated at all.
Reporting that as a denial would be a confident wrong answer in the direction
that sends an operator looking in the wrong place, so `Decision` carries
`Undecidable` separately from `Allowed`.

**Policy is answerable with the data plane down.** The rules are on disk, so
the one layer that does not need a running Nebula still answers — which matters
because the membership somebody runs this against is usually the broken one.

### 6.4 What step 4 settled

**One matcher, two callers, in its own package.** The node-local command and
the control-plane command answer different questions about the same rules, and
if they came from different code an operator could be told one thing by the
server and the opposite by the machine — worse than either command existing.
So the matcher moved to `internal/fwmatch`, and `e2e/reachability_test.go`
asserts the two agree over a matrix of protocols and ports, with a real agent
running the configuration the control plane rendered.

Only the OUTBOUND half is comparable between them, and the test says so. That
is src's own table, which both ends can see; the server's inbound half is dst's
table, which src has no access to at all. That asymmetry is the reason the
bidirectional command needed to exist.

**Compiled rules go back through nebula's parser.** `nebulacfg.FirewallYAML`
renders a compiled `policy.Ruleset` into a firewall section, and
`fwmatch.LoadRulesFromString` reads it back. Converting `policy.Rule` to a
matcher rule field by field would have re-implemented the port-range and
protocol parsing this whole arrangement exists to avoid — and it would have let
the server's answer drift from the agent's in exactly the place nobody would
look. It also means a compiler bug that emits something nebula cannot read
surfaces here rather than at four hundred memberships.

**Both halves print even when one settles it.** Which END denies a flow decides
whose policy an operator has to change, so a bare "DENIED" is not an answer.

**A network on per-role rules is not a denial.** There is no document to
compile, and reporting an empty ruleset would render as "denied" and send
somebody to edit a policy that is not in force.

**The server's caveat mirrors the agent's.** The node-local command says it can
only see one direction; this one says it describes what the stored policy
MEANS, not what any host has applied or whether a tunnel is up. Neither
substitutes for the other, and both say so.
