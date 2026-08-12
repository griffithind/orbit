# ADR-0012: Policy compiles to addresses, not into certificates

**Status:** Accepted
**Date:** 2026-08-11

## Context

Orbit has two firewall sources, and a network runs exactly one of them.
`orbit.network.firewall_source` is `role` or `policy`, checked by the schema
(`internal/db/migrations/0001_initial.sql:129,137`) and mirrored in
`internal/store/policy.go:27-34`.

**Per-role** rules put identity in the certificate. A role carries `groups`, the
groups are baked into the signed host certificate (`internal/ca/ca.go:178,257`),
and a rule selects with `groups:`. The cost is structural, not incidental: a
group edit cannot take effect until every affected host holds a new certificate.
`PATCH /v1/roles/{id}` therefore answers **202** when `groups` changed, with the
count of hosts still holding stale certificates and the instant the last of them
renews (`internal/api/resources.go:900-918`). Ordinary renewal is at the
certificate's midpoint — hours, on the 24h `CertTTL` default that ADR-0002 makes
a security parameter (`internal/wire/wire.go:663`). Orbit already pulls that
forward when a host's certificate predates its role's last groups change
(`internal/enroll/service.go:495-518`), which shortens the window to a round trip
plus a handshake but does not remove it, because the mechanism is still
"reissue and wait".

**Per-network policy** is the other source. One document per network, versioned
in a table with history so an incident can ask what the policy said last Tuesday
(`internal/store/policy.go:120` `PolicyAt`; the migration explains the choice at
`0001_initial.sql:200-221`). The control plane compiles it: `Compiler.resolve`
walks the fleet and turns every `host:`, `id:`, `tag:` and `role:` selector into
the members' overlay **addresses** (`internal/policy/compile.go:153-238`), and
`*` into the network's own prefixes — one rule per prefix rather than one per
host, and it stays correct as hosts come and go (`compile.go:167-182`). The
result is `cidr:` rules, carried through `nebulacfg.FirewallFromPolicy`
(`internal/nebulacfg/policy.go:44`) into the same rendered configuration file
every other setting lives in (`internal/nebulacfg/render.go:613`). An edit is
config-only: it converges on the next agent poll — default `-interval` one
minute (`cmd/orbit/agent.go:999`) — over a hot reload, with no certificate
reissued. `PUT /policy` answers 200, and says so in words
(`internal/api/policy.go:232-237`).

`cidr:` is not the weaker selector, and this is the fact the whole design rests
on. Before any rule is consulted, `Firewall.Drop` validates the peer's claimed
source address against the networks in its **verified certificate** and returns
`ErrInvalidRemoteIP` when it does not match (`docs/policy-model.md` §1.1,
nebula `firewall.go:425`). An address selector is bound to a signature exactly
as tightly as a group selector is. What differs is only *where the change lives*
— inside the signature, or inside the config.

Tailscale solves the same problem and never puts identity in a certificate at
all. Read from source:

- **The filter that reaches a node is address-keyed.** `tailcfg.FilterRule.SrcIPs`
  takes "an IP address", "the string `*`", "a CIDR", "a range of two IPs", or
  `cap:<capability>` — and nothing else (`tailcfg/tailcfg.go:1700-1708`). There
  is no user, tag or group form on the wire.
- **The node never sees the ACL document.** `MapResponse` carries `PacketFilter`
  and `PacketFilters` (`tailcfg/tailcfg.go:2081-2116`) and no policy field. The
  open-source tree contains no HuJSON ACL compiler; `client/tailscale/acl.go` is
  an admin *HTTP client*, and `PreviewACLForUser` (`:369`), `PreviewACLForIPPort`
  (`:398`) and `ValidateACLJSON` (`:478`) are all round trips to the control
  plane. The node's entire share of the work is
  `filter.MatchesFromFilterRules` (`wgengine/filter/tailcfg.go:33`), which turns
  the delivered rules into prefix matchers, then `filter.New` →
  `LocalBackend.setFilter` → `e.SetFilter` (`ipn/ipnlocal/local.go:3486,3539`)
  and per-packet `RunIn`/`RunOut` (`wgengine/filter/filter.go:442,475`).
- **Tags are netmap data, not credentials.** A node *requests* tags —
  "advertising a tag on the client doesn't guarantee that the control server will
  allow the node to adopt that tag" (`ipn/prefs.go:166-170`) — which travel as
  `Hostinfo.RequestTags` (`tailcfg.go:935`, set at
  `ipn/ipnlocal/local.go:6645`), and control grants them back as `Node.Tags` in
  the netmap (`tailcfg.go:416-424`). Node identity is a machine key and a node
  key (`types/key/machine.go`, `types/key/node.go`). The only x509 in the client
  is ACME serving certs for HTTPS (`ipn/ipnlocal/cert.go`) and
  `RegisterRequest.DeviceCert` (`tailcfg.go:1336`), used once at registration on
  Windows machine-certificate deployments (`control/controlclient/sign_supported.go`).
  Nothing in the data path reads a certificate.
- **A change lands on an open connection.** The node holds a long-poll map stream
  (`MapRequest.Stream`, `tailcfg.go:1440`; "the first MapResponse will be
  complete and subsequent MapResponses will be incremental updates with only
  changed information", `tailcfg.go:1965-1974`), and a new filter arrives as an
  incremental `MapResponse` applied through `UpdatePacketFilter`
  (`control/controlclient/direct.go:244-262`, `ipn/ipnlocal/local.go:2636`) with
  no reconnect and no key change. Keep-alives are expected roughly every minute
  and the client abandons a silent poll after `watchdogTimeout = 120 * time.Second`
  (`direct.go:1052-1055`). They went as far as building `PacketFilters`, a map of
  named rule chunks, so the *address-keyed* filter could be updated incrementally
  (`tailcfg.go:2094-2116`) — rather than moving identity to the node to avoid
  resending addresses.
- **"Would this rule permit X to reach Y" is answered by the control plane.**
  On the node, every affordance reports the *delivered* filter and nothing else:
  `debug-packet-filter-rules` dumps the raw `[]tailcfg.FilterRule` and
  `debug-packet-filter-matches` the compiled matches
  (`ipn/localapi/debug.go:297,314`), and `tailscale debug netmap`
  (`cmd/tailscale/cli/debug.go:290,719`) prints the netmap. There is no
  `tailscale debug packet-filter` and no local ACL evaluator. The only runtime
  probe is `tailscale ping --tsmp`, which surfaces the peer's rejection as the
  string `"acl"` (`net/packet/tsmp.go:113-116`) — a probe, not a preview.

## Decision

Orbit compiles firewall policy to addresses, and firewall policy is evaluated in
two places that are not the same place. The **control plane resolves**: it turns
selectors into member addresses at compile time, because it owns address
assignment and is the only component that knows the fleet. **Nebula on each host
matches**: it enforces the compiled `cidr:` rules per packet, against the peer's
verified certificate, with no call to `orbitd` in the data path — which is
ADR-0002 restated for the firewall. Identity never enters a certificate for the
purpose of expressing a rule.

Per-role certificate groups **remain a supported firewall source**, and stop
being the general mechanism. That is the resolution of the open question the two
modes leave, and it is not a hedge — address compilation is strictly faster to
converge, and groups buy two things it cannot:

1. **Rule count.** An address-compiled allowance is O(members) rules per host; a
   group rule is one line regardless of fleet size. `internal/policy/scale_test.go`
   measures the difference: a tiered policy stays cheap to about five thousand
   memberships (134 KiB per host, 655 MiB fleet push), while all-to-all reaches
   431 KiB per host and a 421 MiB fleet push at one thousand — and all-to-all is
   exactly the shape one group rule expresses.
2. **Members that did not exist when the rule was rendered.** A group rule is a
   statement about a *class*, evaluated at handshake against whatever certificate
   arrives. An address-compiled rule is a snapshot of the roster at render time.
   Under ADR-0002 a partitioned host keeps enforcing the rules it has — so when a
   new host enrols during that partition, the partitioned host has no rule naming
   its address, and nebula's firewall is a pure allowlist with no ordering and no
   deny (`docs/policy-model.md` §1.2). It refuses the new peer. That direction is
   the safe one, and it is still an outage between two hosts that policy says may
   talk. A group-based network rides through it untouched.

The asymmetry that keeps `policy` the recommended source is that the same
property inverts on removal. Adding a certificate-bound group fails closed —
merely slow. Removing one fails **open**: the host keeps the group and the access
until it renews, because group membership cannot be subtracted from a live
certificate and the rule set is a union with no "unless". A policy edit that
reads as a revocation is not one. An address-compiled edit revokes on the next
poll.

So: two sources, mutually exclusive, never merged (`internal/nebulacfg/render.go:239-249`).
`role` remains the default and the compatibility path, and is the right answer
for a network that is genuinely all-to-all or that must keep working across long
partitions with a changing roster. `policy` is what documentation, examples and
new networks should use for everything else, and is the only source that can
express a rule about a set of hosts that is not a role.

## Alternatives considered

**Compile the policy document to nebula `groups:`.** The obvious target — nebula
matches groups out of the peer's certificate, and a group is the identity-shaped
thing. Rejected because the change latency is a certificate lifetime, and because
removal fails open: a group cannot be taken out of a certificate that is already
signed and in use. The `cidr:` selector loses nothing in strength for it —
`Firewall.Drop` validates the peer's source address against its verified
certificate before any rule runs — so the group form costs up to 24h of
convergence and buys no additional binding. The reasoning is recorded at
`internal/policy/policy.go:20-41`, and `group:`/`groups:` are refused as policy
selectors for precisely this reason (`policy.go:336-337`).

**Compile to nebula `host:` instead.** Rejected for the same reason with an
extra failure: the certificate name is inside the signature, so renaming costs a
reissue, and `host: any` matches any peer holding a valid certificate from a
trusted CA — including one Orbit never placed in this network
(`internal/policy/compile.go:174-176`).

**Merge the two sources instead of replacing.** Rejected: nebula merges every
`.yml` in a config directory with `mergo.WithAppendSlice`, so firewall lists
**concatenate** (`internal/nebulacfg/render.go:8-9,45-48`). The firewall is
allow-only, so two sources can only ever widen reachability, and the wider one
always wins. Two sources means two answers to "what may reach this host", which
is the thing a compiled policy exists to remove.

**Ship the document to hosts and compile it there.** Rejected on two counts.
Every host would need the full fleet roster to resolve selectors, which leaks
membership of the entire network to every member. And it would put N copies of a
compiler in the field, where version skew is a security bug rather than a
cosmetic one; the server-side compiler can be checked against nebula's own parser
by rendering YAML and reading it back through `AddFirewallRulesFromConfig`
(`internal/nebulacfg/policy.go:68-86`, `internal/fwmatch/parse/parse.go:94-97`),
and a host-side one could not be held to the same evidence. Tailscale reaches the
same place: `MapResponse` has no policy field, and the node's whole job is
`MatchesFromFilterRules` over rules the control plane already resolved.

**Evaluate reachability per connection at the control plane.** The shape a
"check the policy at connect time" instinct suggests. Rejected by ADR-0002: it
puts `orbitd` in the data path and makes a control-plane outage an estate-wide
outage.

**Drop per-role groups entirely and make `policy` the only source.** Tempting,
because it removes the 202, the pulled-forward renewal, and a whole class of
"why is my change not live yet". Rejected: it would delete the only mechanism
that survives the partition-plus-new-host case above, and it would make the
all-to-all shape — measured at 421 MiB per fleet push at one thousand hosts —
unrepresentable at any scale. The right eventual answer is per-tag binding with
an additive address overlay (`docs/policy-model.md` §4.3), not deletion, and that
is not decided here.

## Consequences

**Easy.** A policy edit is a configuration change and behaves like one:
sub-second to compile, one poll to converge, no signature, no reissue, no 202. It
is reversible by another edit at the same speed. It is also **previewable**,
which no certificate-bound scheme can be: `POST /v1/networks/{ref}/policy/check?membership=web-01`
runs the real compiler over the real fleet with the real management floor and
returns the exact ruleset the renderer would produce, alongside the host's
addresses, tags, role and groups — because the usual fault is that the host is
not tagged the way the author assumed, not that the rule is malformed
(`internal/api/policy.go:240-363`). Tailscale's equivalent is also a control-plane
call (`PreviewACLForIPPort`); the difference is that ours compiles into rules an
operator can read.

`orbit why` gets sharper for the same reason. `fwmatch` evaluates a `cidr:` rule
with nothing but an address, so the server can answer about two hosts it has
never seen handshake, and the local form can answer with no tunnel up
(`internal/fwmatch/fwmatch.go:341-348`). A `groups:` or `host:` rule returns
`Unknown` when the peer's certificate is not in hand
(`fwmatch.go:350-353`) — the diagnostic is strictly weaker on the source this
ADR keeps.

**Hard.** Rule count is O(members) per allowance, and a fleet-membership change
is now a re-render event for every host that may reach the new member.
`Compiler.All` exists because of it: resolving the document is the expensive half
and it is identical for every host, so rendering a whole network through
`Membership` would redo it N times (`internal/policy/compile.go:78-94`). The
numbers are in `scale_test.go` and in `docs/policy-model.md` §3, and they are the
honest ceiling on this design.

Every answer is against the fleet **as it is now**. A host enrolled after a check
changes the result, and the check endpoint says so rather than implying a
guarantee it cannot make (`internal/api/policy.go:262-265`).

And the partition cost named in the Decision is real: fail-static plus a
roster-snapshot ruleset means a partitioned host cannot admit a host that
enrolled after its last poll. It fails closed, which is the direction we want,
and it is still downtime for a flow the policy permits. Nothing in this design
removes it; only certificate binding would, at the price of the removal
semantics.

**Committed to.** The management floor is not optional. In authoritative mode a
policy *is* the complete firewall, so a document that forgets the control plane
removes the path every host uses to fetch the fix — including the fix that would
restore it. Two rules wide, emitted whether or not the document asked for them
(`internal/policy/compile.go:44-62`), and mirrored into the preview so a dry run
is not missing exactly the rules an operator is checking for
(`internal/api/policy.go:367-390`).

Also committed to keeping the two sources exclusive. A network in `role` mode
must read byte-identically to a network with no policy document at all, which is
why the opt-in is enforced in one place — `store.NetworkPolicy` returns a nil
document unless `firewall_source` is `policy`, so the render path cannot forget
to check (`internal/store/policy.go:408-455`).

**Revisit if** either half of what groups buy stops being hypothetical: a
customer fleet whose realistic policy is genuinely all-to-all at a scale where
the push size in `scale_test.go` is the binding constraint, or a deployment where
long partitions with a churning roster are normal rather than an incident. The
answer then is the per-tag `binding: certificate` design with a transitional
address overlay and pulled-forward renewal on removal
(`docs/policy-model.md` §4.3) — which needs the handshake-size measurement in
§4.4 first, since a host in many tags produces a larger handshake and the default
tun MTU is 1300.

## References

Orbit:

- `internal/policy/policy.go:20-41` — why addresses and not groups, in the package comment
- `internal/policy/compile.go:153-238` — selector resolution to addresses; `:78-94` — `All` vs `Membership`
- `internal/policy/scale_test.go` — rule counts and fleet push sizes
- `internal/store/policy.go:27-34,120,408-455` — the two sources, `PolicyAt`, the single opt-in
- `internal/db/migrations/0001_initial.sql:129-137,200-236` — `firewall_source`, and why policy is a table with history
- `internal/api/policy.go:240-363` — the check endpoint; `internal/api/resources.go:900-918` — why a group edit answers 202
- `internal/enroll/service.go:495-518` — renewal pulled forward on a groups change
- `internal/nebulacfg/policy.go:44,68-86` — compiled rules into the config, and back through nebula's own parser
- `internal/nebulacfg/render.go:239-249` — policy replaces the role firewall, never merges
- `internal/fwmatch/fwmatch.go:246-248,341-353` — the mirrored grammar, and why a `cidr:` rule is decidable without a certificate
- `docs/policy-model.md` §1.1, §3, §4.2-4.4 — the nebula facts, the measurements, and the future shape
- ADR-0002 (fail static), ADR-0003 (revocation terminates live sessions)

Tailscale, read at `tailscale/` HEAD:

- `tailcfg/tailcfg.go:1694-1755` — `FilterRule`; `SrcIPs` is addresses, CIDRs, ranges or `cap:`
- `tailcfg/tailcfg.go:2081-2116` — `MapResponse.PacketFilter` / `PacketFilters`, incremental named chunks
- `tailcfg/tailcfg.go:416-424,935` — `Node.Tags` granted by control, `Hostinfo.RequestTags` requested by the node
- `ipn/prefs.go:166-170` — advertising a tag does not grant it
- `wgengine/filter/tailcfg.go:33` — `MatchesFromFilterRules`, the node's entire share of compilation
- `ipn/ipnlocal/local.go:2636,3486,3539` — filter installed into wgengine; `wgengine/filter/filter.go:442,475` — `RunIn`/`RunOut`
- `control/controlclient/direct.go:244-262,1052-1055` — `PacketFilterUpdater`, and the 120s poll watchdog
- `ipn/localapi/debug.go:297,314` and `cmd/tailscale/cli/debug.go:290,719` — the node can dump the compiled filter and nothing more
- `client/tailscale/acl.go:369,398,478` — ACL preview and validation are control-plane API calls
- `types/key/machine.go`, `types/key/node.go`, `ipn/ipnlocal/cert.go` — identity is keys; the only x509 is for serving HTTPS
