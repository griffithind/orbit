# Routes and exit nodes

Research, not a plan of record. Two features that are the same feature: an exit
node is a route for `0.0.0.0/0`.

---

## 1. What nebula gives us

The binding constraint, and it is a better hand than it looks.

**A route is a certificate fact.** From `examples/config.yml`:

> The nebula certificate of the "via" node(s) **MUST** have the "route" defined
> as a subnet in its certificate

That is `Certificate.UnsafeNetworks()`, and the CA constrains it: a CA carries
its own `UnsafeNetworks` and `internal/ca.Issuer` refuses to sign a host cert
claiming anything outside it (`containedBy`, `ca.go:317`). So the right to route
a subnet is **signed**, not merely recorded.

Everyone else binds it to a control-plane database row. This is the one place
Orbit's shape is genuinely stronger, and it is worth stating precisely: a
compromised control-plane *database* cannot grant routing authority, because the
CA has to sign it. See §5 for what it costs.

**Config side** (`tun.unsafe_routes`):

```yaml
unsafe_routes:
  - route: 192.168.87.0/24
    via:
      - gateway: 10.0.0.1
        weight: 10
      - gateway: 10.0.0.2
        weight: 5
    mtu: 1300        # defaults to tun mtu
    metric: 0
    install: true    # false keeps it out of the system routing table
```

**Weighted ECMP with automatic failover**, and this beats Tailscale outright —
"if a gateway is not reachable through the overlay another gateway will be
selected to send the traffic through, ignoring weights". Tailscale explicitly
does *not* fail over to a less-specific route (§2).

**The firewall trap.** `local_cidr` on an inbound rule scopes which *destination*
a rule covers. Its default is the host's own overlay addresses — so on a gateway,
a rule without `local_cidr` allows traffic to the gateway and **not** to anything
it routes. A rule naming a routed subnet therefore validates, renders, deploys,
and silently does nothing.

`default_local_cidr_any: true` makes every rule apply to every routed subnet.
It is deprecated, and it is the wrong hammer.

**Exit nodes** are `route: 0.0.0.0/0`. Two host-level requirements nebula does
not handle:

- `net.ipv4.ip_forward=1` and a `MASQUERADE` rule — nebula does no NAT.
- `so_mark` (Linux) so nebula's own UDP to lighthouses is not routed back into
  the tunnel it is carrying. Without it a `0.0.0.0/0` route is a loop.

---

## 2. What the competition does

### Tailscale

**Two-sided consent.** A node advertises (`tailscale set --advertise-routes=…`,
`--advertise-exit-node`); an admin approves in the console. Neither alone is
enough. `autoApprovers` in the policy file automates approval for routes
advertised by a given user or tag.

Clients then **opt in** per device (`--exit-node=<ip>`). Nobody is silently
routed through anything.

- Overlapping routes resolve by **longest prefix match**.
- **No failover to a less-specific route.** If the router for the more-specific
  prefix dies, traffic does not fall back. The documented mitigation is to make
  every router advertise the specific prefixes too.
- Exit-node access needs `autogroup:internet` in the ACL — granting access to
  the *device* does not grant use of it as a gateway.
- Local network access is **lost by default** when using an exit node;
  `--exit-node-allow-lan-access` restores it.
- IP forwarding required; `firewalld` hosts also need masquerading.

### NetBird

Closest to what Orbit should build.

- **Routing peers**, grouped for HA, selected by **metric** (lower wins).
- **Masquerade on by default**, which "hides source IPs and simplifies setup".
  Disabling it means configuring return routes in the external network.
- **Distribution groups** decide which peers *receive* a route — routes are not
  pushed fleet-wide.
- And the warning worth reading twice: **"routes bypass access control policies
  unless explicitly configured."** That footgun is why they built a second
  mechanism ("Networks") where groups are mandatory for both access and
  advertisement.

That is precisely the `local_cidr` trap from §1, shipped. Orbit can avoid it by
construction.

### ZeroTier

Managed routes pushed to all members from the controller; forwarding and route
tables coordinated by hand on each routing peer. Coarse, and the self-hosted
controller has no UI at all.

---

## 3. What Orbit already has

More than expected. Someone left the door open.

| Piece | State |
|---|---|
| CA constraint on unsafe networks | **Built** — `ca.CAParams.UnsafeNetworks`, enforced by `containedBy` |
| Host cert can carry unsafe networks | **Built** — `ca.HostParams.UnsafeNetworks` |
| Policy compiler models routed subnets | **Built** — `policy.Membership.UnsafeNetworks` |
| Compiler emits explicit `local_cidr` | **Built**, with a comment naming the exact trap NetBird shipped |
| `local_cidr` on the wire, rendered, matched | **Built** — `wire`, `nebulacfg`, `fwmatch` |
| `orbit why` understands `local_cidr` | **Built** |

What is missing is the middle, not the ends:

- No storage. Nothing records which subnets a membership routes.
- Enrollment never passes `UnsafeNetworks` into `HostParams`.
- `nebulacfg.Render` emits no `tun.unsafe_routes` block.
- **No CA Orbit creates carries `UnsafeNetworks`** — `orbitd bootstrap` and
  `POST /v1/cas` both omit it, so today every route-bearing cert would be
  refused by the issuer.
- No API, CLI, or UI surface. No exit-node plumbing (forwarding, NAT, `so_mark`).

---

## 4. The design

Decided, with three corrections noted where they change the shape.

### The table

Routes are **topology**, like `is_lighthouse` and `is_relay` — and like those,
they belong to a membership, not a device. A Pi that routes a lab subnet on one
network routes nothing on another.

```sql
CREATE TABLE orbit.route (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id    uuid NOT NULL,
    membership_id uuid NOT NULL,          -- the gateway advertising it

    prefix        cidr NOT NULL,
    weight        int  NOT NULL DEFAULT 1,      -- share among gateways for the SAME prefix
    masquerade    boolean NOT NULL DEFAULT false,
    install       boolean NOT NULL DEFAULT true,
    mtu           int,

    created_at    timestamptz NOT NULL DEFAULT now(),

    -- Composite, so a route cannot name a membership in another network. The
    -- same shape role uses, for the same reason.
    FOREIGN KEY (network_id, membership_id)
        REFERENCES orbit.membership (network_id, id) ON DELETE CASCADE,

    -- One membership offers one prefix once. Two gateways for the same prefix
    -- are two rows, which is exactly how alternative paths are expressed.
    UNIQUE (membership_id, prefix)
);
```

### Priority is two different things, and only one needs modelling

Worth separating, because conflating them produces a knob that does nothing.

**Different prefixes on one gateway** — `192.168.88.0/24` and `0.0.0.0/0` on the
same Pi — need **no priority at all**. Longest-prefix match is how every routing
table on earth works: a packet for `192.168.88.5` takes the /24 because it is
more specific, and everything else falls to the /0. It is automatic, it is not
configurable, and there is nothing to store.

**The same prefix from two gateways** is where priority is real, and that is
`weight`: nebula's weighted ECMP, which also fails over automatically when a
gateway goes unreachable. That is the column above, and it is the whole of
"alternative paths" — two rows, two weights, done.

### NAT is per route, which is right

`masquerade` is a column, not a network-wide setting. The Pi case makes the
argument by itself: `0.0.0.0/0` wants NAT, because the internet cannot route
back to an overlay address; `192.168.88.0/24` usually does not, because the LAN
can be told a static route and the operator would rather see real source
addresses in their own logs.

Nebula performs no NAT. The agent installs and removes the rule, scoped to that
prefix — which means the agent grows the ability to change host firewall state,
and that is a real increase in what it does. Worth its own scrutiny when built.

### Access control needs no new mechanism

The policy document already has `cidr:` selectors, and the compiler already
emits `local_cidr` when a destination is a subnet a host routes. So this works
the day the table exists:

```yaml
allow:
  - src: [role:laptop, tag:team=platform]
    dst: [cidr:192.168.88.0/24]
    proto: any
```

**Do not build a second access-control system for routes.** That is precisely
NetBird's documented mistake — "routes bypass access control policies unless
explicitly configured" — which cost them a whole second mechanism to escape.
One document decides who may reach what, whether the destination is a member or
a subnet behind one.

`autogroup:internet` stays refused. Tailscale needs that token because its ACLs
cannot name the internet; Orbit's can — `dst: [cidr:0.0.0.0/0]` — and the
compiler renders the `local_cidr` that makes it bite on the gateway.

`via:` also stays refused, and the reason sharpens rather than changes: choosing
a **path** is routing, and routing is this table. The firewall sees a peer's
certificate, not a path, so a `via` selector in a policy document would be a
promise the packet filter cannot keep. The two layers stay apart.

### Routes auto-apply; exit nodes are opted into

A route to `192.168.88.0/24` reaches a consumer through policy, with no
per-machine acceptance. That is right: the operator who wrote the policy already
decided.

`0.0.0.0/0` is different, because it captures **everything** — and a machine
silently acquiring a new default route is the one change nobody should discover
by accident.

**But the acceptance cannot be local configuration.** The agent hands nebula
only what the control plane signed (`config-integrity.md` §7a), and a locally
injected route would be the one thing that model exists to prevent. So the local
command is a *request*, not an edit:

```
orbit exit-node ls            # what this membership is permitted to use
orbit exit-node use lab-pi    # PATCH the membership; epoch bumps; config returns
orbit exit-node off
```

Local UX, central authority, signed config intact. The list is what policy
already permits, so an operator cannot opt into a gateway they were never
granted.

---

## 5. The CA constraint

A CA's `UnsafeNetworks` cannot be widened after signing, so enabling routes on a
network whose CA permits none means a **rotation**.

That is a smaller problem than it first looks, and the reasoning is worth
keeping: rotation is a supported, rehearsed operation (`design.md` §6), the
control plane pushes the new bundle before the new CA signs anything, and a
machine that falls behind pulls its configuration and recovers on its own. It is
a scheduled change, not an outage — and gateways can be prioritised, since they
are the only machines that need the new authority.

**Proposal: default a new network's CA to RFC1918** — `10/8`, `172.16/12`,
`192.168/16`. That makes the common case (a Pi in front of a LAN) work the day a
network is bootstrapped, with no rotation.

`0.0.0.0/0` stays out of the default deliberately. A CA permitting it lets any
host it signs claim authority over every destination, and exit nodes are the
feature we already decided should be explicit. Widening to it is a rotation, and
that is the right amount of friction for the thing that carries all of a
machine's traffic.

---

## 6. What the agent does to the host

Today the agent touches **no** host state — no iptables, no `ip route`, no
sysctl. Routes end that, and the ownership model is worth settling before the
first rule is written rather than after.

### The rule: mark the object, not just the record

A state file saying "I added these rules" is not enough. It can be lost, and it
says nothing about a rule somebody has since edited. The marker has to be on the
host object itself, so the agent can find and remove its own work with no
memory of having done it.

**nftables — own a whole table.**

```
table inet orbit { ... }        # chains registered at hooks
nft destroy table inet orbit    # removes everything, edited or not
```

One command, total, idempotent. This is what Tailscale does (`ts-table`), and
their own issue tracker is mostly about the cases where owning less than a whole
table goes wrong.

**iptables — own whole chains**, since there is no private table:

```
ORBIT-OUTPUT, ORBIT-FORWARD, ORBIT-POSTROUTING
```

with a jump inserted at the head of each built-in. Removal is flush-chain,
delete-jump, delete-chain. Never add or delete individual rules in a built-in
chain: that is the thing that cannot be undone reliably once someone else has
edited around it.

**Routes — a private protocol number.**

```
ip route add 192.168.88.0/24 dev orbit-prod proto 201
ip route flush proto 201
```

`proto` exists for exactly this. From `ip-route(8)`: *"A system setting up routes
should set up all of its routes with a unique route origin number."* Anything
without our number is not ours and is not touched.

**Reconcile, do not fire-and-forget.** The same shape as the config divergence
check: every cycle, compare the table and the `proto`-marked routes against what
the signed config says they should be, and repair. A rule someone edited is
detected and replaced, and the agent's records are never the authority — the
host is inspected.

**Uninstall must be total.** `orbit leave` destroys the table, flushes
the proto, and leaves a machine indistinguishable from one Orbit never touched.
That is testable, and it should have a test.

### Who installs the route, nebula or us

Nebula installs unsafe routes itself when `install: true`. That is the simple
path and it should stay the default.

Shielded routes (below) need **policy routing** — an `ip rule` and a private
table — which nebula does not do. Those need `install: false` and agent-owned
routes. So the division is per-route and follows the shield flag, not a global
mode.

---

## 7. Shield: this prefix over the overlay, or not at all

The ask: traffic for an advertised prefix must **never** take the local path,
even when the machine is physically attached to the same network. A laptop on a
café LAN that happens to use `192.168.88.0/24` must not reach the café's hosts
believing they are yours — and must not leak to them.

This is a real hazard, and the ordinary routing table gets it wrong: a
directly-connected route wins over one pointing at a tunnel.

### Two layers, and both are needed

**Routing decides the normal case.** A rule at higher priority than `main`,
pointing at a private table that holds the prefix via the tun:

```
ip rule add to 192.168.88.0/24 priority 100 lookup 201
ip route add 192.168.88.0/24 dev orbit-prod table 201 proto 201
```

**Netfilter decides the failure case.** Routing changes — a new interface, DHCP,
somebody's `ip route add`. The kill switch is what makes "never" true:

```
-d 192.168.88.0/24 ! -o orbit-prod -j DROP
```

Traffic for that prefix leaves through the overlay or it does not leave.

### The exit-node form, and why nebula already has the hard part

For `0.0.0.0/0` this is exactly wg-quick's kill switch, and the mechanism is
worth naming because Orbit gets half of it free:

- WireGuard marks its own outer packets with `FwMark` so they are not routed
  back into the tunnel they carry. **Nebula's `so_mark` is the same knob**, which
  is why the config comments say it "supports `0.0.0.0/0` unsafe_routes".
- `ip rule ... not fwmark X lookup <table>` sends everything unmarked to the
  tunnel table.
- `ip rule table main suppress_prefixlength 0` is the elegant bit: the main
  table's *default* route stops matching while its more-specific routes still
  do. That is "allow LAN access" implemented correctly, for free, rather than as
  a special case.

So Orbit's exit-node shield is: set `so_mark`, add the rules above, add the
kill-switch DROP for anything unmarked leaving a non-tun interface.

### The lockout, which is the part to get right

**A shielded `0.0.0.0/0` can cut the machine off from the control plane.** If the
overlay is down, everything is dropped — including the agent's own HTTPS to the
public enrol URL, which is the one path that could deliver a fix. Nebula's own
UDP survives because of the mark; the agent's does not.

Orbit already has the concept for this at the policy layer: the **management
floor**, the reachability compiled policy may not remove
(`enroll.managementEndpoints`). Shield needs the same idea one layer down, and
the kill-switch rule must except:

- packets carrying nebula's `so_mark` — the tunnel itself,
- the control plane's public endpoint and its overlay replicas,
- loopback and link-local, or DHCP cannot renew and the machine loses its lease.

A shield that can lock a machine out of the only thing able to unlock it is not
a safety feature. This carve-out is not optional, and it is the reason shield is
worth designing rather than assembling from a blog post.

### Who accepts a shield

Not the same answer as exit nodes, and the difference is who the shield is
protecting *from*.

**A route's shield is not user-acceptable.** The case that motivates it —
"internal traffic must never take the local path, so nothing leaks" — protects
the organisation from a machine sitting on a network nobody vetted. The person
at that machine is the risk, not the beneficiary, and they are the one who would
switch it off: on the café LAN, the shield is inconvenient precisely when it is
working. Enforcement the target can disable is not enforcement.

**An exit node's shield is not separately acceptable either — it arrives with
the exit node.** The user already chose to send all their traffic through a
gateway; "or nothing" is what choosing a kill switch means. A second prompt
would let someone accept the exit node and decline the leak protection, which is
the one combination nobody should end up in by accident.

So neither is a separate acceptance. One is imposed, one is implied by a choice
already made.

**There is also no user to accept with.** Orbit has devices and memberships; the
credential model designs a user credential and does not build one
(`credential-model.md` §2). "Accepted by a user" today can only mean "accepted on
the machine", which is the exit-node mechanism — and for a leak control, the
machine is the wrong place to put the switch.

### Roaming breaks the pre-flight check

A first draft of this proposed reporting each machine's local subnets so an
operator could ask "does this shield collide with anything?" before applying it.
That works for a server in a rack and not at all for a laptop, which is most of
the fleet: its local subnet changes at every café, hotel and office. There is no
"before" to check, and the collision is not a possibility to assess but a
certainty to schedule — `192.168.1.0/24` is the most common home subnet in the
world and `192.168.0.0/24` the second, so a roaming machine meets one eventually.

Collision detection therefore has to be **continuous, not pre-flight**. The agent
reports the subnets it is currently attached to (a fact it does not carry today),
and the control plane can say *now* which machines are sitting on a network that
overlaps a shielded prefix. That is a support answer — "your printer stopped
working because this hotel uses your company's subnet" — rather than a planning
one.

### Shield is worth much more for the internet than for a route

The two cases look symmetric and are not.

**`0.0.0.0/0` defends against an accident that happens routinely.** A tunnel
flaps, and every packet silently falls back to the local network in the clear.
Nobody has to be attacking; it is the default behaviour of a routing table, and
it is why every commercial VPN ships a kill switch.

**A route's shield defends against a targeted attack.** For the leak to happen,
somebody has to control a network you join *and* have replicated your internal
prefix — an evil twin that knows your addressing. Real, but it requires an
adversary who has done homework, not a flaky link.

The failure modes are asymmetric in the opposite direction:

| | Value | Failure when it fires wrongly |
|---|---|---|
| `0.0.0.0/0` | High — stops a routine accident | No internet. Obvious, and the user knows why |
| A route prefix | Lower — stops a targeted attack | One subnet mysteriously unreachable. Confusing, hard to attribute |

So the useful one fails comprehensibly and the marginal one fails as a puzzle.

**Recommendation.** Build the mechanism once — it is the same policy routing and
netfilter either way — then:

- **Default it ON for `0.0.0.0/0`.** An exit node without a kill switch is a
  privacy feature with a hole in it, and the user already accepted the gateway.
- **Default it OFF for routes, and document it as narrow.** Its safety is
  proportional to how unusual the prefix is: shielding `10.53.0.0/16` is nearly
  free, shielding `192.168.1.0/24` is a trap that springs at a random hotel. If
  a network intends to shield its internal prefixes, that is a reason to pick
  unusual RFC1918 space at bootstrap — which is advice worth giving *before* the
  first network exists, since a network's CIDRs are not easily changed either.

Break-glass stays a control-plane action on one membership, for the reason
above: the escape hatch belongs on the side that can see the fleet.

### Shape

```sql
ALTER TABLE orbit.route ADD COLUMN shield boolean NOT NULL DEFAULT false;
```

Per route, like `masquerade` — a LAN prefix might be shielded while a second
route on the same gateway is not, and `0.0.0.0/0` is the case that most wants
it and most needs the carve-out.

---

## 8. What is built

Routes, exit nodes and the gateway host-state layer. Shield is not.

```bash
# The CA must permit it, and this is the only time it can be decided.
orbitd bootstrap --network prod --cidr 10.42.0.0/16 \
    --unsafe-networks 192.168.88.0/24

# Then, per gateway:
orbit route add lab-pi 192.168.88.0/24
orbit route add spare-pi 192.168.88.0/24 --weight 5   # redundancy, that is all
orbit route ls lab-pi
orbit route rm <uuid>
```

| Piece | Where |
|---|---|
| `orbit.route`, CA `unsafe_networks` | migration 0024 |
| Storage and grouping | `internal/store/route.go` |
| Prefixes into the certificate | `enroll.issueAndRender` → `ca.HostParams` |
| `tun.unsafe_routes` render | `nebulacfg.renderRoutes`, grouped by `enroll.routesFor` |
| Routed subnets into policy | `store.PolicyFleet` → `policy.Membership.UnsafeNetworks` |
| API | `GET/POST /v1/memberships/{id}/routes`, `DELETE /v1/routes/{id}` |
| Exit-node opt-in | migration 0025, `GET/PUT /v1/memberships/{id}/exit-node` |
| Gateway forwarding and NAT | `internal/agent/hoststate*.go`, nftables table `inet orbit` |
| Agent instructions in the signed config | `nebulacfg.orbitSection`, read by `agent.HostStateFromConfig` |

Three properties are pinned by tests, because each fails silently otherwise:

- **A peer's config names the prefix and the gateway** — the route reaches
  somebody.
- **Two gateways for one prefix render as ONE entry with two `via`.** Two
  entries would be accepted by nebula and treated as a single path, losing the
  redundancy that motivated the second gateway, and looking correct.
- **A prefix outside the CA's constraint is refused at issuance.** Not rendered
  and ignored — refused, with a message naming the CA.

The gateway is not given a route to its own prefix. It reaches that on a real
interface, and an `unsafe_route` naming itself is a loop.

### Exit nodes

```bash
orbit route add lab-pi 0.0.0.0/0 --masquerade   # the gateway offers it
orbit exit-node ls laptop                       # what is on offer
orbit exit-node use laptop <route-uuid>         # this machine chooses it
orbit exit-node off laptop
```

**A default route reaches only the machine that chose it**, which is the
property that separates it from an ordinary route and the one that fails
expensively — rendering every `0.0.0.0/0` to everybody would move a fleet's
internet traffic through whichever gateway was added most recently, visible a
week later as a latency complaint nobody can attribute.

The choice is a control-plane call, not a local edit. The agent runs only what
the control plane signed, so `orbit exit-node use` PATCHes the membership and
the route arrives in the next signed configuration. Local command, central
authority.

`so_mark` is emitted only for a host with a default route. Without it, nebula's
own UDP matches the default route it just installed and the tunnel carries the
packet that carries the tunnel.

**Linux only, for the machine USING it.** `SO_MARK` is implemented in nebula's
`udp_linux.go` and has no darwin equivalent, so a Mac can consume ordinary
routes — nebula installs those itself — but not a default one.

### The host-state layer

A gateway needs two things nebula does not do: IP forwarding, and NAT. Both are
carried in the **same signed document** as the configuration, under an `orbit:`
key nebula ignores — so instructions to change a machine's firewall arrive with
the same proof as its certificate paths and cannot be substituted separately.

Ownership is the whole design, and it is one nftables table:

```
nft destroy table inet orbit
```

Verified on real Linux rather than asserted: the table applies, re-applies
cleanly, and — after somebody else adds a rule and a chain to it — is still
removed entirely by that one command, while an unrelated `inet notorbit` table
survives untouched.

It is **reconciled every cycle**, not applied once. Firewall rules live where
other things also write: somebody flushes nftables, a package upgrade reloads a
ruleset. Applying once and trusting it would leave a gateway the control plane
believes is forwarding and that silently is not. `orbit leave`
destroys the table by name, needing no memory of what was in it.

IP forwarding is enabled and deliberately **not** disabled on uninstall —
something else on the machine may want it, and a container runtime almost
certainly does.

---

## 9. Order of the rest

1. The UI, which has no route surface yet.
2. Shield: the nftables table, the `proto` number, the reconcile
   loop, and a test that uninstall leaves nothing behind. Before any rule is
   written in anger.
3. A Mac path for default routes, if it is ever wanted: nebula has no SO_MARK
   on darwin, so it needs the wg-quick approach of pinning the lighthouse
   endpoints to the physical gateway with host routes.

Access control needed no step and already works: `dst: [cidr:192.168.88.0/24]`
in a policy document compiles, and the compiler emits the `local_cidr` that
makes it bite on the gateway.
