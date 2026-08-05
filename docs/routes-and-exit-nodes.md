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

## 6. Order of work

1. `orbit.route` and the CA default, together — the second gates the first and
   is permanent, so it is not a thing to leave until the feature works.
2. Enrollment carries the gateway's prefixes into `HostParams.UnsafeNetworks`,
   and `policy.Membership.UnsafeNetworks` stops being empty. The compiler
   already does the rest.
3. `nebulacfg` renders `tun.unsafe_routes`, grouping rows by prefix so multiple
   gateways become one entry with weighted `via` list.
4. API, CLI and UI for offering and revoking a route.
5. Exit nodes: `0.0.0.0/0`, the opt-in call, `ip_forward`, `so_mark`, and the
   masquerade rule. Host surgery, and it belongs behind a route feature that
   already works rather than in front of it.

Access control needs no step. It already works.
