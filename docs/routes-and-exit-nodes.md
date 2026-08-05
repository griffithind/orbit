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

## 4. A shape for Orbit

Routes are a **membership** fact — this machine, in this network, routes these
prefixes — which puts them beside `is_lighthouse` and `is_relay`, not on the
device. A laptop that routes a lab subnet on one network routes nothing on
another.

```
membership.routes           text[]   -- prefixes this membership offers
membership.route_metric     int      -- lower wins; NetBird's model
membership.is_exit_node     boolean  -- sugar for routes containing 0.0.0.0/0
```

**Two-sided consent, taken from Tailscale**, because it is right: the machine
*offers* (it is the one that knows what it is plugged into), the control plane
*approves* (it is the one that knows what should be reachable). Orbit already
has both halves — a reservation can carry the offer, `orbit membership set`
approves — and the reservation path means an unattended gateway can be
provisioned in one step, which is the §26 pattern again.

**Consumers get the route through policy, not fleet-wide.** NetBird's
distribution groups by another name. Orbit's policy document already selects by
role and tag; a `routes:` stanza naming which roles may use which gateway falls
out of the existing compiler, and the compiler already knows to emit
`local_cidr` so the rules actually bite.

**Failover is free.** Nebula's weighted ECMP means two gateways offering the
same prefix is HA with no extra machinery — and it is strictly better than the
thing Tailscale documents as a limitation.

**Exit nodes** are the same feature with three additions the agent must own:
`ip_forward`, a `MASQUERADE` rule, and `so_mark`. Masquerade on by default, as
NetBird does — the alternative needs return routes in somebody else's network,
which is not a thing a mesh can arrange for you.

---

## 5. The decisions, and one is time-sensitive

**1. The CA constraint, which must be decided before a network is bootstrapped.**

A CA's `UnsafeNetworks` cannot be widened after the fact — it is signed. A
network bootstrapped today permits no routes at all, and enabling them later
means a **CA rotation**. Rotation is supported and rehearsed (`design.md` §6),
so this is a cost, not a wall. But it is the same shape as the curve decision:
permanent, invisible until it bites.

Three options:

- *Nothing* (today). Routes require a rotation. Honest, and annoying.
- *RFC1918 by default* — `10/8`, `172.16/12`, `192.168/16`. Covers essentially
  every "raspberry pi in front of a lab" case without granting the internet.
- *`0.0.0.0/0`* — permits exit nodes, and also permits any signed host to claim
  authority over every destination. Too wide as a default.

RFC1918 as the default with a bootstrap flag to widen looks right: it makes the
common case work with no rotation, and keeps exit nodes an explicit decision.

**2. Masquerade default.** On, following NetBird — with the caveat documented,
since it hides source addresses from whatever is on the far side.

**3. Does a route need a certificate reissue?** Yes, and that is the trade.
Changing which prefixes a gateway offers means a new certificate. Orbit reissues
on epoch already, so this is seconds — but it is not the instant database toggle
Tailscale has, and the docs should say so rather than let someone discover it.

**4. LAN access while using an exit node.** Tailscale loses it by default and
has a flag. Orbit should decide deliberately rather than inherit whatever
`0.0.0.0/0` does.

---

## 6. Where to start

1. `membership.routes` + the enrollment path into `HostParams.UnsafeNetworks`.
2. `nebulacfg` renders `tun.unsafe_routes` from the topology query.
3. The CA default decision above, since it gates everything and is permanent.
4. Policy `routes:` stanza — the compiler is already waiting for it.
5. Exit nodes last: forwarding, NAT and `so_mark` are host surgery and belong
   behind a working route feature, not in front of it.
