# ADR-0019: No dynamic app connectors; route sets instead

**Status:** Proposed
**Date:** 2026-08-12

## Context

An "app connector" routes traffic for a named *domain* — `github.com`, an S3 bucket, a SaaS
console — through a designated node, so that the service sees a stable egress address. The
appeal is obvious for a self-hosted mesh: it is the feature that turns a gateway from "a subnet
router" into "the way this organisation reaches a third party".

The Tailscale checkout contains **two** implementations of it, and the relationship between
them is the most useful fact available to us.

**The original design (`appc/`)** designates a node with `--advertise-connector`, takes a list
of domains from control, and learns addresses by *observing DNS responses*: clients are pointed
at the connector's PeerAPI DoH endpoint by split DNS, the connector forwards the query upstream,
parses the answer, flattens CNAME chains, and emits a **/32 or /128** for every address it has
not seen before (`appc/observe.go:20-132`). Each discovered address becomes an ordinary
advertised route via `EditPrefs` on `AdvertiseRoutes` (`ipn/ipnlocal/local.go:8508-8544`).

Two properties of that design matter here. First, **there is no aging**. A search of `appc/`
for expire, ttl, prune or evict returns nothing; routes leave only when the domain is removed
from configuration. The discovered set grows monotonically for the life of the connector.
Second, Tailscale instrumented it for the resulting write rate with histogram buckets reaching
**1000 route-store events per minute** (`appc/appconnector.go:84-85`), and `wgengine/userspace.go:347-359`
records the wall they hit: Android throws `TransactionTooLargeException` above roughly 4000
routes, iOS has a 50 MB extension memory ceiling.

**The current design (`feature/conn25/`)** exists because of that. Its package comment
(`feature/conn25/conn25.go:4-7`) says so directly: it "will be an app connector like feature
that routes traffic for configured domains via connector devices and **avoids the 'too many
routes' pitfall of app connector**." conn25 publishes no discovered addresses to the control
plane at all. Control pushes fixed magic and transit pools; the client resolves through the
connector, rewrites the answer to a client-local magic address before the application sees it,
and tells the connector peer-to-peer which transit address means which real one. Transit /32s
go into WireGuard's `AllowedIPs` and never into the OS route table
(`ipn/ipnlocal/local.go:6140-6147`). Mappings are leased off the DNS TTL, clamped to
[1m, 72h].

So the reference implementation shipped the DNS-observation design, ran it, measured it, and
built a second one to replace it.

**Orbit's version of the first design would be strictly worse, for structural reasons.**

Tailscale's discovered /32s land in a mutable in-memory netmap. Orbit's would land in two
signed artefacts. Routes are compiled into the device certificate's `UnsafeNetworks` and into
`tun.unsafe_routes` in the signed full generation. `CreateRoute` and `DeleteRoute` each call
`touchRoutes` **and** `BumpEpoch(ctx, networkID, EpochConfig)` for the whole network
(`internal/store/route.go:64-67`, `:89-92`), and `certStale` then forces the connector's
immediate renewal (`internal/enroll/service.go:537-539`). One discovered address is therefore
**one certificate reissue and one fleet-wide epoch bump** — where the fleet's entire baseline
issuance rate is N certificates per `cert_ttl`/2, with `cert_ttl` defaulting to 24 hours
(`internal/db/migrations/0001_initial.sql:122`). A connector discovering one address a minute
generates, from a single machine, several times the issuance load of the whole network, and per
ADR-0011 each bump re-renders and re-applies a complete generation on every host.

**And the obvious escape does not exist.** It is tempting to install `unsafe_routes` locally and
skip the certificate — nebula parses them with no reference to the local certificate
(`third_party/nebula/overlay/route.go:149-152`) and hot-reloads them on SIGHUP. But
`UnsafeNetworks` is enforced per packet on the *remote* side: `Firewall.Drop` looks the inner
source address up in the peer's certificate-derived network table and returns
`ErrInvalidRemoteIP` when it misses (`third_party/nebula/firewall.go:433-438`). That check sits
**before** the conntrack fast path at `firewall.go:462`, so an established flow cannot bypass
it. A route installed without a matching certificate is a route that silently blackholes: the
packets leave, and the replies are dropped by the client. Verified by reading both sites, not
inferred.

This also runs directly against ADR-0012, whose thesis is that policy compiles to addresses
rather than into certificates, precisely so that the fastest-changing set in the system is not
the one requiring reissue. An app connector would put the fastest-changing set of all into the
certificate.

## Decision

**Orbit does not build dynamic, DNS-observing app connectors.**

It builds **route sets**: a named collection of prefixes attached to a membership, created or
replaced in **one** transaction with **one** `touchRoutes` and **one** `BumpEpoch`, and an
importer that fetches published provider ranges — AWS `ip-ranges.json`, GitHub `/meta`,
Cloudflare, Azure, Google — and diffs them against the set. Tailscale's equivalent importer is
`cmd/connector-gen/`, four short files.

This is not a new concept in Orbit. `orbit route add` already routes an operator-known prefix
through a chosen gateway. What is missing is *bulk*: today each prefix is one API call and one
fleet-wide epoch bump, so importing a provider's published list would be thousands of
generation applies. Route sets make the operation's cost proportional to the number of
*refreshes*, not the number of prefixes — days rather than seconds between changes.

The domains that only a DNS observer can serve — anything behind a shared CDN edge, anything
with no published range list — are **not served**, and the documentation says so rather than
leaving an operator to discover it.

## Alternatives considered

**Port the `appc/` design: observe DNS, publish /32s.** Rejected on Orbit's cost model above,
but the decisive argument is not ours: Tailscale built it, instrumented it for a thousand route
writes a minute, hit platform route limits, and replaced it. Adopting a design its author
abandoned, in a system that makes it more expensive rather than less, would need an argument we
do not have. It would additionally require an aging policy Tailscale never wrote — the
monotonic growth is unaddressed in `appc/` — and it may be forbidden outright by the CA: an
issuer scoped to the operator's own ranges cannot sign a public-internet /32
(`internal/ca/ca.go:317`), and widening that means rotating the CA.

**Port the conn25 design: magic and transit addresses, double NAT.** Rejected as enormous. It
needs a peer-to-peer API between agents (Orbit has none — the agent's only local surfaces are a
read-only unix socket and a DNS listener), a userspace packet datapath doing double NAT, flow
tables, address-pool allocation and lease expiry. ADR-0001 has Orbit consuming nebula as a
config-file-driven library, with no packet-level hooks at all. This is "write a second data
plane", and it is worth recording in the ADR precisely because it is what Tailscale had to
build to make the feature work.

**Do nothing at all — `orbit route add` plus ADR-0016's exit route already covers the
operator-known case.** Defensible, and it is very nearly the decision taken here. Rejected only
because the bulk-import gap is real and cheap to close: without it, the supported path for
"route this provider through that gateway" is several thousand epoch bumps, which is a
non-answer.

## Consequences

Operators get a supported way to route named third-party services through a gateway, for every
provider that publishes its ranges — which is most of the ones people ask about. They do not
get it for anything behind a shared CDN edge, and the honest reason is that the only way to
serve that case is to route the entire edge, which drags every unrelated site on it through the
gateway too. That is an availability and a privacy cost, not a missing feature.

Route sets introduce the first Orbit operation whose cost is deliberately decoupled from the
number of objects it touches. That is a good pattern and it is also a new invariant to hold: a
bulk path that accidentally bumps the epoch per row is indistinguishable from the current
behaviour until someone imports a large list.

We are committed to the position that anything entering a certificate changes at
certificate speed. If a future feature wants a fast-changing set, the answer is ADR-0012's —
compile it to addresses in the generation, not into the certificate — and if that is not
possible, the feature does not fit this architecture.

What would trigger revisiting: nebula gaining per-packet authorisation that is not derived from
the certificate's `UnsafeNetworks`. That single change is what makes the whole family of
dynamic-route features affordable, and without it none of them are.

## References

- `feature/conn25/conn25.go:4-7` — the "too many routes" pitfall, in Tailscale's own words
- `appc/observe.go:20-132` — DNS response observation; `appc/appconnector.go:84-85` — the metric buckets
- `wgengine/userspace.go:347-359` — the Android and iOS route limits
- `ipn/ipnlocal/local.go:6140-6147` — conn25's transit routes staying out of the OS route table
- `third_party/nebula/firewall.go:433-438, 462` — `ErrInvalidRemoteIP`, checked before conntrack
- `third_party/nebula/overlay/route.go:149-152` — `unsafe_routes` parsed without reference to the cert
- `internal/store/route.go:64-67, 89-92` — one epoch bump per route
- `internal/enroll/service.go:537-539` — `certStale` forcing immediate renewal
- `internal/db/migrations/0001_initial.sql:122` — `cert_ttl` default of 24h
- `internal/ca/ca.go:317` — the issuer's `UnsafeNetworks` containment check
- ADR-0011 (full generations, not deltas), ADR-0012 (policy compiles to addresses), ADR-0016
