# ADR-0029: The resolver is authoritative for its own domain, and answers nowhere else

**Status:** Accepted
**Date:** 2026-08-12

## Context

The agent's resolver answers mesh names from a table built out of the rendered generation and
forwards everything else. `DNSStateFromConfig` builds that table with two keys per host
(`internal/agent/hostcfg/dns.go:151-153`):

```go
d.Hosts[name+"."] = addrs
if d.Domain != "" {
    d.Hosts[name+"."+d.Domain+"."] = addrs
}
```

`ServeDNS` consults the table before forwarding and sets `m.Authoritative = true`. The
membership name is free text: non-empty, trimmed, at most 253 bytes
(`internal/enroll/join.go:52-54`), stored in a bare `name text NOT NULL` column with no CHECK —
notably unlike `tun_dev`, which has a charset regex.

Four consequences follow, and all four are the same mistake in different directions.

**A mesh name can shadow any public name.** A host named `login.microsoftonline.com` produces
the table key `login.microsoftonline.com.` and is answered authoritatively, ahead of any
upstream. On Linux that reaches every query on the machine, because `~.` is set unconditionally
(ADR-0013); on an exit node it reaches every query by design. The operator who creates the
membership need not be the operator who trusts the machine.

**Bare single-label names are minted into the DNS root.** `name+"."` is an absolute name at the
root. The comment above it is a good argument for the goal — "a name that resolves only through
[a search list] is a name that stops working for reasons nobody can see" — and reaches for the
wrong mechanism: Orbit answers for a namespace it does not own. Tailscale gets the same
ergonomics by pushing a search domain to the OS and never synthesising short names.

**A miss inside the mesh domain is forwarded to the public internet.** A table miss forwards
unconditionally; there is no concept of authority for `<slug>.internal`. Every typo, every
search-list permutation (`laptop.lab.internal.lab.internal.`), and every stale internal hostname
goes to the machine's upstream — which is the operator's ISP or corporate resolver. The network
slug and the internal host inventory leak. Tailscale returns NXDOMAIN for a suffix it owns
rather than forwarding (`net/dns/resolver/tsdns.go:770-777`).

**There is no PTR.** Anything that is not A or AAAA is forwarded, so `dig -x 10.42.0.9` leaves
the machine. There is no reverse mapping for the mesh at all.

And in the other direction, **nothing checks what upstreams answer**. `forward` relays the
response verbatim, so a public name may resolve into the overlay prefix and be treated by a
browser as a local-network host. There is no rebinding protection in either direction.

## Decision

**The resolver is authoritative for `<slug>.internal` and answers only inside it.**

Concretely: mesh names are constrained at the API to a single DNS label matching a hostname
charset, and are published only under the mesh domain. The bare-label key is removed, and short
names are made to work the way they are meant to — by pushing `<slug>.internal` as a search
domain, which the platform appliers already have the mechanism for. A miss *inside*
`<slug>.internal` is NXDOMAIN, not a forward. PTR for the network's own CIDRs is answered
locally rather than forwarded.

**An upstream answer pointing into the network's own CIDRs is rejected.** That is the rebinding
guard, and it is cheap because the renderer already knows the network's prefixes.

A single property covers the first four of those: *the resolver never answers for a name outside
its own suffix, and never forwards a name inside it.* That is the sentence worth holding onto.

## Alternatives considered

**Keep the bare-label key and validate names harder.** Validation alone closes the shadowing
hole — a single label cannot contain a dot, so `login.microsoftonline.com` becomes
unregisterable. Rejected as insufficient: single-label names in the root are still a namespace
Orbit does not own, and ICANN has shipped new gTLDs that collided with exactly this pattern.
Validation is part of the decision; it is not the whole of it.

**Forward misses inside the mesh domain, as today, and accept the leak.** Rejected: the leak is
the network's own topology, sent to a third party, on every typo. The cost of the alternative is
one comparison.

**Answer PTR by forwarding to the control plane.** Rejected — the mapping is already in the
rendered generation, which is the same source the forward table comes from. There is no reason
for a round trip.

**Add rebinding protection as a separate later decision.** Rejected as an artificial split: the
guard needs the network's prefixes, and the authority check needs the network's suffix, and both
arrive at the resolver by the same path.

## Consequences

Short names stop working on any machine whose search list Orbit cannot set — which is every
platform other than Linux and macOS, and macOS only for the one domain it writes. That is a real
regression against the current behaviour and it is the cost of not squatting the root. The
comment being replaced is right that search lists are fragile; the answer is to make Orbit's
search-domain push reliable, not to route around it.

NXDOMAIN inside the mesh domain means a host that has not yet appeared in a generation resolves
as definitively absent rather than as "ask upstream". During enrolment that is a window where a
name is authoritatively wrong rather than merely unknown, which is the correct trade but is
worth stating.

Name validation is a breaking change for any existing membership whose name contains a dot. That
needs a migration path — reject at creation, tolerate on read — and it interacts with ADR-0022's
observation that there is no rename operation at all.

What would trigger revisiting: multiple mesh domains on one host. The authority rule is written
for one suffix per resolver, and a host in two networks runs two resolvers with two suffixes —
which is ADR-0020's territory and where the interaction needs checking.

## References

- `internal/agent/hostcfg/dns.go:146-153` — both keys, and the argument for the bare one
- `internal/agent/hostcfg/dns.go:301-341` — the table consulted before the forwarder
- `internal/enroll/join.go:52-54` — the whole of name validation
- Tailscale `net/dns/resolver/tsdns.go:770-777` — NXDOMAIN for an owned suffix
- Tailscale `ipn/ipnlocal/node_backend.go:1508-1512, 1549-1554` — names under a suffix, search domains
- ADR-0013 (the resolver is restored, not only set), ADR-0020 (one network owns the host)
