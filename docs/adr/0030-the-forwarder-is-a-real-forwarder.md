# ADR-0030: The forwarder is a real forwarder

**Status:** Accepted
**Date:** 2026-08-12

## Context

Everything the agent's resolver does not answer locally, it forwards. The whole of that path is
twenty lines (`internal/agent/hostcfg/dns.go:344-364`):

```go
c := &dns.Client{Timeout: 4 * time.Second}
for _, server := range up {
    resp, _, err := c.Exchange(req, server)
    if err == nil && resp != nil {
        _ = w.WriteMsg(resp)
        return
    }
}
```

Four properties of that fall out, and each is a way for a name to fail to resolve on a machine
whose DNS Orbit has taken over.

**It is UDP only, and there is no escape.** `dns.Client` with `Net` unset defaults to `"udp"`,
and miekg/dns documents plainly that `Exchange` "does not retry a failed query, nor will it fall
back to TCP in case of truncation", and that "messages without an OPT RR will fallback to the
historic limit of 512 bytes". The client's original message is relayed, so a client that sent no
EDNS0 gets a 512-byte buffer. The dead end is that Orbit's **TCP** listener forwards over UDP
too: a well-behaved client that sees TC and escalates to TCP receives the same truncated answer,
with nowhere left to go.

**Upstreams are tried in order, and any answer wins.** The loop accepts on `err == nil && resp
!= nil` — regardless of rcode. A SERVFAIL or REFUSED from the first upstream is relayed to the
client and the second is never consulted. Three dead upstreams cost twelve seconds of client
wall time. Tailscale fans out concurrently with staggered delays and treats REFUSED/SERVFAIL as
*soft* errors so a slower resolver can still answer (`net/dns/resolver/forwarder.go:764-777`).

**Upstreams are captured once per process and never re-read.** `if len(r.upstream) == 0 {
r.upstream = systemResolvers() }` (`dns.go:216-218`), and `Stop()` deliberately preserves them.
The capture-once design exists to defeat the forwarding loop of ADR-0013, and it pays for that
with never noticing a network change: a laptop that captured `192.168.1.1` at home forwards
there in the café until the agent process restarts.

**Nothing is ever re-asserted.** `Apply`'s first branch compares the config string against
`r.current` and returns early after swapping the name table; the listener is rebound and
`applyDNS` re-run only on the changed path (`dns.go:187-195`, `:223-236`). So when nebula
restarts — destroying and recreating the tun, and with it every `resolvectl` setting, which
hangs off that link — the config string is unchanged, `Apply` returns early, and the machine
silently stops being pointed at its resolver until the config epoch moves. This contradicts the
principle stated two files away: `configcheck.go:176-179`, "repair and confirm are the same
operation", and `loop.go:667-668`, host rules "have to be re-asserted rather than assumed". Host
state re-applies wholesale every cycle. DNS opted out.

Two smaller ones in the same family: the authoritative path never copies or synthesises an OPT
RR, never calls `Truncate`, and never sets TC — while the comment justifying the TCP listener
gives TC-then-TCP as the reason it exists. And there is no cache of any kind, positive or
negative, and no SOA, so downstream caches have no negative TTL to honour.

One thing that is already right and should not be regressed: a known name with no address of the
queried family returns NOERROR with an empty answer, and `dns_test.go:106-108` pins it. That is
the same rule Tailscale applies, and it is the correct one.

## Decision

**Upstreams are queried concurrently, with soft-error failover.** A REFUSED or SERVFAIL from one
upstream does not end the query. The first *usable* answer wins, not the first response.

**Truncation escalates.** The forwarder retries over TCP when an answer comes back truncated,
and the authoritative path sets TC and truncates rather than emitting an oversized datagram. The
TCP listener stops being decoration.

**Upstreams are re-read when the machine's network changes**, subject to the ADR-0013 guard that
rejects loopback and any address this process serves. Capture-once was the right answer to the
loop and the wrong answer to roaming; the guard is what makes re-reading safe.

**DNS host state is re-asserted every cycle, like every other host object.** `Apply` stops
early-returning on an unchanged config: the listener and the OS interception are confirmed each
pass, because confirming and repairing are the same operation.

These are one decision, not four. The current forwarder is a demo of the shape of a forwarder;
each property above is what separates that from something a machine's entire name resolution can
depend on — which is exactly what ADR-0013's `~.` makes it.

## Alternatives considered

**Add a cache.** Deliberately excluded from this decision. It is the most visible improvement and
the least urgent: every gap above is a name that *fails to resolve*, and a cache addresses none
of them. It also introduces a TTL-honouring invalidation problem that interacts with the 60s
hardcoded TTL on mesh answers. Worth its own decision, later.

**Keep capture-once and require a restart after a network change.** Rejected: `Restart=always`
means the agent does not restart on a network change, and the failure — every public name
failing to resolve after moving networks — is indistinguishable to the user from the mesh being
broken.

**Do not run a forwarder at all: answer mesh names and return REFUSED for everything else,
letting the OS fall through to its other resolvers.** Genuinely attractive, and it deletes this
entire ADR. Rejected because Linux's `~.` makes Orbit the resolver of last resort for
everything, so there is nothing to fall through *to* — and fixing that is ADR-0013's split-DNS
decision, which is not yet implemented. If split DNS lands first, this alternative becomes worth
reopening: a resolver that only ever answers for its own suffix does not need a forwarder.

## Consequences

Concurrent upstream queries mean the machine's real resolvers see more traffic than they do
today — up to N queries where there was one — for the failure cases. Tailscale's staggering is
the mitigation and it is worth copying rather than reinventing.

Re-asserting every cycle means `resolvectl` and `scutil` are invoked once a minute per network on
every managed host, where today they are invoked on change. That is a real cost, and it is the
same cost host state already pays for the same reason.

We become committed to the resolver being a dependency of the machine's name resolution rather
than an accessory to it — which is already true in practice and is currently not reflected in how
the code is written or tested.

What would trigger revisiting: split DNS landing, per ADR-0013. If Orbit stops being the resolver
of last resort, the forwarder's failure modes stop being total, and the "do not forward at all"
alternative becomes the simpler answer.

## References

- `internal/agent/hostcfg/dns.go:344-364` — the forwarder; `:216-218, 291-292` — capture-once
- `internal/agent/hostcfg/dns.go:187-195, 223-236` — the early return that skips re-assertion
- `internal/agent/hostcfg/dns.go:257-259` — the TCP listener's stated justification
- `internal/agent/configcheck.go:176-179`, `internal/agent/loop.go:667-668` — the principle DNS opted out of
- `internal/agent/hostcfg/dns_test.go:106-108` — the NODATA behaviour worth protecting
- Tailscale `net/dns/resolver/forwarder.go:106-112, 677-738, 764-777` — races, TCP retry, soft errors
- ADR-0013 (the resolver is restored, not only set), ADR-0029 (authoritative for its own domain)
