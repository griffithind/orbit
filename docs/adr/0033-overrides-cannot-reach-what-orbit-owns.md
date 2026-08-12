# ADR-0033: Overrides cannot reach what Orbit owns

**Status:** Accepted
**Date:** 2026-08-12

## Context

`config_overrides` lets an operator set nebula keys Orbit does not render. It is a deliberate
escape hatch, and it has a deny-list: `protectedOverrides`
(`internal/nebulacfg/overrides.go:57-69`) refuses eleven keys, each with a reason. The reasons
are good ones — `pki` because "an override here can silently stop a host honouring revocations";
`static_host_map` because "Orbit owns the topology"; `listen.port` and `tun.dev` because they are
allocated per host so two nebula processes do not collide.

The list is a deny-list, and three things Orbit equally owns are not on it.

**`orbit` is not protected.** The `orbit` section carries the rendered DNS state — the mesh name
table and the resolver's listen address (`internal/nebulacfg/render.go:804-822`) — plus the exit
node and forwarding flags. Overrides are merged last into the rendered YAML and the result is
*then* signed, so the agent's signature check provides no protection: the control plane vouches
for the injected values. Anyone who can set `config_overrides` on a membership or a network can
rewrite `orbit.dns.hosts`, minting arbitrary name-to-address mappings — and, per ADR-0029's
finding that names are unvalidated free text, mappings for public names — or move
`orbit.dns.listen`.

**`lighthouse.serve_dns` and `lighthouse.dns.*` are not protected.** They stand up nebula's own
hostmap-backed DNS server, whose listen host defaults to the empty string
(`third_party/nebula/dns_server.go:452`), which is every interface. An override can therefore
start a second, unmanaged DNS server on a managed host, bound publicly, answering from nebula's
hostmap.

**`listen.host` is not protected and is not reachable any other way.** `renderFor` never sets
`Input.ListenHost`, so the default `"::"` always applies; there is no per-host or per-network
field. So the only lever an operator has over the listen address is the override — while
`listen.port`, the key directly beside it, is protected on the argument that it is "allocated per
host and network". Both halves of the same socket, opposite treatment, and the unprotected half
is the one with no supported alternative.

The pattern is the same in each case: the deny-list was written against the keys that existed
when it was written, and the render has grown since. `orbit` is Orbit's own section — the one
part of the file that is definitionally not nebula's — and it is the one section an override can
rewrite wholesale.

## Decision

**The override filter becomes an allow-list of what an override may reach, rather than a
deny-list of what it may not.**

Everything Orbit renders is Orbit's, and is refused. Everything else — nebula keys Orbit does not
set, which is the case the escape hatch exists for — is permitted. The check is derived from the
render rather than maintained beside it: the set of top-level keys and dotted paths the renderer
emits is computable, and a key an override sets that the renderer also sets is refused with a
message naming the field that owns it.

Where the escape hatch is currently the only way to set something Orbit owns — `listen.host`
today — that becomes a first-class field rather than an exception to the rule. An override that
is the supported path for a rendered key means the rule has a hole shaped exactly like the thing
it is protecting.

**One deliberate exception, recorded rather than discovered: `punchy`.** Orbit renders `punch`
and `respond` — the booleans that turn hole punching on — and ADR-0032 adds considered defaults
for the timings. The timings are nonetheless exactly what a host behind a pathological NAT needs
tuned, which is what the escape hatch exists for, and
`TestOverridesCannotReachOrbitOwnedKeys` has asserted since before either ADR that
`punchy: {delay: 2s}` must keep working. The rule is "everything Orbit renders is Orbit's"
*except* where a rendered value is a default rather than a policy; `punchy` is the only such
section today, and the test that enforces the rule names it in prose so the exception cannot
become a habit.

Implementing this immediately turned up two more sections the ADR had not enumerated — `punchy`
above, and `logging`, which is open for the obvious reason. That is the mechanism working: the
list had been outgrown three times, not twice.

## Alternatives considered

**Add `orbit`, `lighthouse.serve_dns`, `lighthouse.dns` and `listen.host` to the deny-list.**
Three lines, and it closes today's holes. Rejected as the decision, though it is the immediate
fix: the deny-list has now been outgrown twice by the renderer, and a mechanism that must be
updated whenever an unrelated file grows a field will be outgrown again. It is worth landing
first and superseding second.

**Sign the pre-override render and have the agent verify overrides separately.** Rejected as
solving a different problem. The agent's signature check is not the weak point — the control
plane is a trusted signer by construction (ADR-0002), and the concern here is an operator with
`memberships:write` reaching further than that scope implies, not a forged config.

**Remove `config_overrides` entirely.** Rejected: nebula has a large surface Orbit does not
render, and an escape hatch for the keys Orbit has no opinion about is what keeps the render
short and reviewable (`render.go:574-578`).

**Scope overrides by token scope — require a higher privilege to set them.** Complementary rather
than alternative, and probably worth doing too. It does not remove the need to know which keys
are Orbit's.

## Consequences

An allow-list derived from the renderer means adding a field to the render automatically removes
it from the override surface. That is the property worth having, and it is also a compatibility
hazard: a deployment using an override for a key Orbit later starts rendering will find that
override refused on upgrade. Under ADR-0005 that is acceptable before v1 and would need a
migration note after it.

Computing the rendered key set is a real piece of work — the render is a struct tree with
`omitempty` throughout, so "what does the renderer emit" is not simply "what fields exist". A
structural test over the render's YAML tags is the tractable form, in the same family as the
existing AST tests.

We become committed to `listen.host` and anything else in its position being a modelled field. If
a key is worth setting and Orbit renders its neighbours, Orbit renders it.

What would trigger revisiting: the override surface shrinking to nothing as the render grows. At
that point the escape hatch is dead weight and should be removed rather than maintained.

## References

- `internal/nebulacfg/overrides.go:57-69` — the deny-list and its eleven reasons
- `internal/nebulacfg/render.go:804-822` — the `orbit` section an override can rewrite
- `internal/nebulacfg/render.go:591-594` — `ListenHost` defaulting, with no control-plane field
- `third_party/nebula/dns_server.go:452` — the empty default listen host
- `internal/nebulacfg/render.go:574-578` — why the render stays short, and why the hatch exists
- ADR-0002 (fail static), ADR-0005 (no compatibility before v1), ADR-0029 (resolver authority)
