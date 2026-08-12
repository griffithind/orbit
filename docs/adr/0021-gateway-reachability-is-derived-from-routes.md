# ADR-0021: A gateway's inbound reachability is derived from its routes

**Status:** Accepted
**Date:** 2026-08-12

## Context

Nebula's firewall matches an inbound packet against the *local* address it is destined for, not
only the remote address it came from. `firewallLocalCIDR.addRule`
(`third_party/nebula/firewall.go:893-918`) decides what an omitted `local_cidr` means, and the
answer depends on the host's own certificate:

```go
if localCidr == "" {
    if len(f.unsafeNetworks) == 0 || f.defaultLocalCIDRAny {
        flc.Any = true
        return nil
    }
    for _, network := range f.assignedNetworks {
        flc.LocalCIDR.Insert(network)
    }
    return nil
}
```

So an empty `local_cidr` means "any address" on a host with **no** unsafe networks, and "only my
own overlay addresses" on a host that has them. Nebula's changelog records this as a deliberate
change of default. Orbit never sets `firewall.default_local_cidr_any` — the string appears in
this repository only in comments, a test, a doc paragraph, and nebula's own source.

Orbit puts a gateway's routes into that gateway's certificate. `internal/enroll/service.go:660`
issues with `UnsafeNetworks: store.RoutePrefixes(routes)`, and the comment above it explains
why: "nebula requires the gateway's certificate to carry the prefix".

Those two facts compose into a defect with an unusually cruel shape. A host becomes a gateway,
forwarding works, and then its **next certificate** — issued minutes to hours later, because
`certStale` forces renewal on `routes_changed_at` — carries the unsafe networks for the first
time. From that moment every inbound rule with no explicit `local_cidr` narrows to the
gateway's own overlay addresses, and forwarded traffic is dropped by nebula before it reaches
the tun. The cause is `route add`; the trigger is renewal; the symptom arrives later and looks
like a certificate problem.

**The codebase predicted this exactly and then walked into it.** `internal/policy/fleet.go:45-54`
documents the trap in full — "when a rule's `local_cidr` is empty and the host HAS unsafe
networks and `firewall.default_local_cidr_any` is unset — Orbit never sets it — the rule applies
ONLY to the host's own addresses and not to the subnets it routes… A dst naming a routed subnet
then validates, renders, deploys, and quietly does nothing" — and prefaces it with "Orbit does
not issue certificates carrying these yet, so this is empty in practice". That premise stopped
being true at `enroll/service.go:660`.

The **policy** path is safe. `internal/policy/compile.go:225-233` detects a selector naming a
routed subnet and emits an explicit `local_cidr` for it. The **role** path is not: a role's
rules are free-form JSON where `LocalCIDR` exists as an optional field
(`internal/nebulacfg/render.go:344`) and is never required, defaulted, or checked against the
membership's routes. `DefaultFirewall()` is deny-all inbound, so on a role-based network the
first gateway's forwarding stops working on its second certificate and nothing anywhere says
why.

The diagnostic that should catch it agrees with the wrong model.
`internal/fwmatch/fwmatch.go:320-332` treats an empty `local_cidr` as "any" unconditionally,
carrying the comment "when the host routes no unsafe networks, which is every host Orbit issues
for today" — the same false premise. So on a gateway, `orbit why` reports *allow* for rules
nebula narrows, and reports *miss on local_cidr* for the policy-compiled rules that are the ones
actually permitting forwarded traffic, because `Query.LocalAddr` is always the host's own
address. Both directions are wrong, on the one host where the question is hardest to answer by
hand.

## Decision

**A gateway's inbound reachability is computed from its routes, not written by hand.**

Where a rule's `local_cidr` is omitted and the host serves routes, the render supplies it: the
host's own addresses **plus** the prefixes that host routes. This makes an omitted `local_cidr`
mean the same thing on a gateway as it does everywhere else — "wherever this host answers" — and
it does so by the same mechanism the policy compiler already uses, extended to the role path
rather than duplicated for it.

`internal/fwmatch` takes the host's unsafe networks into account, so `orbit why` models what
nebula does. A diagnostic that disagrees with the enforcement it describes is worse than no
diagnostic, and this one disagrees in the direction that says "allowed" about traffic that is
dropped.

The two false comments — `internal/policy/fleet.go:45-47` and `internal/fwmatch/fwmatch.go:320-332`
— are corrected as part of the change, not left to be found again.

## Alternatives considered

**Set `firewall.default_local_cidr_any: true` in the rendered config.** One line, and it
restores the pre-narrowing behaviour globally. Rejected: it widens *every* rule on every gateway
to every routed subnet, which is precisely the grant nebula's changelog changed the default to
stop making silently. It would trade a silent deny for a silent allow, and this project's
whole posture on policy (ADR-0012) is that the grant should be the thing that is written down.

**Require `local_cidr` on every role rule and refuse a role without it.** Rejected as hostile to
the common case: the overwhelming majority of hosts route nothing, and on those hosts an
explicit `local_cidr` is noise that every operator would have to write and no operator would
have a reason to understand.

**Refuse `route add` on a membership whose role cannot express the reachability.** Considered
seriously, because failing at write time is this project's preference. Rejected because the role
may be shared by many memberships and the check would be a cross-object validation whose failure
message ("your role does not name this subnet") describes a nebula implementation detail rather
than an operator's intent.

**Leave it, and document that gateways need explicit `local_cidr`.** Rejected. The failure is
delayed past the change that causes it, produces no error anywhere, and lands on the host whose
purpose is to forward.

## Consequences

Rules on gateways become broader than they read: an operator inspecting a role sees a rule with
no `local_cidr` and gets, on a gateway, a rule covering routed subnets too. That is the correct
meaning, and it is still a widening relative to what the YAML says, so the rendered config —
which is what `orbit config show` prints — must show the derived value rather than the omitted
one. Making the render explicit rather than relying on a nebula default is what keeps the
config self-describing.

We become committed to the render knowing the host's routes at firewall-generation time. It
already does — the same call site issues the certificate from them — but it couples two sections
of the render that were previously independent.

The `fwmatch` correction means `orbit why` will start reporting denies it previously reported as
allows. That is the point, and it will look like a regression to anyone who trusted the old
output.

What would trigger revisiting: nebula changing the meaning of an omitted `local_cidr` again, or
gaining a way to say "any address this host is responsible for" directly. The whole of this
decision is a workaround for a default whose meaning depends on another field of the
certificate.

## References

- `third_party/nebula/firewall.go:893-918` — `addRule`, and the `unsafeNetworks` dependency
- `third_party/nebula/firewall.go:214` — `default_local_cidr_any`, defaulting false
- `internal/enroll/service.go:660` — routes entering the gateway's own certificate
- `internal/policy/fleet.go:45-54` — the trap, documented, with the premise that expired
- `internal/policy/compile.go:225-233` — the policy path handling it correctly
- `internal/nebulacfg/render.go:344` — `LocalCIDR` as an optional role field
- `internal/fwmatch/fwmatch.go:320-332` — the diagnostic carrying the same false premise
- ADR-0012 (policy compiles to addresses), ADR-0014 (diagnostics report what nebula decided)
