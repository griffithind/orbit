# ADR-0003: Revocation terminates live sessions

**Status:** Accepted
**Date:** 2026-08-10

## Context

"Revoked" means two different things in practice, and most products ship the weaker one without
saying so.

- **Weak**: the credential stops working for *new* connections. Established sessions continue.
- **Strong**: established sessions are torn down.

Established connections survive a policy change in Illumio, Cilium, NSX, Istio, and Tailscale.
Tailscale's is the clearest case: its ingress filter checks TCP only on the SYN
(`if !q.IsTCPSyn() { return Accept, "tcp non-syn" }`) and deliberately carries conntrack state
across filter rebuilds "to enable changing rules at runtime without breaking existing stateful
flows." Removing an ACL therefore stops new flows and leaves existing ones running.

Of the commercial ZTNA products surveyed, only **Teleport's Lock API** and **Appgate's** live
entitlement rewriting implement out-of-band session termination with documented semantics.
Teleport's locks run on a dedicated `LockWatcher` that bypasses the general cache precisely so
propagation is seconds rather than cache-TTL.

The managed-Nebula competitor, Defined Networking, publishes a **60-second** revocation SLA — the
`dnclient` poll interval.

Nebula gives us the strong form for free, and it is worth quoting because it is easy to miss.
`connection_manager.go:473`:

```go
} else if err == cert.ErrBlockListed { //avoiding errors.Is for speed
    // Block listed certificates should always be disconnected
    return true
}
```

Blocklisted certificates **skip the `pki.disconnect_invalid` check entirely** and always tear the
tunnel down. The check runs from `makeTrafficDecision` on the connection manager's tick,
`timers.connection_alive_interval`, default 5 seconds.

## Decision

`orbit membership block` terminates established tunnels, not merely future handshakes. Three
things make that true and keep it true:

1. `pki.disconnect_invalid: true` is rendered unconditionally
   (`internal/nebulacfg/render.go:647`), so expiry also tears down.
2. The blocklist is distributed by epoch and convergence is reported per membership.
3. `e2e/revocation_test.go` measures block-commit → teardown end to end, reading the teardown
   time **from nebula's own hostmap** rather than from anything Orbit believes, and fails the
   build on regression.

> **Known defect, 2026-08-10.** Point 2 currently overstates the shipped behaviour, and this ADR
> is the record of that. The push channel (`Loop.Run` → `watchOnce` → `Client.Watch`) is built and
> tested but **is not wired into the daemon**: `networkLoop.run` calls `Loop.Tick`
> (`cmd/orbit/agent.go:851`), which has no push path, on a ticker defaulting to `-interval` of one
> minute (`agent.go:291`). `e2e/revocation_test.go:155` drives `Loop.Run` directly with a 5s
> interval, so the suite measures a path production does not execute.
>
> Real-world latency today is therefore bounded by the poll interval plus the connection-manager
> tick — roughly 65 seconds, which is parity with Defined Networking's published 60-second SLA
> rather than the improvement on it that this ADR claims. Wiring the push path is tracked as the
> first fix; until it lands, neither the README nor this document should assert seconds.

The floor is not zero and we state it rather than hiding it: the connection manager re-checks
certificates every `timers.connection_alive_interval`, so roughly half that is unavoidable
latency no control plane can remove.

## Alternatives considered

**Rely on short certificate TTLs alone.** This is SPIRE's, Istio's and Teleport's model, and it is
correct for credentials measured in minutes. It is not sufficient for compromise response: the
window is the TTL, and a TTL short enough to serve as a revocation mechanism makes control-plane
availability load-bearing — which ADR-0002 declines.

**Blocklist without teardown.** The default if we did nothing. Rejected: it makes "blocked" mean
something weaker than every operator will assume, and the gap between the assumption and the
behaviour is exactly where incidents live.

**A CRL or OCSP responder.** Rejected. Nebula has neither, and the research is unkind to both:
Vault's certificate auth matches revocation *per chain*, so "if the client presents any chain
where no certificate matches a revoked serial number, authentication is allowed"; AWS Roles
Anywhere refuses CDP/OCSP callbacks outright and supports imported CRLs only. Online revocation
is an availability liability attached to a security control.

## Consequences

**Easy.** A membership can be removed from the mesh in seconds, and the number is defensible
because it is measured from the enforcer rather than asserted from the issuer.

**Hard.** The number depends on `timers.connection_alive_interval`, which Orbit does not currently
pin — it inherits Nebula's default of 5s. That makes our SLA hostage to an upstream default and
should be fixed by setting it explicitly and asserting it in the same test that measures
propagation.

**A known weakness in the identifier.** Nebula's blocklist keys on the certificate's SHA-256
fingerprint, and GHSA-69x3-g4r3-p962 (CVSS 7.6, fixed in 1.10.3) showed why that is fragile: ECDSA
signature malleability let an attacker holding a blocklisted P256 key produce a byte-different
certificate with an identical public key and therefore a different fingerprint. The revocation
identifier was derived from bytes the adversary could perturb. We are on 1.11.0 and carry the fix,
but the structural lesson stands, and BeyondCorp's inversion is the better long-term shape:
*"the inventory acts as a whitelist of the accepted device identifiers, and there is no live
dependency on the CRL"* — with the striking property that losing the CA key does not lose control.
A future ADR should move the authority from "fingerprints we deny" to "memberships we admit."

**Committed to.** The README's published number must match what the test guards. Today it does
not — the README says ~5s and the suite asserts p50 15s / max 45s with budgets deliberately loosened
for CI. Either the budget tightens or the claim changes; a differentiator that is not evidenced
where customers read it is not a differentiator.

## References

- `third_party/nebula/connection_manager.go:473` — `isInvalidCertificate`
- `third_party/nebula/connection_manager.go:322` — call site in `makeTrafficDecision`
- `internal/nebulacfg/render.go:376,647` — `disconnect_invalid` always set, with rationale
- `e2e/revocation_test.go` — the measurement and its budgets
- GHSA-69x3-g4r3-p962 — P256 blocklist bypass via signature malleability
- Defined Networking, "blocklisting" — the 60-second competitor baseline
