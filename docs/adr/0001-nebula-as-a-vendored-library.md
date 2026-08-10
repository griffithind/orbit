# ADR-0001: Nebula as a vendored library, not a subprocess

**Status:** Accepted
**Date:** 2026-08-10

## Context

Orbit is a control plane for a data plane it does not implement. There are three ways to stand in
that relationship to Nebula:

1. **Supervise the upstream binary.** Write config files, exec `nebula`, send SIGHUP.
2. **Import it as a library** from an unmodified upstream module.
3. **Import it as a library from a pinned fork.**

Nebula's own shape pushes on this choice. Certificate groups are signed into the peer certificate
and evaluated by Nebula's host firewall, so any policy Orbit issues is enforced by Nebula's
matcher, not Orbit's. If Orbit is to explain, test, or predict its own policy, it needs access to
that matcher — not a reimplementation of it, which would drift and be wrong in exactly the cases
that matter.

Upstream also moves. v1.10.0 shipped the ASN.1 certificate v2 format and IPv6; v1.11.0 migrated
logging from logrus to `log/slog` and **changed the signature of the embedder constructors**, and
in the same release corrected `firewall.inbound_action` / `outbound_action`, which had been applied
to the opposite direction. A subprocess integration would not have noticed the last one.

## Decision

Nebula is a Go module dependency, built from a pinned fork under `third_party/nebula`
(currently `v1.11.0-3-g3afbd01`), and linked into both `orbit` and `orbitd`. A managed host is one
binary and one service.

Consequences we accept deliberately:

- `orbit` and `orbitd` share the Nebula version. Upgrades are atomic across the fleet's tooling.
- The build requires submodules. Cloning without `--recurse-submodules` fails on a missing module,
  loudly, at build time.
- We can call into Nebula's own parser and matcher. `e2e/why_test.go` does exactly this —
  `TestLoadRulesUsesNebulasParser`, and explainer results are checked against Nebula's verdict in
  both directions.

## Alternatives considered

**Supervise the upstream binary.** Rejected. It makes the policy explainer a reimplementation, and
a reimplementation of a security-critical matcher that drifts silently is worse than not having
one. It also means shipping and version-matching a second binary on every managed host, and it
gives up in-process access to the hostmap — which is what `e2e/revocation_test.go` reads to time
tunnel teardown from the enforcer rather than from our own belief.

**Depend on unmodified upstream.** Preferred in principle, and we should return to it whenever the
delta is empty. A fork is a maintenance tax and a supply-chain surface. It is justified only while
we carry changes upstream has not taken; every change we hold should have an upstream PR or a
written reason it will never be one.

## Consequences

**Easy.** One binary per host. Policy explanation is differential-tested against the real enforcer.
Revocation timing is measured from the hostmap. No config-file race between writer and reader, no
SIGHUP delivery to debug.

**Hard.** We inherit upstream's breaking changes at the source level rather than the config level —
the v1.11.0 `*slog.Logger` constructor change is the example. Upgrades require reading the
changelog properly, and the ICMP reject code changing from 3 to 13 in the same release is the kind
of thing that only shows up in a test that asserts it.

**Committed to.** Tracking upstream on a real cadence. A vendored fork that falls behind stops
being a fork and starts being a maintenance liability — ZeroTier's abandoned 2.0 branch and
Headscale's capability-version treadmill are both cautionary versions of the same failure.

**Revisit if** the fork delta reaches zero (drop the fork, depend on upstream directly), or if
upstream's embedding API becomes unstable enough that supervising the binary is genuinely cheaper.

## References

- `.gitmodules`, `third_party/nebula` at `v1.11.0-3-g3afbd01`
- `e2e/why_test.go:423` — `TestLoadRulesUsesNebulasParser`
- Nebula CHANGELOG v1.11.0 — slog migration, embedder constructor change, inbound/outbound action
  correction, ICMP code 13
- Nebula CHANGELOG v1.10.0 — certificate v2 (ASN.1), IPv6, multiple overlay addresses
