# ADR-0002: The control plane fails static

**Status:** Accepted
**Date:** 2026-08-10

## Context

When the control plane is unreachable, an overlay network can do one of three things:

- **Fail closed** — refuse traffic. A control-plane outage becomes an estate-wide outage.
- **Fail open** — drop enforcement. A control-plane outage silently removes all segmentation,
  and nobody notices until the incident review.
- **Fail static** — keep enforcing the last known-good policy, stop accepting changes.

Four independently designed systems converged on fail-static, which is unusually strong evidence:

- **Illumio**: the VEN "continues to enforce the last-known-good policy while it tries to
  reconnect." Heartbeat every 5 minutes; three misses degrade, auth failure drops to a minimal
  state with 4-hour retries.
- **Cilium**: "All datapath forwarding, policy enforcement and visibility functions for existing
  workloads/endpoints do not depend on the kvstore." eBPF programs live in the kernel, so an agent
  restart costs flow events, not enforcement.
- **ZeroTier**: Certificate-of-Membership agreement is a *relative* timestamp comparison between
  two peers, so an established network keeps passing traffic indefinitely when the controller dies.
- **Nebula**: the lighthouse holds no key material and takes no part in the handshake, so losing
  it costs discovery of uncached peers, not connectivity.

The counterexample is instructive. Zscaler Private Access has an explicit DR mode that preserves
availability during a vendor outage — and their own ProServe guide states "ZPA Policies are
unavailable during DR Mode." A mode designed for outages works by turning the product off.

## Decision

Orbit fails static. When `orbitd` is unreachable:

- Established tunnels continue, enforcing the policy already on the host.
- Certificates already issued remain valid until their TTL.
- No new memberships, no policy changes, no route approvals, no revocation delivery.

The safety valve is the certificate TTL, not a liveness check. `Network.CertTTL` is documented in
the wire contract as "the revocation SLA for a partitioned host, not merely a rotation cadence"
precisely because it is the bound on how long a partitioned host can outlive a decision to
remove it.

## Alternatives considered

**Fail closed on control-plane loss.** Rejected: it makes `orbitd` a single point of failure for
the data plane, which contradicts the reason to run an overlay at all. It also inverts the
incentive during an incident — operators would route around Orbit rather than through it.

**Heartbeat-based liveness with a short deadline.** Rejected: it is fail-closed with extra steps,
and it turns every network partition into an outage. Teleport offers exactly this as an option
(`locking_mode: strict`, 5-minute staleness tolerance) and ships the permissive mode as the
default for the same reason.

## Consequences

**Easy.** `orbitd` can be restarted, migrated, upgraded, or lost without touching the data plane.
It can be operated at a lower availability tier than the hosts it serves. Maintenance is boring.

**Hard.** Revocation depends on reachability. A host that is partitioned from `orbitd` keeps its
access until its certificate expires — so `CertTTL` is a security parameter, not a convenience,
and the API says so. Shortening it tightens the partition bound and increases renewal load; that
trade is the operator's to make, and the default of 24h is a starting point, not a recommendation
for every network.

**Committed to.** The blocklist must reach hosts to take effect. This is why distribution is
push-first with a polling fallback (ADR pending) and why convergence is a first-class metric
(`orbit_hosts_blocklist_converged`) rather than an assumption — an unmeasured claim about
propagation is a marketing claim.

**Revisit if** we ever need a hard revocation guarantee that does not depend on host reachability.
That requires either an online authorization check in the data path — which would put the control
plane back in the path and forfeit this ADR — or dramatically shorter certificate lifetimes.

## References

- `internal/wire/wire.go:663` — `CertTTL` documented as a partition bound
- `internal/agent/loop.go:982` — push with polling fallback
- `internal/metrics/collector.go` — convergence metrics
- Illumio VEN-to-PCE communication docs; Cilium troubleshooting docs; ZeroTier protocol docs
- Zscaler ProServe Disaster Recovery guide (the counterexample)
