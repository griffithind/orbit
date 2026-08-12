# ADR-0031: Clock skew is measured, not inferred from certificate errors

**Status:** Proposed
**Date:** 2026-08-12

## Context

Nebula has **zero** skew tolerance. `Expired` is
`notBefore.After(t) || notAfter.Before(t)` (`third_party/nebula/cert/cert_v2.go:170-172`),
evaluated against raw `time.Now()` at handshake and on every connection-manager tick. A grep for
`leeway`, `clock.?skew` or `tolerance` across the vendored tree returns nothing. A host whose own
certificate falls outside its window is a hard error at load; a CA in the bundle that is expired
fails all its leaves with `ErrRootExpired`.

Orbit's total defence against a wrong clock is a one-minute backdate at issuance
(`internal/enroll/service.go:639`, `issuer.ValidityFor(net.CertTTL, time.Minute)`) and a
**manual diagnostic command**: `clockCheck` in `cmd/orbit/netcheck.go:207-241`, comparing local
time against the control plane's `Date` header with `maxSkew = 2 * time.Minute`. Its own advice
text says the failure "reports itself as a certificate error" — which is exactly the problem.
Nothing in `orbit agent run` runs that check. `Loop.clock()` is a bare `time.Now()` with a test
hook.

So the failure modes are:

**A device more than a minute slow rejects its own brand-new certificate.** With `notBefore =
CP_now - 1m`, nebula refuses to load it, the apply fails and rolls back to the previous
generation — fail-safe, and the loop then retries forever with no statement of cause. This looks
identical to a wrong key, a wrong CA, or a corrupted config.

**A returning peer with a slow clock accepts a revoked certificate.** ADR-0025's blocklist
delivery omits entries whose `not_after` has passed, on the reasoning that nebula will reject the
expired leaf anyway. That reasoning depends on the *verifying* peer's wall clock, with zero
leeway, and nothing on the agent checks that clock.

**The two enrolment doors disagree.** `device.VerifyJoin` / `VerifyClaim` reject outside
±`JoinFreshness = 5 * time.Minute` with a dedicated `ErrStaleJoin` that names the drift, and a
doc comment saying the remedy is "fix the machine's clock" (`internal/device/join.go:45, 86-91`).
`Service.Enroll` carries no timestamp and performs no such check. The strong door diagnoses
skew; the weak one does not — the same asymmetry ADR-0024 records for proof of possession.

Tailscale's answer is instructive and Orbit has nothing equivalent. They measure skew against the
control plane and *correct for it*: `expiryManager.onControlTime` computes
`delta := t.Sub(localNow)` from `MapResponse.ControlTime` and stores it when the absolute delta
exceeds one minute (`ipn/ipnlocal/expiry.go:25-28, 64-74`); peer expiry is then evaluated against
`controlNow := localNow.Add(clockDelta)` (`:148-171`), and expired peers are *marked* rather than
deleted so downstream code "can provide more clear error messages" (`:76-81`).

Orbit cannot adopt the correction — nebula's check is inside the vendored data plane and takes
wall time — but it can adopt the **measurement**, and the transport for it already exists: the
control plane sends a `Date` header on every response the agent already makes.

## Decision

**The agent measures clock skew against the control plane on every poll and reports it as a
first-class condition** — in the agent report, in `orbit status`, and as a metric per ADR-0008.
The threshold is the one issuance already assumes: one minute.

**Skew is named at the point of failure.** When an apply fails because nebula rejected a
certificate whose window has not opened, the agent says so — "this machine's clock is N behind
the control plane" — rather than logging a generic validation failure and retrying. The
information is already in hand at that moment; today it is discarded.

**`Enroll` carries a timestamp and rejects a stale one**, exactly as `join` and `claim` already
do, with the same `ErrStaleJoin` shape and the same remedy in the message.

Correction, not adoption: Orbit measures and reports skew but does **not** correct for it. The
enforcement point is nebula, using wall time, and a control plane that silently compensated would
be hiding a fault the data plane will not hide.

## Alternatives considered

**Widen the issuance backdate from one minute to something generous — an hour.** Cheap, and it
makes the slow-clock case disappear for most machines. Rejected: it widens the window in which a
certificate is valid before anyone intended it to be, it does nothing for the *fast*-clock case,
and it converts a diagnosable fault into a hidden one. The backdate exists to absorb round-trip
and propagation, not to paper over a broken host.

**Have the agent set the system clock.** Rejected outright: that is NTP's job, it needs privileges
Orbit should not exercise, and a mesh agent adjusting a machine's clock is a far larger blast
radius than the problem.

**Refuse to apply a generation when skew exceeds the threshold.** Considered seriously — it fails
closed and it is loud. Rejected because it makes a clock problem into a total outage for a host
that might otherwise be fine, and because the apply already fails safely on its own. Reporting is
the intervention; refusing is not.

**Rely on `orbit netcheck`.** It already does this correctly and is the model for the check. It
is a command a human runs after suspecting the problem, and the entire difficulty is that nothing
points at the problem in the first place.

## Consequences

Skew becomes visible before it becomes an outage, which is the whole value: the current failure
is a host that silently stops converging and whose logs name the wrong cause.

Reporting skew means the agent report grows a field and the control plane stores it, so a fleet
view can answer "which machines have bad clocks" — a question that today has no answer short of
running `netcheck` on each of them.

We are committed to not compensating. If a future change makes Orbit tolerate skew somewhere,
that tolerance must be stated rather than emergent, because nebula's zero-leeway check is the
real enforcement and any tolerance above it is a place where Orbit and the data plane disagree.

What would trigger revisiting: nebula gaining a configurable validity leeway. That would make
correction possible at the enforcement point rather than around it, and would change this from a
reporting decision to a configuration one.

## References

- `third_party/nebula/cert/cert_v2.go:170-172` — the zero-leeway check
- `internal/enroll/service.go:639` — the one-minute backdate, and the whole of the defence
- `cmd/orbit/netcheck.go:205, 207-241` — the check that exists and is never run automatically
- `internal/device/join.go:45, 86-91, 101-106` — `ErrStaleJoin`, on the door that has it
- Tailscale `ipn/ipnlocal/expiry.go:25-28, 64-74, 76-81, 148-171` — measure, correct, mark
- ADR-0008 (what we measure), ADR-0024 (one enrolment door), ADR-0025 (blocklist delivery)
