# ADR-0024: One enrolment door, and it proves possession

**Status:** Proposed
**Date:** 2026-08-12

## Context

Orbit has two ways to get a certificate for a membership, and they have very different
strengths.

**`join` + `claim`** is the strong one. `Claim` requires a signature by the device key over a
statement that binds the mesh public key, and `device.VerifyClaim` reads the device key **from
the database** rather than from the request, so the check cannot be made vacuous
(`internal/device/join.go:152-163`). The statements are length-prefixed and domain-separated
(`:65-79`, `:116-143`) with a test pinning their unambiguity. This is proof of possession of the
device identity.

**`enroll`** is the weak one, and it issues for the same membership. `wire.EnrollRequest` is
`Credential`, `PublicKey`, `Curve` and advisory metadata — **there is no signature field**
(`internal/wire/wire.go:18-36`). `Service.Enroll` validates the code, redeems it, and issues
over whatever public key the caller supplied; the only checks on that key are structural
(`internal/enroll/service.go:211-252`, `validatePublicKey` at `:1081-1120`). Nothing in
`enrollment_credential` binds a device, a key, or a fingerprint
(`internal/db/migrations/0001_initial.sql:422-445`); `used_from inet` records the source after
the fact.

So an enrolment code is a bearer credential that mints a certificate over a key the bearer
chooses, for a membership that may already have a device attached to it. `orbit agent enroll`
is a live caller (`cmd/orbit/agent.go:152`) and never touches the device key. Whatever `claim`
proves, `enroll` renders optional.

Three things around it make the exposure larger than it looks.

**Reservation code TTL is unbounded and client-supplied.** `Service.Reserve` only floors it —
`if ttl <= 0 { ttl = DefaultCodeTTL }` (`internal/enroll/join.go:557-559`) — and the value comes
straight from the request as `time.Duration(req.TTLSeconds)*time.Second`
(`internal/api/join.go:257-258`). A reservation auto-authorises on redemption
(`internal/store/host.go:824-833`). That is an unattended admission credential with an operator-
chosen lifetime, against the rationale written at `internal/enroll/service.go:35-38`: "a
long-lived join token sitting in a configuration management repository is the usual way a
fleet's trust boundary is lost". The admin code route always passes 0; only reservations expose
the knob.

**There is no per-code attempt limit.** The limiter is per source address and per process
(`internal/api/ratelimit.go:70-78`), so N replicas multiply the global ceiling by N, and nothing
counts failures against a *code*. `ratelimit.go:26-28` says so: "Nothing finer is available."
Two further edges: when the 4096-key table is full of fresh keys a new key gets no limiter at
all (`:160-166`), and under `-trust-forwarded-for` the limiter key is the leftmost
`X-Forwarded-For` element, which most proxies append to rather than overwrite — making the
per-source bucket attacker-chosen and the key table attacker-fillable. Identity is unaffected;
`agentPeerAddr` ignores the flag.

**`/agent/v1/renew` has no limiter at all** (`internal/api/server.go:255-265`), and it issues
certificates.

What is *not* a gap, and is worth recording so it is not re-litigated: redemption is atomic and
replay-proof — a single `UPDATE … WHERE secret_hash = $1 AND used_at IS NULL AND expires_at >
now() RETURNING …` (`internal/store/lookup.go:77-84`) executed before any expensive work — and
unknown, spent and expired codes all return one indistinguishable 401. Renewal identity is
locked down: `wire.RenewRequest` is two fields, and `Renew` takes name, groups, networks and
routes from the database, with the caller resolved from the overlay source address and never
from a header. A device cannot change what it claims to be at renewal.

## Decision

**An enrolment code is bound to a device at redemption.** The code path requires the same
proof of possession `claim` requires: a signature by the device key over a statement binding the
mesh public key and the code. `Enroll` gains a signature field and verifies it against the
device row, and a code redeemed by a device becomes bound to that device's fingerprint, so a
second redemption by a different device is refused rather than issuing.

For the first enrolment of a device the control plane has never seen, the device key is
recorded at redemption exactly as `join` records it — the code authorises the *binding*, and
possession of the key authorises everything after.

**Reservation TTL is capped server-side**, at a value the deployment sets and the request cannot
exceed.

**Per-code attempt counting lives in Postgres**, alongside `used_at`, so a code locks out after
a small number of failures regardless of which replica saw them, and so the deployment-wide
ceiling is a ceiling rather than a per-process one. `/agent/v1/renew` gets a limiter.

## Alternatives considered

**Delete the code path entirely and make `join` + `claim` the only door.** Cleanest, and ADR-0006's
"wire it or delete it" points this way. Rejected because the code path is what makes an
unattended first boot possible without a pre-shared device identity, and that is the case
reservations exist for. Binding the code to the device at redemption keeps the ergonomics and
removes the bypass.

**Leave `enroll` as-is and rely on the code being short-lived and single-use.** This is the
current position. Rejected: single-use bounds how many certificates a stolen code yields, not
*whose* key they are issued over, and the code is the only thing standing between an attacker
and a valid membership certificate.

**Rate-limit harder instead.** Rejected as addressing the wrong failure. The problem is not
guessing a 24-byte code — that is genuinely infeasible — it is that a code obtained any other
way (a CI log, a configuration repository, an operator's terminal scrollback) is sufficient on
its own.

## Consequences

`orbit agent enroll` acquires a dependency on the device key, which means the enrolment flow can
no longer be completed by pasting a code into a machine that has never run `orbit`. That is a
real ergonomic loss and it is the point: the two doors currently offer different guarantees for
the same result, and the weaker one wins by being easier.

Per-code state in Postgres adds a write to the redemption path, which is already a write.

We are committed to every issuance path proving possession of the device key. A future path that
cannot — a browser-driven enrolment, say — would need its own ADR rather than reusing this door.

What would trigger revisiting: hardware-backed device keys. If the device key lives in a TPM,
the binding becomes stronger for free and the code becomes purely an authorisation to bind.

## References

- `internal/wire/wire.go:18-36` — `EnrollRequest`, with no signature field
- `internal/enroll/service.go:211-252` — issuance over a caller-chosen key; `:35-38` — the rationale
- `internal/device/join.go:152-163` — `VerifyClaim` reading the key from the database
- `internal/enroll/join.go:557-559`, `internal/api/join.go:257-258` — the uncapped TTL
- `internal/api/ratelimit.go:26-28, 70-78, 160-166` — no per-code dimension, per-process ceiling
- `internal/api/server.go:255-265` — renew, unlimited
- `internal/store/lookup.go:77-84` — the atomic redemption, which is correct
- ADR-0006 (code must be reachable), ADR-0009 (replicas), ADR-0023 (blocking stops issuance)
