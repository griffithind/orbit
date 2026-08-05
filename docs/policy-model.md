# Orbit — Policy Model

How Nebula's firewall actually works, what a certificate can carry, and what
Orbit can build on top of both. File references are to `slackhq/nebula` at
v1.11.0.

This document exists because the interesting design decisions in Orbit's policy
compiler are all downstream of properties of Nebula that are easy to get wrong
from the documentation alone.

---

## 1. What Nebula enforces

### 1.1 The order of checks

`Firewall.Drop` (`firewall.go:425`) runs five steps, and the first two happen
before any rule is consulted:

1. **The peer's claimed source address is validated against its verified
   certificate.** `h.networks` is built at handshake time from the peer's
   certificate; an address outside it is `ErrInvalidRemoteIP`. A peer cannot
   claim an address its certificate does not carry.
2. **The local address must be one we handle** — our own networks plus any
   unsafe networks we route — else `ErrInvalidLocalIP`.
3. **Conntrack.** A known tuple is allowed without re-matching.
4. **Rule match**, else `ErrNoMatchingRule`.
5. The flow is recorded.

Step 1 is the single most load-bearing fact in this document. It is why a
`cidr:` selector is not weaker than a `groups:` selector: both are bound to a
signed certificate. `cidr:` is not a spoofable header, and compiling policy to
addresses is not a security compromise made for convenience.

### 1.2 The rule grammar

Within a table, a rule matches when:

```
proto AND port AND (ca_sha OR ca_name) AND local_cidr AND (group OR host OR cidr)
```

stated at `firewall.go:88` and again at `firewall.go:1012`. The `group` term
requires **all** groups named in that rule; separate rules OR together
(`firewall.go:859`).

Four consequences shape everything below.

**It is a pure allowlist with no ordering.** There is no deny rule, no
`break`, no first-match-wins. The rules are a set union. "Allow A to B except
C" is not expressible in a Nebula configuration at all. This is the single
biggest gap between what an operator wants to write and what Nebula can be
told, and closing it is Orbit's job, not Nebula's (§5).

**Every selector is symmetric across direction.** `port` is always the
*destination* port — incoming matches `LocalPort`, outgoing matches
`RemotePort`, and `firewall/packet.go:26` defines both as the destination for
their direction. `host` and `cidr` always match the *peer*; `local_cidr`
always matches *us*. One allowance therefore compiles cleanly to an inbound
rule on the destination and an outbound rule on the source, and the two agree
about what they mean.

**Outbound is enforced on the sender against the destination's certificate.**
`inside.go:74` calls `Drop` with `incoming=false` down the same `peerCert`
path the inbound side uses. Emitting both directions is defence in depth: the
flow stays closed if either end is misconfigured. Tailscale's model does not
offer this.

**Policy changes reach live connections.** A conntrack entry records the
`rulesVersion` that admitted it; on a version bump each entry is re-tested
against the new table and evicted if it no longer matches
(`firewall.go:527-560`). Revoking access severs established flows rather than
waiting for them to idle out. ZeroTier's engine is stateless and cannot do
this. It is a real advantage and worth stating plainly in user-facing docs.

### 1.3 Limits to design around

- **ICMP has no type or code filtering.** `code` is parsed and warned about as
  never having been functional (`firewall.go:1049`). "Allow echo, deny
  redirect" cannot be expressed.
- **Protocols are `any`, `tcp`, `udp`, `icmp`.** No SCTP, no numeric protocol.
- **Port ranges are materialised one port at a time.** `addRule` loops
  `for i := startPort; i <= endPort; i++` and allocates a `FirewallCA` per port
  (`firewall.go:660`). A `1-65535` rule builds 65535 map entries. The compiler
  must emit `any` rather than a full range, and should refuse to expand a range
  wider than a few thousand ports.
- **Non-first IP fragments carry no ports** and match only `port: fragment`
  (`-1`) (`firewall.go:691`). A UDP allowance that works for small packets
  silently drops fragmented ones.

---

## 2. What a certificate can say

A Nebula certificate carries exactly `Name`, `Networks`, `UnsafeNetworks`,
`Groups`, `IsCA`, `NotBefore`/`NotAfter`, `Issuer`, `PublicKey`, `Curve`,
`Signature` (`cert/cert.go:19`). That is the entire vocabulary.

There is no user identity, no key/value map, and no capability — and nothing in
`FirewallRule.match` that could consume one. Refusing user selectors, posture
selectors and app capabilities outright is therefore permanent, not a gap
waiting on implementation. Accepting them and enforcing a device rule would be
a lie in the permissive direction.

`ca_sha` matches `Issuer()`, the signing CA's fingerprint; `ca_name` resolves
through the CA pool (`firewall.go:746`). Groups are inverted into a set once at
verification and cached on the `CachedCertificate` (`cert/ca_pool.go:191`), so
group matching is a map lookup, not a scan.

A CA may constrain the groups, networks and unsafe networks of the certificates
it signs (`checkCAConstraints` in `cert/sign.go`). Orbit does not use this yet;
it is the mechanism that would make a scoped or delegated CA safe.

### 2.1 The extension point, and why we are not using it yet

Version 2 certificates have an undocumented but real extension point:

- `unmarshalDetails` (`cert/cert_v2.go:641`) reads tags 0–7 in order and
  returns without checking that the buffer is empty — the last read is the
  issuer at `:731`. Trailing elements are silently ignored.
- The raw details bytes are captured with `ReadASN1Element`, preserving tag and
  length (`cert/cert_v2.go:584`).
- `CheckSignature` signs over `rawDetails` verbatim rather than a re-marshal.
- `Marshal` and `MarshalForHandshakes` both emit `rawDetails` verbatim.

An ASN.1 element appended after the issuer tag is therefore covered by the CA
signature, survives every round trip including the handshake, and is invisible
to Nebula. Posture attestations, a policy epoch, or a user binding could ride
inside a certificate that stock Nebula still accepts and forwards intact.

**We are not building on it.** It is unspecified behaviour, not a documented
extension mechanism: upstream may add a trailing-data check, or claim tag 8 for
itself and collide with us. It would also require marshalling details ourselves
rather than going through `TBSCertificate`. The door is open; the house behind
it is a bet on upstream not closing it. Revisit only if upstream specifies it.

---

## 3. How Orbit compiles today, and what it costs

Orbit resolves every selector to overlay addresses on the server and emits
`cidr:` rules. Because Orbit owns address assignment, a selector's membership is
known at compile time, so a policy edit is configuration-only: hot, sub-second,
and requiring no certificate reissuance.

The cost is rule count. Each host's configuration grows with the number of peers
it may talk to, and a fleet-wide push regenerates every host's configuration, so
a push is O(N² × entries) bytes. Measured by
`internal/policy/scale_test.go`:

**All-to-all — three entries, every host may reach every host:**

| memberships | rules | per-membership config | fleet push |
|------:|------:|----------------:|-----------:|
| 100   | 594   | 43.3 KiB        | 4.2 MiB    |
| 500   | 2994  | 216.1 KiB       | 105.5 MiB  |
| 1000  | 5994  | 431.6 KiB       | 421.5 MiB  |
| 2000  | 11994 | 862.6 KiB       | 1.6 GiB    |

**Tiered — nine entries, tier-to-tier plus one wildcard:**

| memberships | rules | per-membership config | fleet push |
|------:|------:|----------------:|-----------:|
| 100   | 38    | 3.7 KiB         | 369.2 KiB  |
| 1000  | 375   | 27.5 KiB        | 26.8 MiB   |
| 5000  | 1875  | 134.1 KiB       | 655.0 MiB  |

Realistic policies are tiered and stay cheap to about five thousand memberships. The
all-to-all shape is where address compilation breaks down, and it is exactly the
shape a group-based rule expresses in one line.

`*` is already the cheap case: it compiles to the network's prefixes, one rule
per prefix regardless of fleet size.

---

## 4. Tags as certificate groups

### 4.1 The encoding

Nebula matches groups by exact string equality against a set
(`firewall.go:863`). Any string works. An Orbit tag can therefore be carried as
a reserved-prefix group:

```
tag  env=prod        ->  group  _o.t.env.prod
tag  role=db         ->  group  _o.t.role.db
```

The prefix is reserved. Orbit must reject operator-supplied group names
beginning with `_o.` — in `ModeAuthoritative` Orbit owns the file, but in
`ModeFragment` an operator writes rules Orbit cannot see, and a collision there
would silently widen access.

**Key/value structure buys nothing at the enforcement layer.** Nebula groups are
opaque strings with no comparison operators. ZeroTier's tags are numeric and
comparable — `tdiff department 0` means "same department, whatever it is" — and
that is what makes key/value meaningful there. Nebula has no equivalent, so
"same environment" cannot be expressed without enumerating environments.

Key/value is still worth adopting, for reasons that live entirely in Orbit:
validation (one `env` per host), selector expressiveness resolved server-side
(`tag:env=*`), and not having `prod` and `production` both in the fleet. It
should be introduced as an Orbit model change, not justified as a Nebula
capability.

### 4.2 The trade this inverts

| | address-bound (today) | certificate-bound |
|---|---|---|
| rules per allowance | O(members) | O(1) |
| membership change | config push, sub-second | certificate reissue |
| enforceable by a constrained CA | no | yes |
| revocation on removal | immediate | at renewal |

The last row is the dangerous one, and the asymmetry matters:

- **Adding** a certificate-bound tag fails **closed**. The host cannot reach the
  newly permitted thing until it renews. Safe, merely slow.
- **Removing** a certificate-bound tag fails **open**. The host keeps the group,
  and therefore the access, until its certificate expires. A policy edit that
  reads as a revocation is not one.

Group membership cannot be subtracted from a live certificate. There is no rule
that says "this group, unless" — the rule set is a union (§1.2). Removal
genuinely requires reissue, or blocklisting the outstanding certificate.

### 4.3 The design: per-tag binding, with a transitional overlay

Each tag carries a binding, defaulting to the safe value:

```
binding: config        # default — address-compiled, hot, instant revoke
binding: certificate   # group-compiled, O(1) rules, revoke needs reissue
```

`config` is the default because the failure mode of the wrong default here is
access persisting after it was revoked. An operator promotes a tag to
`certificate` deliberately, for tags that are structural and change rarely —
environment, region, tier, ownership — which are also the tags that dominate
rule count.

Two mechanisms make `certificate` binding workable, and Orbit already has both:

**On removal: pull the renewal forward.** The mechanism exists and is already
used for exactly this shape of problem: an address change stamps
`addr_changed_at`, which is compared against the active certificate's
`issued_at` to pull the membership's renewal forward
(`internal/store/address.go:372`, `internal/store/network.go:704`). A
certificate-bound tag change is the same problem with a different column, and
should reuse the mechanism rather than invent one. That reduces the exposure
window from a certificate lifetime to a round trip plus a handshake.
When the removal is a genuine revocation rather than a reorganisation, blocklist
the outstanding fingerprint as well — which severs the membership entirely until it
re-enrols, and is the correct heaviness for that case.

**On addition: a transitional address overlay.** Because the rule set is a
union, access can be granted immediately by emitting `cidr:` rules for the new
members *alongside* the group rule, then dropping them once every member's
certificate carries the group. Orbit measures convergence from applied epochs,
so it already knows when that is true. Grant is instant; the steady state is
O(1).

The overlay only works in the additive direction. That is not a limitation of
the implementation — it is the union semantics of §1.2, and no amount of
compiler work changes it.

### 4.4 What must be measured before shipping this

Certificates are sent in the handshake, and Nebula imposes no size limit below
`MaxCertificateSize` (65536, `cert/cert_v2.go:43`). The practical limit is path
MTU: a membership in many tags produces a larger handshake packet, and the default tun
MTU is 1300 (`overlay/tun.go:13`). We have not measured where a group list
starts to fragment handshakes. That measurement gates any per-membership tag limit we
advertise, and it should exist before certificate binding is offered.

---

## 5. Exclusions, compiled away

Nebula cannot express "allow A to B except C". Orbit can, because Orbit resolves
membership on the server: the exclusion is a set difference computed at compile
time, and what reaches the membership is a plain union of allowances.

```
allow:
  - src: [role:web]
    dst: [role:db]
    except: [tag:staging]
    proto: tcp
    ports: ["5432"]
```

compiles to `cidr:` rules for `members(role:db) \ members(tag:staging)`.

This is where Orbit can be genuinely more expressive than both comparators:
Tailscale grants are also allow-only with no exclusion, and ZeroTier has ordered
rules with `drop` but no identity resolution to apply them to.

**Exclusion forces `config` binding on the selectors it touches.** A group
cannot be subtracted from, so an entry with an `except` clause must compile its
destination to addresses. This is a clean rule to state and to enforce in the
validator: using `except` on a certificate-bound tag is an error with a message
that says which tag and why, not a silent downgrade.

---

## 6. What Orbit will not build

**ZeroTier-style capabilities.** They depend on peers pushing signed credential
bundles to each other at flow time. Nebula has no channel for that; it is a
protocol change, not a control-plane one.

**User identity in the packet path.** §2. A certificate identifies a device.
Posture and user binding belong at *issuance*: Orbit controls certificate
lifetime, so a posture check at renewal gives device-compliance enforcement with
a latency of one certificate lifetime and zero Nebula changes.

**ICMP type/code filtering and fragment-aware policy.** Upstream work or
nothing.

**A fork.** In-process versus supervised Nebula is a deployment choice; running
modified Nebula is a different project with a different security surface.

---

## 7. Summary of the position

Nebula's firewall is a small, symmetric, certificate-bound allowlist with
stateful connection tracking and live re-validation on rule change. It is a good
*enforcement target* and a poor *authoring language*.

Orbit's compiler is the policy engine. Everything expressive — exclusions,
selector resolution, per-membership tailoring, binding choice — happens on the server
and lands as the simplest artifact Nebula can enforce. The certificate is used
for what only it can do: bind an address to an identity, and carry the structural
labels that would otherwise dominate rule count.
