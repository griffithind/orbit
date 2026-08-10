# The credential model

Two credentials, not one. This document records why, what each is authoritative
for, and where the access decision is actually made.

**Status.** The device half is built: `orbit join` generates a device key,
the control plane records it, and the nebula certificate is issued against a
membership that names it (`docs/model.md`, `docs/design-device-identity.md`). The
**user credential is designed and not built** — there is no user noun yet, and
`internal/policy` still refuses `user:` selectors, correctly. §5 and §6 apply to
what exists today; §2's user half is the shape to build into.

---

## 1. The problem with a single certificate

Nebula gives each host one certificate carrying its address and its groups, and
the firewall matches on those groups. The obvious move is to put everything in
there — device, user, posture, context — and compile policy against it.

It does not survive contact with a desktop fleet. A device certificate that also
encodes the current user means either re-issuing it on every login, or accepting
that it means "this machine, plus whoever happens to be sitting at it." The first
is a certificate lifecycle driven by session events; the second silently drops
the user from the model while pretending otherwise.

The two facts have different lifetimes, different roots of trust, and different
things they are allowed to assert. They should be different credentials.

---

## 2. The two credentials

### Device credential — the Nebula certificate

- **Issued at**: enrollment.
- **Bound to**: a key generated on the machine and never transmitted — a file
  at mode 0600. Not hardware-held; see §7 for why not.
- **Asserts**: this is a known, enrolled machine.
- **Authoritative for**: **network reachability.** Which hosts this machine may
  open a connection to, on which ports.
- **Lifetime**: short, renewed on an epoch. Renewal is where posture is
  re-evaluated.

### User credential — a short-lived X.509 certificate

- **Issued at**: successful user authentication on a specific enrolled device.
- **Bound to**: the user, and *named to the device* it was minted for.
- **Asserts**: this person, on that machine, under these conditions, at this
  time.
- **Authoritative for**: **service access.** What the person may do once packets
  can flow.
- **Lifetime**: minutes to hours. Short enough that revocation is expiry.

Contents, at minimum: subject identity, groups, the device ID it was issued
against, issuance time, expiry, and a record of the context that was true at
issuance (posture state, observed network location).

**It is not a Nebula certificate.** Nebula's format is its own; the user
credential should be ordinary X.509 so it can be consumed by PKINIT to obtain a
Kerberos ticket, presented as a browser client certificate, or exchanged for an
assertion — three transports for one credential rather than three competing
designs.

---

## 3. Where the access decision happens

**At issuance, not in the data path.**

Orbit is already an issuer. Time, posture, device state and observed location are
inputs to two questions: *do I mint this credential*, and *how narrow is it*. The
short lifetime is what makes the evaluation continuous — a device that stops
qualifying stops being re-credentialed, and its access decays rather than being
severed by a live decision point.

This preserves the property that makes the design worth having: **there is no
policy decision point in the packet path.** A control-plane outage means no *new*
credentials, not no network. NIST SP 800-207 §5.2 names PDP unavailability as a
first-class threat and offers no doctrine for it; this is the doctrine.

The corollary is that "conditional access" is not a feature bolted on later. It
is the rule set governing issuance, and it is the same code path either way.

---

## 4. Why this shape is right

Both hardware attestation platforms independently arrived at the same structure,
which is worth one paragraph because it is the strongest available evidence that
the split is not arbitrary.

Apple App Attest cannot hold a working key — `generateKey` returns an opaque
handle "usable only for assertions" — so the sanctioned pattern is to generate a
*separate* Secure Enclave key and bind it by putting its public half into the
attestation. Android Key Attestation is the same shape: attest a hardware signing
key, and have it sign the public half of the key you actually use.

**One credential attests another.** Neither platform tries to make a single key
carry both the hardware proof and the working identity. This model is that same
join, applied to device and user rather than to attestation and agreement.

---

## 5. What this model does not do

**Per-user network segmentation on a shared machine.** Nebula sees devices. Any
user on a box can put packets on the wire; enforcing "user A reaches host X, user
B does not" at layer 3 on one machine is a fiction. Under this model that is
enforced at the service layer by the user credential, which is the only place it
is actually true.

State this as a design property, not a limitation to be worked around later.

---

## 6. Signal trustworthiness

Distinguish what is **observed** from what is **asserted**, and prefer observed.

| Signal | Source | Trust |
|---|---|---|
| Device identity | Certificate over a key that never left the machine | **Proven** — as far as possession goes; a key on disk is copyable, so this proves "something holding that key", not "that physical machine" |
| Underlay address, lighthouse reached | Observed by the control plane during handshake | **Observed** — coarse but real |
| Time of issuance | Control plane clock | **Observed** |
| Boot state, TPM presence | Agent report | **Asserted.** Read natively from the machine and attributable to an enrolled device, but not attested |
| Disk encryption, firewall, patch level | Agent report | **Asserted.** Attributable to an enrolled device; not proof |
| Geolocation | Anything self-reported | **Asserted, weakly.** Entra's own documentation says device-platform signals "aren't verified" |

The honest claim this supports: posture reports are **attributable to a key that
also gates network access**, delivered in seconds rather than hours, with
revocation that severs the connection. Lying requires
compromising the host rather than spoofing a header. That is a real improvement.
It is not proof that the report is true, and it should not be sold as one.

---

## 7. Constraints this design inherits

**One curve, and no choice about it.** `cert/ca_pool.go` rejects a certificate
whose curve differs from its signer's, and nothing updates a network's curve —
so the wrong answer means rebuilding the network and re-enrolling every machine.
Orbit is **P-256 only**: there is no `-curve` flag on either half, and migration
0021 refuses anything else in the database.

P-256 rather than Curve25519 because it is the curve every other ecosystem
standardises on for ECDSA, and because the difference reaches no further than
the handshake — `pki.go newCipherSuite` uses the curve only to pick the Noise DH
function, while the AEAD and hash come from the separate `cipher` setting, so
every packet after the handshake is identical work either way. Measured: about
10% on the handshake DH and 24% on a certificate verify, which is 10-20µs once
per peer pair.

The value is having ONE curve. Two defaults that could disagree is not a
theoretical hazard: `orbitd bootstrap` defaulted to P256 while every `orbit
agent` path defaulted to CURVE25519, and a machine following the documented
steps failed its claim with a curve mismatch. Two constants in two binaries
cannot notice they differ.

**Private keys are files, deliberately.** The mesh key lives at
`<network dir>/host.key` and the device identity key at
`/var/lib/orbit/device.key`, both mode 0600. There is no PKCS#11, no TPM, no
Secure Enclave — the same choice Tailscale and ZeroTier make.

Hardware backing defeats **offline** attacks: a stolen disk, a backup, a VM
snapshot, a decommissioned SSD. It does nothing against an attacker with code
execution on a running machine, who simply asks the chip to sign. That is a real
category, and a narrow one, and covering it costs a cgo build variant, a second
release artifact, and a PKCS#11 module installed and configured on every managed
host — for a property that could not even be verified, since nothing attested
that a machine reporting "token" was using one.

What bounds the file instead: certificates are short-lived (24h by default), the
mesh key is rotated on every renewal, and `orbit device block` refuses a device
everywhere on the control plane immediately. A stolen disk image buys mesh
access until the certificate expires, not indefinitely.

## 8. Open questions

1. What exactly goes in the user credential, and in which fields — extensions,
   SAN, or a signed claims blob?
2. What issues it: does Orbit accept an OIDC ID token, a Kerberos ticket, a PAM
   success, or all three?
3. How does the user credential reach its consumers — NSS database, Kerberos
   ccache, a local socket?
