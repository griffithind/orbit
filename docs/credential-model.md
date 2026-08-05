# The credential model

Two credentials, not one. This document records why, what each is authoritative
for, and where the access decision is actually made.

**Status.** The device half is built: `orbit agent join` generates a device key,
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
- **Bound to**: a key that never leaves hardware (TPM, Secure Enclave, StrongBox)
  where the platform allows; a software key otherwise, stated as such.
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
| Device key resident in hardware | Attestation at enrollment | **Proven**, where the platform supports it |
| Device identity | Certificate + hardware key | **Proven** |
| Underlay address, lighthouse reached | Observed by the control plane during handshake | **Observed** — coarse but real |
| Time of issuance | Control plane clock | **Observed** |
| Boot state | TPM quote + event log | **Proven** where measured boot is configured |
| Disk encryption, firewall, patch level | Agent report | **Asserted.** Attributable to an enrolled device; not proof |
| Geolocation | Anything self-reported | **Asserted, weakly.** Entra's own documentation says device-platform signals "aren't verified" |

The honest claim this supports: posture reports are **attributable to a
hardware-held key that also gates network access**, delivered in seconds rather
than hours, with revocation that severs the connection. Lying requires
compromising the host rather than spoofing a header. That is a real improvement.
It is not proof that the report is true, and it should not be sold as one.

---

## 7. Constraints this design inherits

**Curve was a whole-network, create-time decision. Now it is not a decision at
all.** `cert/ca_pool.go` rejects a certificate whose curve differs from its
signer's, and nothing updates a network's curve — so the wrong answer meant
rebuilding the network and re-enrolling every machine. Hardware-backed keys
require P-256: TPM 2.0 has no Curve25519, Apple's Secure Enclave is P-256 only,
Windows' Platform Crypto Provider is ECDSA P-256/P-384, and nebula's own PKCS#11
path exists only for P-256 (`noiseutil.DHP256PKCS11`, with no 25519 equivalent).

So Orbit is **P-256 only**. There is no `-curve` flag on either half, and
migration 0021 refuses anything else in the database. What it costs reaches no
further than the handshake — the curve selects only the Noise DH function
(`pki.go newCipherSuite`), while the AEAD and hash come from the separate
`cipher` setting, so every packet after the handshake is identical work.
Measured: about 10% on the handshake DH and 24% on a certificate verify, which
is 10-20µs once per peer pair.

Removing the choice also removed a live bug: `orbitd bootstrap` defaulted to
P256 while every `orbit agent` path defaulted to CURVE25519, so a machine
following the documented steps failed its claim with a curve mismatch. Neither
default was wrong alone, which is why it survived — two constants in two
binaries cannot notice they disagree.

**Nebula needs raw ECDH, and `tpm2-pkcs11` does not provide it.** TESTED, and
the answer is no.

`pkclient.DeriveNoise` uses `CKM_ECDH1_DERIVE` with `CKD_NULL` — no KDF, the
bare 32-byte X coordinate. This was recorded here as "should pass through, but
unverified". It does not pass through:

```
$ pkcs11-tool --module libtpm2_pkcs11.so --list-mechanisms | grep -i ecdh
(nothing)

$ pkcs11-tool --module libtpm2_pkcs11.so --derive --mechanism ECDH1-DERIVE …
error: PKCS11 function C_DeriveKey failed: rv = CKR_MECHANISM_INVALID (0x70)
```

A P-256 key created by `tpm2_ptool addkey --algorithm=ecc256` reports
`Allowed mechanisms: ECDSA, ECDSA-SHA1, ECDSA-SHA256, ECDSA-SHA384,
ECDSA-SHA512` — signing only. The module advertises no derive mechanism of any
kind.

**The gap is the bridge, not the hardware.** The same TPM reports
`TPM2_CC_ECDH_ZGen` and `TPM2_CC_ECDH_KeyGen` among its implemented commands,
and `TPM2_ECC_NIST_P256` among its curves. The chip can do exactly what nebula
needs; `tpm2-pkcs11` simply does not expose it through PKCS#11.

So a TPM-backed nebula host key is **not achievable with tpm2-pkcs11 today**,
and no amount of configuration changes that. What would: the mechanism landing
upstream in tpm2-pkcs11, or a different PKCS#11 module over the same TPM. Both
are outside Orbit — `pki.go` dispatches on the `pkcs11:` prefix and any
conforming module plugs in unmodified, so nothing here has to change when one
appears.

Verified against tpm2-pkcs11 1.9.0 (Debian trixie) with `swtpm` and
`tpm2-abrmd`. Reproduce by creating a token with `tpm2_ptool`, adding an
`ecc256` key, and running the two commands above. A hardware TPM is not needed
to re-test this: the mechanism list comes from the module.

A **PKCS#11 token that does implement `CKM_ECDH1_DERIVE`** — a YubiKey via
`ykcs11`, a SoftHSM token, an HSM — still works, and that is what the
`-tags pkcs11` build is for. It is the TPM specifically that is blocked.

### The DEVICE key, which a TPM can hold

The mesh key is blocked. **The device identity key is not**, and the difference
is the operation rather than the hardware: a device key only ever **signs**.
`tpm2-pkcs11` implements `CKM_ECDSA_SHA256` and advertises it on an `ecc256`
key; it is only the derive mechanism that is missing.

Tested, against the same software TPM: a device identity opened from a
TPM-resident key signed a join statement, and the signature verified through
`device.Verify` against the SPKI derived from the token's own EC point.

```bash
orbit agent install -device-key 'pkcs11:token=orbit;object=device-key'
```

records the URI in `device-key.ref` and writes **no private key file** — the
private half is created on the token by `tpm2_ptool` and never leaves it.
`orbit agent join` then uses whatever install recorded, on every network, so the
choice is made once per machine.

This is the more valuable half. The device key is what Orbit's identity model
rests on: joining is a signature over it, no secret travels, and a machine whose
certificate expired still gets back in because that key never expires. A stolen
disk image is no longer a stolen identity.

**Two limits, both real.**

*It is claimed, not attested.* `KeyBacking` is what the agent reports about
itself. A machine whose agent has been replaced can report `token` while using a
file. Proving TPM residency needs the TPM to certify the key — `TPM2_Certify`
under an attestation key whose own certificate chains to the manufacturer — and
that is a different feature. Treat the field as inventory, not evidence.

*A PIN in the URI is a secret on the disk.* `pin-value=` in `device-key.ref`
means anyone who can read that file can ask the chip to use the key, which is
most of what moving the key into a chip was for. Orbit writes the file `0600`
when it sees one and warns; `pin-source=` naming a `0600` file, or no PIN at all
with the module prompting, is better.

**No Nebula fork is required.** `pki.go` dispatches on the `pkcs11:` string
prefix, so any conforming PKCS#11 module plugs in unmodified. The cost is the
`cgo` and `pkcs11` build tags, which means hosts wanting hardware keys lose the
single static binary.

**EK certificates are often absent** on Intel PTT and AMD fTPM, with no fetchable
endpoint. A trust-on-first-use enrollment path is a requirement, not a
compromise.

---

## 8. Open questions

1. Does `tpm2-pkcs11` satisfy Nebula's derive template (`CKD_NULL`,
   `CKA_EXTRACTABLE`, `CKA_VALUE_LEN == 32`)? One afternoon with
   `make bin-pkcs11` and a TPM settles it.
2. What exactly goes in the user credential, and in which fields — extensions,
   SAN, or a signed claims blob?
3. What issues it: does Orbit accept an OIDC ID token, a Kerberos ticket, a PAM
   success, or all three?
4. How does the user credential reach its consumers — NSS database, Kerberos
   ccache, a local socket?
