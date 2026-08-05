# Design: device identity, joining, and talking to the control plane

Status: **built.** `docs/model.md` §6 records what landed and in what order; this
document is the reasoning behind it, kept because the reasoning is what a future
change has to argue against.

One part is designed and NOT built: the verifiable network ID in §4. It commits
to a network identity key that nothing generates yet, so `orbit agent join`
takes a network uuid or slug today.

---

## 1. Three identities, not one

| | What it says | Issued by | Lifetime | Scope |
|---|---|---|---|---|
| **Device** | this is a specific machine | nobody — self-generated | permanent | global to the machine |
| **Membership** | this machine belongs to that network | the control plane | hours | one network |
| **User** | this person, on that machine | the control plane | minutes | one session |

The device identity is the new one, and the fact that **nobody issues it** is the
whole point.

A host generates its device key on first start, before it has joined anything
and before it has heard of a control plane. That key is the same across every
network the host joins and every control plane it talks to. It is not a
credential in the sense of granting access — it grants the right to *ask*.

This is ZeroTier's node identity, and the reason to copy it is that it breaks a
circularity the previous design only moved. See §2.

---

## 2. What it fixes

The agent surface is reachable only over the overlay, so a host needs a working
tunnel to renew the certificate that gives it a working tunnel. `orbit agent
recover` exists to break that circle.

The earlier proposal was a control-plane certificate with a longer life than the
mesh certificate. That works until it doesn't: two expiring credentials still
both expire, and the loop returns on a longer timescale.

A device identity that **never expires and is never issued** cannot fail that
way. A host can always reach the control plane, because reaching it uses
something no authority granted and no clock invalidates.

Two consequences worth stating plainly:

- **Certificate expiry stops being a lockout.** The host authenticates with its
  device key and renews normally. `orbit agent recover` becomes unnecessary.
- **Reporting survives a broken data plane.** Today a host whose mesh is down
  cannot report that its mesh is down; the control plane sees silence, which is
  indistinguishable from a closed laptop. Everything posture collection is for
  becomes reportable from exactly the hosts worth hearing from.

---

## 3. The flow

```
first start        orbit generates a device key           (no network, no control plane)
                   → device.key, never leaves the host

join               orbit join <network-id> -url <cp>      (optionally: -code <enrollment code>)
                   → control plane records the device public key
                   → host row created in state `pending`

authorize          admin approves, from CLI or web        (or: skipped, if a valid code was presented)
                   → device certificate issued for the device key
                   → nebula certificate issued for a freshly generated mesh key
                   → host becomes active

steady state       mTLS to the control plane with the device certificate
                   nebula tunnel with the membership certificate
                   the two fail independently
```

### Why the enrollment code survives

Join-and-authorize moves the gate from "holds a credential" to "an admin says
yes". That is better in that no secret has to travel, and worse in that
unattended provisioning stops working and somebody must watch a queue.

So both. A join that carries a valid enrollment code is **auto-authorized**;
one that does not lands in `pending`. The code becomes optional
pre-authorization rather than the only door, and the existing single-use,
15-minute, HMAC-stored machinery (`internal/enroll/credential.go`) is reused
rather than replaced.

---

## 4. Network IDs

ZeroTier's network ID encodes the controller's address in its top 40 bits, so
`join <id>` needs nothing else. That does not transfer: an Orbit control plane
is a URL, not a routable identity, so the URL is a separate argument regardless.

What *does* transfer, and is worth more than brevity: **derive the network ID
from a key the control plane can prove it holds.**

```
network id = crockford_base32( truncate( sha256(network identity public key) ) )
```

### Not the CA key — a correction

The first draft of this section said "the CA's public key". That is wrong, and
the reason is worth recording because it is easy to re-derive incorrectly.

Orbit rotates CAs: `POST /v1/cas`, activate, retire. A rotation gives the
network a new CA with a new key, so an ID derived from the active CA **changes
on every rotation** — every host's stored ID becomes wrong at once, and
verification fails fleet-wide. An identifier that changes is not an identifier.

So the ID commits to a **network identity key**: generated once at bootstrap,
never rotated, and never used to sign a certificate. Its only jobs are to name
the network and to prove, during a join, that the control plane answering is the
one the ID names.

The alternative considered and rejected was a **rotation chain** — ID commits to
the founding CA, each outgoing CA signs its successor's public key, and a
joining host walks the chain. More elegant, no second key, and rotation is
authenticated by the key being rotated out, which is how key rotation normally
works. Rejected because a CA key destroyed before it signs a successor breaks
the chain permanently, and that puts an unrecoverable failure mode in the
rotation path.

**Handle the identity key like the CA key.** Someone holding it can convince a
*joining* host that their control plane is this network. They still cannot mint
certificates for the existing fleet — that needs the CA key — but "new hosts
join the attacker instead" is close enough to full compromise to warrant the
same storage, the same encryption at rest, and the same care.

Then the ID is not a label, it is a **commitment to a trust anchor**. A host
joining `orb_7f3k9m2q4x8w1` can check that whatever control plane answers
actually holds the CA that ID names. Pointing a host at a hostile URL stops
working — which a UUID plus a URL cannot defend against today, because nothing
in either one says which key to expect.

Crockford base32 because it excludes the glyphs people confuse (I/L/O/U) and
because it is case-insensitive on input. Someone reads these over the phone.

This sits **beside** `Network.slug`, which is the human name and the directory
name on every host. Different jobs: the slug is memorable, the ID is verifiable.

---

## 5. Revocation: blocklist, not expiry

Nebula's blocklist is expensive because it has to reach every node — which is
why short certificate lifetimes are the revocation story for mesh membership.

The device identity is the opposite. There is exactly **one** enforcement point
and it is the process holding the database, so a blocklist check is a lookup it
is already making. Revocation is immediate rather than TTL-bounded, with no
propagation problem at all.

The device certificate still carries a long expiry — a year — but that expiry is
**garbage collection, not revocation**. It is what lets a blocklist entry be
pruned: once the certificate it names cannot be presented, the entry is dead
weight. Without it the blocklist grows forever.

Blocking a **device** blocks it on this control plane, across every network.
Blocking a **host** blocks one membership. Both are useful and they are not the
same action.

---

## 6. No proof of work

ZeroTier derives its 40-bit address from a memory-hard function so the space
cannot be swept, addresses cannot be farmed, and nobody can grind for one that
collides with a target. That matters because ZeroTier identities are
**self-assigned and permissionless**.

Orbit's are neither. Host IDs are UUIDs the control plane assigns; the device
certificate is issued, not claimed; and joining is gated by an admin or a code.
There is no space to sweep and nothing to farm, so a PoW would cost battery on
every laptop and buy nothing.

The instinct behind it — *make identity creation prove something real* — is
right, and **TPM attestation is the strictly better version**. Proof of work
proves someone spent CPU, which anyone with CPU can do. Attestation proves the
key lives in hardware you can name, which cannot be forged at any price. That is
already the plan; this is the same idea done properly.

---

## 7. Properties to accept deliberately

**Correlation across control planes.** One device key everywhere means two
colluding control planes can tell they are looking at the same machine.
ZeroTier has the same property. Acceptable for a self-hosted fleet, and it
should be a decision rather than a discovery.

**A pending queue is a queue.** Joins that carry no code accumulate until
someone looks. That is a denial-of-attention surface if a network ID leaks:
anyone who knows it can create rows. Mitigations are rate limiting per source
and per network, and a bound on pending rows — neither is exotic, but neither is
free, and it is the cost of the door being open.

**The device key is only as good as its storage.** In a file it is copyable off
a disk image, which is the same weakness the mesh key has today. In a TPM it is
not. The design does not require hardware; it makes hardware worth having, and
the difference must be stated per host rather than implied fleet-wide.

---

## 8. What this took

The sequence, and what each step could not be moved before, is recorded in
[model.md](model.md) §6. All six landed. The two that were load-bearing:

`orbit.membership.device_id` could not become `NOT NULL` until nothing could
create a membership without a device — which meant deleting `POST /v1/hosts`
first, because migrations are tracked by name with no checksum and an
already-migrated database never re-runs a file. The constraint would have passed
every local test and failed a fresh deployment on its first host creation.

`orbit agent recover` could not be deleted until re-joining was proven to
replace it, which is why `TestExpiredCertificateRecoversByRejoining` was written
and made to pass *before* anything was removed.

## 9. What is not built

1. **The verifiable network ID** of §4. It commits to a network identity key
   that nothing generates yet, so `orbit agent join` takes a network uuid or
   slug. Until it exists, pointing a machine at a hostile URL is defended by
   nothing — which a uuid plus a URL never defended against either, so this is a
   gap the design closes rather than one it opened.
2. **An offline network identity key.** Considered and dropped rather than
   deferred — the identity key lives in the vault with the CA key. The network
   ID is therefore **replaceable, not permanent**: the agent verifies it at join
   and does not persist it, so retiring a compromised one is a change to one
   argument, and machines keep their memberships. `key-custody.md` §4.2 has the
   full reasoning.
3. **The device certificate and mTLS to the control plane.** `internal/ca` can
   issue one (`IssueDeviceCert`), and nothing presents one yet: the join and
   claim endpoints authenticate a raw signature instead, which is sufficient for
   what they do and does not require a second PKI on day one. mTLS is what would
   let the *steady-state* agent API leave the overlay.
4. **Attestation.** `key_backing` records what a machine claims about where its
   key lives, and nothing proves it. See `credential-model.md` §6 for what is
   observed versus asserted today.
