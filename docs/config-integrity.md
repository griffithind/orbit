# Config integrity

How a machine knows the configuration it is running is the one the control plane
sent, and what happens when it is not.

---

## 1. What is broken today

The agent asks for new material only when the epoch it holds differs from the
one the control plane reports (`internal/agent/loop.go`, the poll path around
line 860). It then reports back the epoch it *received*.

Nothing reads what is on disk.

So:

```
operator edits /etc/orbit/prod/nebula.yml, reloads nebula
control plane: "prod-01 is at config epoch 47"     ← believes it converged
prod-01:       running something nobody rendered
```

The divergence is not detected, not reported, and not corrected. It persists
until some unrelated change bumps the epoch, at which point the edit vanishes
with no record that it was ever there. Both halves of that are bad: the fleet
view is wrong while the edit is live, and the edit disappears silently when it
ends.

This is the concrete problem. "Sign the config" is one answer to it, and the
rest of this document is about which parts of the problem signing actually
solves.

---

## 2. What signing can and cannot do

**Root on the machine wins.** A user with root can stop the agent, edit nebula's
binary, drop the tun device, or run a nebula of their own. No signature changes
that, and a design that claims otherwise is lying about its threat model.

What signing buys is narrower and still worth having:

| Property | Signing gives it? |
|---|---|
| The machine can tell whether its config is the control plane's | **Yes** |
| A divergence is reported rather than silent | **Yes** — the agent has something to report |
| A config can be delivered over a transport that is not trusted | **Yes** — this is the big one |
| A stale config cannot be replayed forward | **Yes**, with epoch binding |
| One machine's config cannot be installed on another | **Yes**, with membership binding |
| Root cannot change what nebula runs | **No** |
| Root cannot read the config | **No** |

The honest framing is **detection and refusal, not prevention**. An operator who
edits the file gets a machine that refuses to run the edit and a control plane
that says so — which is the outcome the current design gets wrong, and is
achievable. "Root cannot subvert its own machine" is not.

---

## 3. Sign, or encrypt?

**Sign. Do not encrypt.**

Encryption at rest on the agent is theatre against the only attacker who
matters. The config has to be handed to nebula in cleartext, so the key must be
on the machine, so root reads both. It buys nothing over file permissions and
costs a key-management problem.

Encryption *in transit* is a property of the transport, not of the config, and
today the transport is already confidential: the agent API is overlay-only
(`design.md` §10), so it runs inside a nebula tunnel. If the agent API ever
leaves the data plane — which is the open question in item 2 of this refactor —
the answer is TLS on the new transport, not a bespoke envelope around the YAML.

The config is not secret in any case. It contains firewall rules, lighthouse
addresses and group names: useful reconnaissance, not credentials. The
certificate and the private key are separate files and the key never travels.

---

## 4. What signs it

**The network identity key** — Ed25519, generated at bootstrap, never rotated,
stored in the vault (`internal/vault`, `key-custody.md`).

It is the right key and there is no close second:

- **The agent already verifies it at join.** `verifyNetwork`
  (`internal/agent/client.go`) checks that the key hashes to the network ID and
  that the join proof verifies under it, *before* acting on anything the control
  plane said. The trust anchor is already established, out of band, at the one
  moment a machine is most careful.
- **It is not the CA key.** A config signature is not a certificate, and reusing
  the CA key would make one compromise two.
- **It never rotates**, so a verifier never has to handle a key change — which
  matters because a machine that cannot verify its config is a machine that
  cannot start.

**The one change required: the agent must keep it.** Today `verifyNetwork`
checks the key and throws it away. The network public key has to be persisted in
`agent.json` beside `MembershipID`, and — this is the part that carries the
security — **it must be written once at join and never updated from a
response.** A key the control plane can replace on any poll is not a trust
anchor; it is a suggestion.

---

## 5. What is covered

Signing the config bytes alone is not enough. Three attacks survive it:

| Attack | Defeated by binding in |
|---|---|
| Install machine A's config on machine B | `membership_id` |
| Replay epoch 12 over epoch 47 to restore a firewall hole | `config_epoch` |
| Pair a valid config with a different trust bundle | SHA-256 of the CA bundle |

**Binding a field is only half of it — the verifier has to read it.** The first
version of this had `membership_id` in the envelope and nothing comparing it,
which is worth stating because the gap is invisible: every signature verified,
every test passed, and machine A's genuinely-signed generation installed on
machine B. Two hosts with the same role are handed byte-identical configs, so
nothing about the bytes distinguishes them. `TestAGenerationDoesNotTransplantBetweenMachines`
is what found it, and it is the reason `VerifyMaterial` takes the membership id
as an argument rather than as context.

So the signed statement is an envelope, not the file:

```
orbit-config-v1
network_id
membership_id
config_epoch
blocklist_epoch
sha256(config bytes)
sha256(ca bundle)
```

length-prefixed and canonically encoded, exactly as `device.JoinStatement`
already is — and for the same reason it was made length-prefixed after a test
caught the ambiguity: a delimiter-joined encoding lets two different field sets
produce identical bytes.

---

## 6. The problem that makes this non-trivial

**The agent rewrites the config after receiving it.**

`Applier.localize` (`internal/agent/generation/apply.go:477`) substitutes three path
strings — `pki.ca`, `pki.cert`, `pki.key` — because the control plane renders
canonical paths and cannot know where this host keeps its files, or whether its
key is a file at all (a PKCS#11 host substitutes a URI).

So the bytes on disk are *not* the bytes that were signed, and a naive
"verify nebula.yml against the signature" fails on every host.

Three ways out, and the reason for the choice:

1. **Have the control plane render the real paths.** It cannot: it does not know
   them, and `model.md`'s rule says a fact belongs to the narrowest noun that
   determines it. The layout is the agent's fact.
2. **Sign the localized form.** Same problem — the control plane would have to
   produce it.
3. **Keep the signed original, and make the live file a deterministic function
   of it.** ✅

Concretely, alongside `nebula.yml` the agent keeps:

- `nebula.yml.signed` — the exact bytes the control plane sent
- `nebula.yml.sig` — the envelope and its signature

and verification is:

```
verify signature over envelope, under the pinned network key
check sha256(nebula.yml.signed) matches the envelope
localize(nebula.yml.signed) == nebula.yml      ← byte comparison
```

The third line is what catches the operator's edit. `localize` is a pure
function of the signed bytes and the layout, so re-deriving it is cheap and
total: there is no part of the live file it does not account for.

---

## 7. When it is checked

| Moment | Why |
|---|---|
| Before installing a generation | The existing `validateStaged` step already refuses a config nebula will not load; this refuses one the control plane did not send |
| At agent startup | The machine may have been edited while the agent was stopped, which is exactly when someone would do it |
| On every poll | A hash comparison, so it costs nothing, and it is the only thing that turns a silent divergence into a reported one |

On mismatch the agent **refuses to treat the local file as current, re-fetches,
and reports the divergence.** It does not stop nebula: a running tunnel is not
made safer by dropping it, and an agent that halts the mesh because a file has
an extra newline is an agent that gets disabled.

The report is the point. `Convergence` (`design.md` §6) gates CA rotation and
backs the revocation SLO, and both are computed from epochs the agent
self-reports. A machine that reports epoch 47 while running an edit corrupts
that number. With this, it reports the divergence instead.

---

## 7a. Nebula never reads the file

Everything above detects an edit. This prevents one.

The agent used to verify the config and write it, and nebula would then
**independently re-read that file** (`config.C.Load`). Verification was therefore
advisory: an edit between the check and the read won, root could `SIGHUP` nebula
without the agent involved, and stopping the agent stopped the checking.

Nebula is now given no path. `Applier.VerifiedConfig` reads the signed original,
verifies it against the pinned network key, inlines `pki.ca`, `pki.cert` and
`pki.key` as PEM, and hands nebula the bytes (`config.C.LoadString`) — on every
start and every reload. `nebula.yml` on disk is a record for people to read.
Editing it changes nothing, because nothing reads it.

This is what `internal/mesh` already did for the control plane. The agent was the
half still reading a file.

`TestEditingTheConfigFileChangesNothing` asserts the file is inert;
`TestATamperedSignedConfigIsNeverLoaded` asserts the signed original is checked
before a byte reaches nebula.

**The ceiling is unchanged.** Root can still stop the agent and run its own
nebula with the key file, replace the agent binary, or ptrace it. What this
guarantees is narrower and worth having: *Orbit's nebula only ever runs
control-plane-authored configuration.*

---

## 8. What this unlocks

Item 2 of this refactor asked whether the control plane ↔ agent channel should
leave the data plane. It has not, and the reason it cannot today is that the
agent trusts the channel to authenticate the config: identity is the source
overlay address, which nebula's firewall verifies per packet
(`firewall.go Drop`).

A signed config inverts that. The material carries its own proof, so the
transport only has to deliver bytes. That makes a public-internet agent
endpoint, a CDN, a config baked into a machine image, or a USB stick all equally
sound — and it removes the bootstrap ordering problem where reaching the overlay
requires a lighthouse that has to be enrolled over the overlay.

**That is the reason to do this**, more than the tamper detection. The tamper
case is a bug fix; this is a change in what the system can be.

---

## 9. What it does not solve

- **Root.** Stated in §2 and worth repeating, because a signed config invites
  the belief that the machine is now under control. It is not; it is now
  *honest*.
- **A compromised control plane.** It holds the identity key, so it signs
  whatever it likes. Same as `design.md` §10's "code execution in Orbit" row,
  and not made worse: that attacker already mints certificates.
- **Downgrade to no signature at all.** An agent that accepts unsigned material
  "for compatibility" has no property here. The rollout has to end with
  unsigned material refused, and the interim has to be short and version-gated.

---

## 10. Order of work

1. Persist the network public key at join, write-once. *(No behaviour change;
   everything else depends on it.)*
2. Control plane signs; response carries the envelope and signature.
3. Agent verifies before applying, keeps `.signed` and `.sig`, refuses material
   that does not verify.
4. Startup and per-poll disk check; report divergence.
5. Remove the unsigned path.
6. Only then, revisit item 2 — the transport.

Steps 1 to 4 are **built**. Step 5 is deliberately not: a host that has pinned a
key already requires a valid signature with no way to opt out, and a host that
has not pinned one warns and accepts. That second case is the only unsigned path
left, it closes at that host's next renewal, and it exists so that upgrading the
control plane does not strand every host that enrolled before signing existed.
When no host in a fleet is unpinned, the branch can go.

### Where it lives

| Piece | Code |
|---|---|
| Nebula loads verified bytes, never a path | `agent.Applier.VerifiedConfig`, `agent.Embedded.Config` |
| Envelope, canonical encoding, sign and verify | `internal/ca/configsig.go` |
| Control plane signs every generation | `enroll.Service.signMaterial` |
| The pinned key, write-once | `agent.State.NetworkKey` |
| Gate before every apply | `agent.Loop.checkMaterial` |
| Disk check and self-heal | `agent.Applier.VerifyInstalled`, `agent.Loop.checkInstalled` |
| The signed original and its proof | `nebula.signed.yml`, `nebula.sig.json` |
