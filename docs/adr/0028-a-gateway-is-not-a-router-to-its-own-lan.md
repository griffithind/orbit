# ADR-0028: A gateway is not a router to its own LAN

**Status:** Proposed
**Date:** 2026-08-12

## Context

Orbit has two firewalls and it is worth being precise about which does what, because the code
currently describes a division of labour it does not implement.

**Nebula's per-packet firewall** is the policy enforcement point: in-process, certificate-bound,
allow-only, stateful, configured entirely from the rendered `firewall:` section. It sees every
packet crossing the tun including forwarded traffic, in both directions. Its deny-by-default
guarantee is real — an empty rule set drops everything, verified by tracing `newFirewallTable`
through `FirewallTable.match` to `ErrNoMatchingRule`, and confirmed by executing a zero-rule
`Firewall.Drop` for tcp/udp/icmp/any in both directions.

**The host firewall** is `nft table inet orbit`, and it contains **one chain**:

```
chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  iifname "<tun>" ip daddr <prefix> counter masquerade
}
```

emitted only when there is something to masquerade (`hostcfg/hoststate_linux.go:107-123`). There
is no forward chain, no input chain, no filter chain anywhere — a grep for `hook forward`,
`hook input` or `type filter` across `internal/agent/` returns nothing. A forward-only gateway
renders an empty table.

Three places say otherwise. `forward_linux.go:33-34` describes the "neither firewalld nor ufw"
case as falling back to "our own forward chain, which works precisely because nothing else is
going to drop after us". `forward_linux_test.go:11-12` asserts "Orbit writes its own forward
chain". `CHANGELOG.md:295-300` repeats it. What is actually sufficient is the **kernel's default
FORWARD ACCEPT policy**, and `ensureForwardAllowed`'s default branch is a bare `return nil` that
never checks whether that policy still holds. Any host where something else holds a DROP at the
forward hook — Docker sets `iptables -P FORWARD DROP` by default; k3s, Calico and Cilium
likewise — forwards nothing while `orbit status` reports the gateway working. Nothing in the
agent mentions any of them.

**And on an exit node, nothing keeps a mesh peer out of the gateway's own LAN.** The only
constraint on a forwarded destination is nebula's `local_cidr`. An exit node's certificate
carries `0.0.0.0/0` as an unsafe network (`internal/enroll/service.go:660`), so
`routableNetworks` contains every address and nebula's local-address check stops rejecting
anything. The only way to express "may use the exit node" is `dst: [cidr:0.0.0.0/0]` —
`docs/routes-and-exit-nodes.md:217-220` says so explicitly — which compiles to
`local_cidr: 0.0.0.0/0` on the gateway. That covers the gateway's LAN, all of RFC1918,
link-local including `169.254.169.254`, and the gateway's own non-overlay addresses.

No narrowing is expressible. `docs/policy-model.md:280-302` documents an `except:` clause across
twenty lines with a worked example and a validator error message; `policy.Entry` has no `Except`
field, and `parseEntry` uses `DisallowUnknownFields`, so `except:` is a hard parse error. Nebula
has no deny rule at all.

Tailscale's netfilter layer is no better here — `ts-forward` accepts everything tun-sourced with
no destination restriction. Their enforcement is in the userspace filter, and the exit-node case
is handled explicitly: on an advertised `0.0.0.0/0` they subtract every non-Tailscale interface
prefix (`shrinkDefaultRoute`, `ipn/ipnlocal/local.go:3649-3672`) and then deliberately re-add the
host's own IPs, with the rationale at `:3407-3427`:

> we filter out locally reachable LANs, so that the default route effectively appears to be a
> "guest wifi": you get internet access, but to additionally get LAN access the LAN(s) need to be
> offered explicitly as well.

The honest comparison: management ports on the gateway are reachable in both designs; the LAN is
subtracted in Tailscale and is not in Orbit.

## Decision

**A `0.0.0.0/0` allowance compiles to a `local_cidr` set with the gateway's directly-connected
LANs, loopback and link-local subtracted, and an explicit per-route opt-in to add them back.**
This is `shrinkDefaultRoute` computed on the control plane, and it needs no nebula change:
nebula's grammar already lets one entry emit several narrow `local_cidr` rules instead of one
wide one.

**The host firewall's role is named, and made true.** Either Orbit owns a filter chain in the
conventional `filter` table, jumped from the top of the base chain — Tailscale's shape, and
their stated reasoning at `util/linuxfw/nftables_runner.go:55-64` is exactly the one Orbit's
comment gives for *not* doing it — or Orbit explicitly detects a foreign DROP at the forward
hook and fails loudly. What stops is silently depending on an absence nothing checks. The three
comments describing the chain that is not there are deleted either way.

**`except:` is implemented or its twenty lines of documentation are deleted.** A documented
clause that is a parse error is worse than an undocumented limitation, and it is the exact
capability the LAN-subtraction decision above needs an operator to be able to express by hand.

## Alternatives considered

**Set `firewall.default_local_cidr_any: true` and treat the exit node as unrestricted.**
Rejected for the reason ADR-0021 rejects it: it converts a silent deny into a silent allow, and
it makes every rule on every gateway apply to every routed subnet.

**Rely on operators writing narrow `dst:` entries.** Rejected because the only vocabulary
available is `cidr:0.0.0.0/0` — the docs say so — and because the subtraction depends on the
gateway's runtime interface set, which an operator writing policy does not have.

**Put the LAN subtraction in the agent, where the interface list actually lives.** Genuinely
appealing, and it is where Tailscale does it. Rejected because the resulting rules must be inside
the signed generation for ADR-0012's guarantee to hold — a locally computed firewall is a
firewall the control plane cannot attest to. The agent reports its interface prefixes; the
control plane does the arithmetic.

**Own a filter chain in a private `inet` table.** Rejected on the diagnosis Orbit already made
correctly: `accept` is not terminal in nftables, so a private table's accept falls through to
whatever else is at that hook. That diagnosis is right; the conclusion drawn from it — that Orbit
therefore cannot own a filter chain — does not follow, and Tailscale's jump-from-the-conventional-
table shape is the counterexample.

## Consequences

Exit nodes stop being a path to the gateway's LAN, which will break any deployment currently
relying on that as an undocumented feature — reaching a printer or a NAS "through" the exit node
will stop working until the LAN is offered as its own route. That is the correct shape and it is
a visible behaviour change.

The control plane needs the gateway's directly-connected prefixes, which means the agent reports
them and the render consumes them. That is a new input to the generation and therefore a new
epoch trigger under ADR-0022, and it means a gateway that changes networks re-renders.

Owning a filter chain in the conventional table is a larger commitment than the private table:
Orbit would be creating base chains it does not own if they are absent, which is what Tailscale
does and what the current design was written to avoid.

What would trigger revisiting: nebula gaining deny rules. The whole shape here — subtract at
compile time, emit many narrow allows — is a workaround for an allow-only firewall with no
subtraction.

## References

- `internal/agent/hostcfg/hoststate_linux.go:107-123` — the one chain that exists
- `internal/agent/hostcfg/forward_linux.go:33-34, 49-55` — the chain that does not, and the unchecked absence
- `internal/enroll/service.go:660` — `0.0.0.0/0` entering the gateway's certificate
- `docs/routes-and-exit-nodes.md:217-220` — `dst: [cidr:0.0.0.0/0]` as the only vocabulary
- `docs/policy-model.md:280-302` — `except:`, documented and unparseable
- Tailscale `ipn/ipnlocal/local.go:3407-3427, 3649-3672` — `shrinkDefaultRoute` and its rationale
- Tailscale `util/linuxfw/nftables_runner.go:55-64` — why the jump-from-conventional-table shape exists
- ADR-0012 (policy compiles to addresses), ADR-0021 (gateway reachability), ADR-0022
