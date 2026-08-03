package nebulacfg

import (
	"github.com/griffithind/orbit/internal/policy"
)

// Policy compilation reaches the rendered config here.
//
// The whole integration is one substitution: a network with a policy renders
// the compiled rules in place of the role's, and a network without one renders
// exactly what it rendered before. Opt-in, and the two paths do not interact.

// FirewallFromPolicy converts a compiled ruleset into the firewall this mode
// can honestly render.
//
// THE OUTBOUND DECISION, which is the interesting part.
//
// Orbit's DefaultFirewall emits {port: any, proto: any, host: any} OUTBOUND. A
// compiled outbound rule sitting next to that allow-all accomplishes nothing.
//
//   - In ModeAuthoritative Orbit writes the only file, so the allow-all is
//     Orbit's own choice and it is dropped. Both halves of every allowance are
//     rendered: the flow is closed unless BOTH ends agree, which is the defence
//     in depth nebula offers here and the reason the compiler emits two halves
//     at all. This does mean a host reaches nothing it was not named for, so
//     the compiler's management floor — the control plane's agent API — is not
//     optional; see policy.Compiler.Management.
//
//   - In ModeFragment nebula CONCATENATES firewall lists across files, so rules
//     can only ever be added. Orbit cannot remove its own allow-all from an
//     operator's merged view, and cannot see whether the operator wrote one
//     too. A narrow outbound rule there would be decoration: it would change no
//     packet's fate while reading, in a review, exactly like enforcement. So
//     fragment mode renders the inbound half only and keeps the allow-all it
//     always had. Policy in fragment mode is enforced at the RECEIVER.
//
// The asymmetry is the honest one: the mode already decides whether Orbit's
// document is the whole policy or a lower bound, and this is that same fact
// showing up in the output.
func FirewallFromPolicy(rs policy.Ruleset, mode string) *Firewall {
	fw := &Firewall{
		Inbound:  make([]Rule, 0, len(rs.Inbound)),
		Outbound: make([]Rule, 0, len(rs.Outbound)),
	}
	for _, r := range rs.Inbound {
		fw.Inbound = append(fw.Inbound, ruleFromPolicy(r))
	}

	if mode == ModeFragment {
		fw.Outbound = DefaultFirewall().Outbound
		return fw
	}
	for _, r := range rs.Outbound {
		fw.Outbound = append(fw.Outbound, ruleFromPolicy(r))
	}
	return fw
}

func ruleFromPolicy(r policy.Rule) Rule {
	return Rule{
		Port:      r.Port,
		Proto:     r.Proto,
		CIDR:      r.CIDR,
		LocalCIDR: r.LocalCIDR,
	}
}
