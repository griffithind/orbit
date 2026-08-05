//go:build !linux

package agent

// Not a gateway platform.
//
// A Mac can USE routes — nebula installs them on darwin itself — and that path
// needs nothing from this file. What it cannot do is ADVERTISE one: forwarding
// and NAT here mean pf anchors and a different sysctl namespace, and shipping a
// half-tested version of that would produce a gateway that looks configured and
// drops packets.
//
// Refusing is the honest behaviour. A machine told to forward that silently
// does not is a network where some packets vanish and the reason is three
// layers from the symptom.

type unsupportedConfigurer struct{}

// NewHostConfigurer returns a configurer that refuses to act as a gateway.
func NewHostConfigurer(log logger) HostConfigurer { return unsupportedConfigurer{} }

func (unsupportedConfigurer) Describe() string { return "unsupported on this platform" }

func (unsupportedConfigurer) Apply(h HostState) error {
	if h.Empty() {
		// Nothing asked for, so nothing to refuse. This is every ordinary Mac.
		return nil
	}
	return ErrHostStateUnsupported
}

// Remove has nothing to undo, and says so by succeeding. Uninstall must not
// fail on a machine that was never a gateway.
func (unsupportedConfigurer) Remove() error { return nil }

type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}
