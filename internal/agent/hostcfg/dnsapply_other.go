//go:build !linux && !darwin

package hostcfg

// applyDNS refuses where there is no supported way to change the machine's resolver.
//
// A refusal rather than a silent success. The resolver still runs and still answers
// anything that asks it directly, so `dig @<overlay-address>` works; what is missing is
// the step that makes the machine ask, and an operator should be told that rather than
// left wondering why names do not resolve.
func applyDNS(_, _, _ string, _ bool) error { return ErrDNSUnsupported }

func removeDNS(_, _ string) error { return nil }
