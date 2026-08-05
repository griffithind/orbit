//go:build !linux && !darwin

package agent

// applyDNS and removeDNS do nothing where there is no supported way to change the
// machine's resolver. The resolver still runs and still answers anything that asks it
// directly; what is missing is the step that makes the machine ask.
func applyDNS(_, _, _ string, _ bool) error { return nil }
func removeDNS(_, _ string) error           { return nil }
