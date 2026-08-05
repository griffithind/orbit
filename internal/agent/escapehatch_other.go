//go:build !linux && !darwin

package agent

// pinSocket does nothing where there are no exit nodes to escape from.
func pinSocket(_ string, _ uintptr, _ int) error { return nil }
