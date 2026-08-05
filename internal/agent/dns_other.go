//go:build !linux && !darwin

package agent

// systemResolvers has no portable answer, so the resolver forwards nothing and answers
// only mesh names. That is a worse resolver than no resolver, which is why the platforms
// that cannot read their own configuration do not get pointed at it.
func systemResolvers() []string { return nil }
