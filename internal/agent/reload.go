package agent

import (
	"context"
)

// NoopReloader does nothing. Used when something else owns the nebula process
// lifecycle, such as a test harness or an operator who reloads by hand.
type NoopReloader struct{}

func (NoopReloader) Reload(context.Context) error { return nil }
func (NoopReloader) Describe() string             { return "none" }

// ReloaderFunc adapts a function to the Reloader interface. Useful for tests
// and for embedding the agent in a process that owns nebula itself.
type ReloaderFunc struct {
	Name string
	Fn   func() error
}

func (r ReloaderFunc) Reload(context.Context) error { return r.Fn() }

func (r ReloaderFunc) Describe() string {
	if r.Name == "" {
		return "func"
	}
	return r.Name
}
