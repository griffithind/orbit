//go:build !darwin

package dataplane

import (
	"log/slog"

	"github.com/slackhq/nebula/udp"
)

// newListenerFactory returns nil everywhere but darwin: nebula opens its own listener and
// keeps its own datapath, including the batched recvmmsg reads on Linux that a gateway
// under load depends on.
//
// Linux reaches the same end by a different means — listen.so_mark on the socket and an
// ip rule to act on it, installed and owned by the host-state layer. Taking the socket
// over there would trade a documented, upstream-maintained path for a hand-rolled one, on
// the platform where being wrong costs the most.
func newListenerFactory(_ *slog.Logger, _ bool) udp.ListenerFactory { return nil }
