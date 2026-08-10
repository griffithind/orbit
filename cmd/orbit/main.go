// Command orbit administers an Orbit control plane.
//
// It is a separate binary from orbitd, not a set of subcommands on it, and the
// separation is the point.
//
// orbitd needs ORBIT_DSN and filesystem access to a CA signing key; it belongs
// on the control plane host and nowhere else. orbit needs a URL and a scoped
// bearer token, and belongs on a laptop or a CI runner. Merging them would put
// `orbitd token create` — which mints a "*" token straight from the database,
// bypassing every scope check, and is the documented break-glass path — on every
// operator workstation. orbitd also links internal/mesh, and through it nebula
// and gvisor, so merging would mean a `go install` of the admin CLI pulled down a
// userspace TCP/IP stack.
//
// The command tree is data, in tree.go, and `orbit --help` renders it. This
// comment deliberately does not restate it: the listing it used to carry named
// `host`, a command renamed two releases earlier, which is what a duplicated
// index does.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/griffithind/orbit/internal/version"
)

func main() {

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// No args is the same as --help, but a mistake rather than a request, so it
	// exits 2. dispatch renders it from the tree.
	args := os.Args[1:]

	root := rootCommand()

	// --version and -version are accepted here rather than in the tree because
	// they are flags in spelling and a command in effect, and putting them in
	// the table would make them a subcommand named "--version".
	if len(args) > 0 {
		switch args[0] {
		case "-version", "--version":
			fmt.Fprintln(out, version.Version)
			return
		}
	}

	err := root.dispatch(ctx, "", args)

	// Same shape as orbitd — dispatch returns an error, main prints it and
	// exits — with the one difference that the status is a class rather than
	// always 1. A caller that cannot tell a revoked token from an unreachable
	// control plane retries the wrong one.
	code, msg := exitCode(err)
	if code != exitOK && msg != "" {
		fmt.Fprintln(errOut, "orbit: "+msg)
	}
	os.Exit(code)
}

// parseFlags parses args, tolerating flags written after the operand.
//
// Go's flag package stops at the first non-flag argument, so `orbit membership rm
// web-01 -y` would silently leave -y unparsed and prompt anyway — and `orbit
// host show web-01 -json` would print human output while the operator's script
// waited for JSON. Both are worse than an error, because both look like they
// worked.
//
// So operands are lifted out and appended after the flags, which is what GNU
// getopt does and what fingers expect. Doing it correctly needs to know which
// flags take a value, which is why it walks the FlagSet rather than pattern
// matching: in `-network prod web-01`, "prod" is a value and "web-01" is the
// operand, and nothing about their spelling says so.
func parseFlags(fs *flag.FlagSet, args []string) error {
	var flags, operands []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			// Everything after it is an operand, by convention.
			operands = append(operands, args[i+1:]...)
			i = len(args)
		case len(a) > 1 && a[0] == '-':
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if n, _, found := strings.Cut(name, "="); found {
				_ = n // value came attached; nothing more to consume
				continue
			}
			// A bool flag takes no value; anything else consumes the next
			// argument. An unknown flag is left alone so flag's own error
			// message is the one the operator sees.
			f := fs.Lookup(name)
			if f == nil {
				continue
			}
			if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
				continue
			}
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		default:
			operands = append(operands, a)
		}
	}
	return fs.Parse(append(flags, operands...))
}
