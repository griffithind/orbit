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
// Commands:
//
//	whoami    describe the credential in use
//	host      list, inspect, create, edit, enroll, block, and decommission hosts
//	converge  how much of the fleet has applied the current configuration
//	network   list networks
//	role      list, inspect, edit, and delete roles
//	policy    read, check, and apply the network policy document
//	ca        list, activate, and retire certificate authorities
//	token     list, mint, and revoke admin tokens
//	session   list and end browser sessions on the operator console
//	audit     read the audit trail
//	agent     join a network, keep its nebula configuration current
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
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "whoami":
		err = whoamiCmd(ctx, os.Args[2:])
	case "membership", "member":
		err = membershipCmd(ctx, os.Args[2:])
	case "device":
		err = deviceCmd(ctx, os.Args[2:])
	case "route":
		err = routeCmd(ctx, os.Args[2:])
	case "converge":
		err = convergeCmd(ctx, os.Args[2:])
	case "network":
		err = networkCmd(ctx, os.Args[2:])
	case "role":
		err = roleCmd(ctx, os.Args[2:])
	case "policy":
		err = policyCmd(ctx, os.Args[2:])
	case "ca":
		err = caCmd(ctx, os.Args[2:])
	case "token":
		err = tokenCmd(ctx, os.Args[2:])
	case "session":
		err = sessionCmd(ctx, os.Args[2:])
	case "agent":
		err = agentCmd(ctx, os.Args[2:])
	case "status":
		err = statusCmd(ctx, os.Args[2:])
	case "peers":
		err = peersCmd(ctx, os.Args[2:])
	case "why":
		err = whyCmd(ctx, os.Args[2:])
	case "audit":
		err = auditCmd(ctx, os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version.Version)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "orbit: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(exitUsage)
	}

	// Same shape as orbitd — dispatch returns an error, main
	// prints it and exits — with the one difference that the status is a class
	// rather than always 1. A caller that cannot tell a revoked token from an
	// unreachable control plane retries the wrong one.
	code, msg := exitCode(err)
	if code != exitOK && msg != "" {
		fmt.Fprintln(os.Stderr, "orbit: "+msg)
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprint(os.Stderr, `orbit <command> [flags]

  whoami     describe the credential in use
  membership ls, show, pending, authorize, reserve, set, code, block, unblock, rm
             a machine IN a network. Aliased as "member"
  device     ls, show, block, unblock — the machines themselves, across every network
  converge   how much of the fleet has applied the current configuration
  network    ls
  role       ls, show, edit, rm
  policy     show, check, apply, use
  ca         ls, activate, retire
  token      ls, create, revoke
  session    ls, revoke — browser sessions on the operator console
  audit      read the audit trail
  agent      install, uninstall, join, enroll, run — what runs ON a managed host
  status     what the agent on THIS host is doing, on every network it joined
  peers      the tunnels THIS host actually has, from nebula's own hostmap
  why        why THIS host can or cannot reach a peer
  version    print the build version

Every command takes -json, which emits the API response verbatim.

Configuration:
  ORBIT_URL         control plane admin URL           (or -url)
  ORBIT_TOKEN       admin token                       (or ORBIT_TOKEN_FILE, -token-file)
  ORBIT_NETWORK     network name or uuid              (or -network)
  ORBIT_CONFIG      profile file, default ~/.config/orbit/config.yaml

There is no -token flag: an argument is visible in ps to every user on the box.

Run "orbit <command> -h" for flags.
`)
}

// parseFlags parses args, tolerating flags written after the operand.
//
// Go's flag package stops at the first non-flag argument, so `orbit host rm
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

// subUsage renders a command group's verbs. Kept in the same shape as usage() so
// the two do not drift into different styles.
func subUsage(group string, verbs ...string) error {
	var b []byte
	b = fmt.Appendf(b, "orbit %s <subcommand> [flags]\n\n", group)
	for _, v := range verbs {
		b = fmt.Appendf(b, "  %s\n", v)
	}
	b = fmt.Appendf(b, "\nRun \"orbit %s <subcommand> -h\" for flags.\n", group)
	os.Stderr.Write(b)
	// No message: the listing above is the message, and prefixing "orbit: no
	// subcommand given" under it says nothing the empty invocation did not.
	return &exitError{code: exitUsage}
}

// unknownSub is the same listing, for a verb that does not exist.
func unknownSub(group, sub string, verbs ...string) error {
	_ = subUsage(group, verbs...)
	return usageErrorf("unknown %s subcommand %q", group, sub)
}
