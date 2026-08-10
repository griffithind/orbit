package main

import (
	"context"
	"fmt"

	"github.com/griffithind/orbit/internal/version"
)

// The command tree.
//
// Three tiers, and the tier is legible from the command itself:
//
//   - NODE commands act on this machine. No token, usually root.
//   - FLEET commands act on the control plane. A token, never root.
//   - META commands are about the tool.
//
// The daily verbs sit at the top level and the rest are noun-verb. That is
// Tailscale's shape and it is right here for the same reason: a fixed noun set
// wants noun-verb (Docker restructured in 1.13 because a flat verb space
// collapsed), but the eight or nine things typed every day should not need a
// noun first. `orbit join`, not `orbit agent join`.
//
// `converge` stays a bare verb deliberately. It is typed more often than
// everything under `network` combined, and burying it would be the same mistake
// in the other direction.

func rootCommand() *command {
	return &command{
		Name:  "orbit",
		Short: "administer an Orbit control plane, and the agent on this host",
		Long: `Configuration, in precedence order: flag, environment, profile.
  ORBIT_URL         control plane admin URL           (or --url)
  ORBIT_TOKEN       admin token                       (or ORBIT_TOKEN_FILE, --token-file)
  ORBIT_NETWORK     network name or uuid              (or --network)
  ORBIT_CONFIG      profile file, default ~/.config/orbit/config.yaml

There is no --token flag: an argument is visible in ps to every user on the box.`,
		Subs: []*command{
			{
				Section: "NODE — this machine. No token; usually needs root.",
				Name:    "status", Short: "what this host is doing, on every network it joined",
				Raw: true,
				Run: func(ctx context.Context, a []string) error { return statusCmd(ctx, a) },
			},
			{
				Name: "peers", Short: "the tunnels this host actually has, from nebula's hostmap",
				Raw: true,
				Run: func(ctx context.Context, a []string) error { return peersCmd(ctx, a) },
			},
			{
				Name: "why", Short: "why this host can or cannot reach a peer",
				Args: "<peer> | <src> <dst>", Raw: true,
				Run: func(ctx context.Context, a []string) error { return whyCmd(ctx, a) },
			},
			{
				Name: "join", Short: "join a network — once per network",
				Long: `Promoted from "orbit agent join". Joining is a daily verb and the
noun added nothing: there is only one agent on a machine.`,
				Raw: true,
				Run: func(_ context.Context, a []string) error { return joinCmd(a) },
			},
			{
				Name: "leave", Short: "leave one network and remove its local state",
				Long: `Was "orbit agent uninstall", which read as "remove the agent" — it
removes one NETWORK, and the machine keeps serving every other one.`,
				Raw: true,
				Run: func(_ context.Context, a []string) error { return uninstallCmd(a) },
			},
			{
				Name: "agent", Short: "install and run the service itself",
				Subs: []*command{
					{
						Name: "install", Short: "set this machine up: device identity, service",
						Raw: true,
						Run: func(_ context.Context, a []string) error { return installCmd(a) },
					},
					{
						Name: "run", Short: "serve every joined network: poll, apply, renew",
						Raw: true,
						Run: func(_ context.Context, a []string) error { return runCmd(a) },
					},
					{
						Name: "enroll", Short: "re-enrol an existing membership with a code",
						Raw: true,
						Run: func(_ context.Context, a []string) error { return enrollCmd(a) },
					},
				},
			},

			{
				Section: "FLEET — the control plane. Needs a token.",
				Name:    "whoami", Short: "describe the credential in use",
				Raw: true,
				Run: func(ctx context.Context, a []string) error { return whoamiCmd(ctx, a) },
			},
			{
				Name: "converge", Short: "how much of the fleet has applied the current configuration",
				Raw: true,
				Run: func(ctx context.Context, a []string) error { return convergeCmd(ctx, a) },
			},
			group("membership", "a machine IN a network", []string{"member"}, membershipCmd),
			group("device", "the machines themselves, across every network", nil, deviceCmd),
			group("network", "networks on this control plane", nil, networkCmd),
			group("role", "roles and their firewall rules", nil, roleCmd),
			group("policy", "the network policy document", nil, policyCmd),
			group("ca", "certificate authorities", nil, caCmd),
			group("route", "routes a membership advertises", nil, routeCmd),
			group("exit-node", "which route a membership uses for the internet", nil, exitNodeCmd),
			group("token", "admin tokens", nil, tokenCmd),
			group("session", "browser sessions on the operator console", nil, sessionCmd),
			{
				Name: "audit", Short: "read the audit trail",
				Raw: true,
				Run: func(ctx context.Context, a []string) error { return auditCmd(ctx, a) },
			},

			{
				Section: "META",
				Name:    "version", Short: "print the build version",
				MaxArgs: 0,
				Run: func(context.Context, []string) error {
					fmt.Fprintln(out, version.Version)
					return nil
				},
			},
		},
	}
}

// group adapts a command that still does its own subcommand dispatch.
//
// Transitional. The leaves have not moved into the table yet, so these keep
// their existing switch and their existing help; what they gain immediately is
// the corrected top-level structure and one consistent unknown-command message.
// Migrating them is mechanical and independent, one group per change.
func group(name, short string, aliases []string, run func(context.Context, []string) error) *command {
	return &command{
		Name: name, Short: short, Aliases: aliases,
		Args: "<subcommand>", Raw: true,
		Run: func(ctx context.Context, a []string) error { return run(ctx, a) },
	}
}
