package main

import (
	"context"
	"flag"
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
				Raw:   true,
				Run:   func(ctx context.Context, a []string) error { return statusCmd(ctx, a) },
				Flags: func(fs *flag.FlagSet) { bindStatusCmd(fs) },
			},
			{
				Name: "peers", Short: "the tunnels this host actually has, from nebula's hostmap",
				Raw:   true,
				Run:   func(ctx context.Context, a []string) error { return peersCmd(ctx, a) },
				Flags: func(fs *flag.FlagSet) { bindPeersCmd(fs) },
			},
			{
				Name: "netcheck", Short: "can this host reach the control plane, and is its clock right",
				Raw:   true,
				Run:   netcheckCmd,
				Flags: func(fs *flag.FlagSet) { bindNetcheckCmd(fs) },
			},
			{
				Name: "why", Short: "why this host can or cannot reach a peer",
				Args: "<peer> | <src> <dst>", Raw: true,
				Run:   func(ctx context.Context, a []string) error { return whyCmd(ctx, a) },
				Flags: func(fs *flag.FlagSet) { bindWhyCmd(fs, &options{}) },
			},
			{
				Name: "join", Short: "join a network — once per network",
				Long: `Promoted from "orbit agent join". Joining is a daily verb and the
noun added nothing: there is only one agent on a machine.`,
				Raw:   true,
				Run:   func(_ context.Context, a []string) error { return joinCmd(a) },
				Flags: func(fs *flag.FlagSet) { bindJoinCmd(fs) },
			},
			{
				Name: "leave", Short: "leave one network and remove its local state",
				Long: `Was "orbit agent uninstall", which read as "remove the agent" — it
removes one NETWORK, and the machine keeps serving every other one.`,
				Raw: true,
				Run: func(_ context.Context, a []string) error { return uninstallCmd(a) },
				Flags: func(fs *flag.FlagSet) {
					addDirFlags(fs)
					bindUninstallCmd(fs)
				},
			},
			{
				Name: "agent", Short: "install and run the service itself",
				Subs: []*command{
					{
						Name: "install", Short: "set this machine up: device identity, service",
						Raw:   true,
						Run:   func(_ context.Context, a []string) error { return installCmd(a) },
						Flags: func(fs *flag.FlagSet) { bindInstallCmd(fs) },
					},
					{
						Name: "run", Short: "serve every joined network: poll, apply, renew",
						Raw: true,
						Run: func(_ context.Context, a []string) error { return runCmd(a) },
						Flags: func(fs *flag.FlagSet) {
							addDirFlags(fs)
							bindRunCmd(fs)
						},
					},
					{
						Name: "enroll", Short: "re-enrol an existing membership with a code",
						Raw: true,
						Run: func(_ context.Context, a []string) error { return enrollCmd(a) },
						Flags: func(fs *flag.FlagSet) {
							addDirFlags(fs)
							bindEnrollCmd(fs)
						},
					},
				},
			},

			{
				Section: "FLEET — the control plane. Needs a token.",
				Name:    "whoami", Short: "describe the credential in use",
				Raw:   true,
				Run:   func(ctx context.Context, a []string) error { return whoamiCmd(ctx, a) },
				Flags: func(fs *flag.FlagSet) { (&options{}).bind(fs) },
			},
			{
				Name: "converge", Short: "how much of the fleet has applied the current configuration",
				Raw:   true,
				Run:   func(ctx context.Context, a []string) error { return convergeCmd(ctx, a) },
				Flags: func(fs *flag.FlagSet) { bindConvergeCmd(fs, &options{}) },
			},
			subgroup("membership", "a machine IN a network", []string{"member"}, []*command{
				declaringAdmin(leaf("ls", "list the fleet, filtered and paginated", func(ctx context.Context, a []string) error { return membershipLs(ctx, a) }), bindMembershipLs),
				declaringAdmin(leaf("show", "everything about one membership", func(ctx context.Context, a []string) error { return membershipShow(ctx, a) }), bindMembershipShow),
				withAdminFlags(leaf("pending", "memberships waiting for authorization", func(ctx context.Context, a []string) error { return membershipPending(ctx, a) })),
				declaringAdmin(mutating("authorize", "admit a pending membership", func(ctx context.Context, a []string) error { return membershipAuthorize(ctx, a) }), bindMembershipAuthorize),
				declaringAdmin(mutating("reserve", "reserve a place, printing a single-use code", func(ctx context.Context, a []string) error { return membershipReserve(ctx, a) }), bindMembershipReserve),
				declaringAdmin(mutating("set", "change role, tags, or lighthouse/relay flags", func(ctx context.Context, a []string) error { return membershipSet(ctx, a) }), bindMembershipSet),
				withAdminFlags(mutating("code", "mint a fresh enrollment code", func(ctx context.Context, a []string) error { return membershipCode(ctx, a) })),
				withAdminFlags(mutating("block", "revoke its certificates and cut it off", func(ctx context.Context, a []string) error { return membershipBlock(ctx, a, false) })),
				withAdminFlags(mutating("unblock", "lift a block", func(ctx context.Context, a []string) error { return membershipBlock(ctx, a, true) })),
				declaringAdmin(mutating("rm", "remove it permanently", func(ctx context.Context, a []string) error { return membershipRm(ctx, a) }), bindMembershipRm),
			}),
			subgroup("device", "the machines themselves, across every network", nil, []*command{
				declaringAdmin(leaf("ls", "every machine this control plane knows", func(ctx context.Context, a []string) error { return deviceLs(ctx, a) }), bindDeviceLs),
				withAdminFlags(leaf("show", "one machine and its memberships", func(ctx context.Context, a []string) error { return deviceShow(ctx, a) })),
				declaringAdmin(mutating("set-addrs", "set the public addresses peers dial", func(ctx context.Context, a []string) error { return deviceSetAddrs(ctx, a) }), bindDeviceSetAddrs),
				declaringAdmin(mutating("block", "cut a machine off every network at once", func(ctx context.Context, a []string) error { return deviceBlock(ctx, a, false) }), bindDeviceBlock),
				declaringAdmin(mutating("unblock", "lift a machine-wide block", func(ctx context.Context, a []string) error { return deviceBlock(ctx, a, true) }), bindDeviceBlock),
			}),
			subgroup("network", "networks on this control plane", nil, []*command{
				withAdminFlags(leaf("ls", "list networks", func(ctx context.Context, a []string) error { return networkLs(ctx, a) })),
			}),
			subgroup("role", "roles and their firewall rules", nil, []*command{
				withAdminFlags(leaf("ls", "list roles", func(ctx context.Context, a []string) error { return roleLs(ctx, a) })),
				withAdminFlags(leaf("show", "one role, with its rules", func(ctx context.Context, a []string) error { return roleShow(ctx, a) })),
				declaringAdmin(mutating("edit", "change a role's name, groups or firewall", func(ctx context.Context, a []string) error { return roleEdit(ctx, a) }), bindRoleEdit),
				withAdminFlags(mutating("rm", "delete a role", func(ctx context.Context, a []string) error { return roleRm(ctx, a) })),
			}),
			subgroup("policy", "the network policy document", nil, []*command{
				withAdminFlags(leaf("show", "the document in force", func(ctx context.Context, a []string) error { return policyShow(ctx, a) })),
				declaringAdmin(leaf("check", "validate a document without applying it", func(ctx context.Context, a []string) error { return policyCheck(ctx, a) }), bindPolicyCheck),
				withAdminFlags(mutating("apply", "install a document", func(ctx context.Context, a []string) error { return policyApply(ctx, a) })),
				withAdminFlags(mutating("use", "switch the network between role and policy firewalls", func(ctx context.Context, a []string) error { return policyUse(ctx, a) })),
			}),
			subgroup("ca", "certificate authorities", nil, []*command{
				declaringAdmin(mutating("create", "mint a new authority", func(ctx context.Context, a []string) error { return caCreate(ctx, a) }), bindCaCreate),
				withAdminFlags(leaf("ls", "list authorities and their state", func(ctx context.Context, a []string) error { return caLs(ctx, a) })),
				declaringAdmin(mutating("activate", "promote one to sign new certificates", func(ctx context.Context, a []string) error { return caActivate(ctx, a) }), bindCaActivate),
				withAdminFlags(mutating("retire", "stop trusting one", func(ctx context.Context, a []string) error { return caRetire(ctx, a) })),
			}),
			subgroup("route", "routes a membership advertises", nil, []*command{
				withAdminFlags(leaf("ls", "routes on a membership, or the whole network", func(ctx context.Context, a []string) error { return routeList(ctx, a) })),
				declaringAdmin(mutating("add", "advertise a prefix from a membership", func(ctx context.Context, a []string) error { return routeAdd(ctx, a) }), bindRouteAdd),
				withAdminFlags(mutating("rm", "stop advertising one", func(ctx context.Context, a []string) error { return routeRemove(ctx, a) })),
			}),
			subgroup("exit-node", "which route a membership uses for the internet", nil, []*command{
				withAdminFlags(leaf("ls", "exit nodes available to a membership", func(ctx context.Context, a []string) error { return exitNodeList(ctx, a) })),
				withAdminFlags(mutating("use", "send a membership's default route through one", func(ctx context.Context, a []string) error { return exitNodeUse(ctx, a, false) })),
				withAdminFlags(mutating("off", "stop using an exit node", func(ctx context.Context, a []string) error { return exitNodeUse(ctx, a, true) })),
			}),
			subgroup("token", "admin tokens", nil, []*command{
				withAdminFlags(leaf("ls", "list tokens", func(ctx context.Context, a []string) error { return tokenLs(ctx, a) })),
				declaringAdmin(mutating("create", "mint a scoped token", func(ctx context.Context, a []string) error { return tokenCreate(ctx, a) }), bindTokenCreate),
				withAdminFlags(mutating("revoke", "revoke one", func(ctx context.Context, a []string) error { return tokenRevoke(ctx, a) })),
			}),
			subgroup("session", "browser sessions on the operator console", nil, []*command{
				withAdminFlags(leaf("ls", "list sessions", func(ctx context.Context, a []string) error { return sessionLs(ctx, a) })),
				withAdminFlags(mutating("revoke", "end one", func(ctx context.Context, a []string) error { return sessionRevoke(ctx, a) })),
			}),
			{
				Name: "api", Short: "an authenticated request against the admin API",
				Args: "<path>", Raw: true, Mutating: true,
				Long: `Every route this CLI has not wrapped, with the profile, URL and token
already resolved. The body is emitted verbatim, so it is interchangeable with curl.`,
				Run:   apiCmd,
				Flags: func(fs *flag.FlagSet) { bindApiCmd(fs, &options{}) },
			},
			{
				Name: "audit", Short: "read the audit trail",
				Raw:   true,
				Run:   func(ctx context.Context, a []string) error { return auditCmd(ctx, a) },
				Flags: func(fs *flag.FlagSet) { bindAuditCmd(fs, &options{}) },
			},

			{
				Section: "META",
				Name:    "completion", Short: "shell completion for bash, zsh or fish",
				Args: "<shell>", Raw: true,
				Run: completionCmd,
			},
			{
				Name: "__complete", Short: "internal: completion candidates", Hidden: true,
				Raw: true,
				Run: completeCmd,
			},
			{
				Name: "version", Short: "print the build version",
				MaxArgs: 0,
				Run: func(context.Context, []string) error {
					fmt.Fprintln(out, version.Version)
					return nil
				},
			},
		},
	}
}

// subgroup is a noun with verbs under it.
//
// The verbs are real table entries now, so `orbit membership --help` and
// `orbit membership nosuch` are rendered by the same code as every other level
// — which is what removed the three dialects of "unknown subcommand" and the
// nine flag sets still named after a command renamed two releases ago.
func subgroup(name, short string, aliases []string, subs []*command) *command {
	return &command{Name: name, Short: short, Aliases: aliases, Subs: subs}
}

// leaf is one verb, still parsing its own flags.
//
// Raw because the flag definitions live in the leaf functions, which have not
// moved into the table yet. That is the remaining half of the migration and it
// is what unlocks the Mutating bit, the operand checks, and completion. Doing it
// in the same change as the restructure would have meant rewriting forty
// functions before anything could be run.
func leaf(name, short string, run func(context.Context, []string) error) *command {
	return &command{Name: name, Short: short, Raw: true, Run: run}
}

// mutating is a leaf that changes the control plane.
//
// The bit is not decoration. cmd/orbit/tree_test.go asserts that every command
// marked here calls o.announce, which is the check that would have caught the
// seven that did not — among them `membership authorize`, which admits a machine
// and allocates its address, while `membership block`, which is reversible,
// announced.
//
// Once leaves parse their flags through the table the announcement moves here
// and the test becomes unnecessary. Until then the marker and the test together
// are what make it a rule rather than a habit.

// Every leaf declares its flags to the command tree, with no exceptions and no
// default. The leaf still parses them — it needs the values — but the tree knows
// where the declarations live, so completion can build the same FlagSet without
// running the command.
//
// The rule is "no default" because the two times a default filled the gap, it
// filled it wrongly: completion listed the shared flags itself and offered
// --yes, which has never existed, and then offered --token-file for `orbit
// status`, which talks to the local agent socket and has never taken one.

// withAdminFlags marks a leaf whose only flags are the shared admin set.
func withAdminFlags(c *command) *command {
	c.Flags = func(fs *flag.FlagSet) { (&options{}).bind(fs) }
	return c
}

// declaringAdmin attaches a leaf's own flag declarations for the commands that
// also take the shared admin set. Their bind function registers both, so what
// the tree knows is the whole set the command accepts.
//
// Generic over the bind function's return so each leaf hands back a typed struct
// of pointers rather than a bag of anys.
func declaringAdmin[T any](c *command, bind func(*flag.FlagSet, *options) T) *command {
	c.Flags = func(fs *flag.FlagSet) { bind(fs, &options{}) }
	return c
}

func mutating(name, short string, run func(context.Context, []string) error) *command {
	c := leaf(name, short, run)
	c.Mutating = true
	return c
}
