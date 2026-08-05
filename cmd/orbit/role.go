package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/adminclient"
	"github.com/griffithind/orbit/internal/wire"
)

const roleVerbs = "ls, show, edit, rm"

func roleCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return subUsage("role",
			"ls     list the roles in a network",
			"show   one role, with its groups and firewall rules",
			"edit   change a role's name, groups, or firewall",
			"rm     delete a role no host carries")
	}
	switch args[0] {
	case "ls":
		return roleLs(ctx, args[1:])
	case "show":
		return roleShow(ctx, args[1:])
	case "edit":
		return roleEdit(ctx, args[1:])
	case "rm":
		return roleRm(ctx, args[1:])
	default:
		return unknownSub("role", args[0], roleVerbs)
	}
}

func roleLs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("role ls", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	networkID, err := o.networkID(ctx)
	if err != nil {
		return err
	}
	res, err := o.client.ListRoles(ctx, networkID)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	t := newTable(o.r,
		column{name: "NAME", elastic: true},
		column{name: "GROUPS"},
		column{name: "FIREWALL"},
		column{name: "ID", optional: true},
	)
	for _, r := range res.Value {
		t.add(r.Name, strings.Join(r.Groups, ","), firewallSummary(r.Firewall), r.ID)
	}
	if t.empty() {
		fmt.Fprintln(errOut, "no roles in this network")
		return nil
	}
	t.render(out)
	return nil
}

// firewallSummary counts the rules rather than printing them. A listing has room
// for "3 in / 1 out"; the rules themselves are what `role show` is for.
func firewallSummary(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "-"
	}
	var fw struct {
		Inbound  []json.RawMessage `json:"inbound"`
		Outbound []json.RawMessage `json:"outbound"`
	}
	if err := json.Unmarshal(raw, &fw); err != nil {
		return "(unparsed)"
	}
	return fmt.Sprintf("%d in / %d out", len(fw.Inbound), len(fw.Outbound))
}

func roleShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("role show", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit role show <name|uuid>")
	}
	if err := o.load(); err != nil {
		return err
	}

	networkID, err := o.networkID(ctx)
	if err != nil {
		return err
	}
	roleID, err := o.client.ResolveRole(ctx, networkID, fs.Arg(0))
	if err != nil {
		return err
	}
	res, err := o.client.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	r := res.Value
	fmt.Fprintln(out, o.r.bold(r.Name))
	fmt.Fprintf(out, "%-10s %s\n", "id", r.ID)
	fmt.Fprintf(out, "%-10s %s\n", "network", r.NetworkID)
	fmt.Fprintf(out, "%-10s %s\n", "groups", strings.Join(r.Groups, ", "))
	fmt.Fprintln(out, "firewall")
	if len(r.Firewall) == 0 {
		fmt.Fprintln(out, "  (none)")
		return nil
	}
	fmt.Fprintln(out, indent(prettyJSON(r.Firewall), "  "))

	// Which hosts carry it, because that is the number that decides whether an
	// edit is cheap: a firewall change converges in seconds, a group change costs
	// every one of these hosts a certificate lifetime.
	hosts, err := o.client.ListHosts(ctx, adminclient.MembershipFilter{
		NetworkID: networkID, RoleID: &roleID, Count: true, Limit: 1,
	})
	if err == nil {
		n := 0
		if hosts.Value.TotalCount != nil {
			n = *hosts.Value.TotalCount
		}
		fmt.Fprintf(out, "\n%-10s %d host(s)\n", "carried by", n)
	}
	return nil
}

func roleEdit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("role edit", flag.ExitOnError)
	var o options
	o.bind(fs)
	var (
		name     = fs.String("name", "", "new name")
		groups   = fs.String("groups", "", "comma separated groups, replacing the current set")
		firewall = fs.String("firewall", "", "path to a JSON firewall document, or - for stdin")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit role edit <name|uuid> [-name x] [-groups a,b] [-firewall file]")
	}
	supplied := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { supplied[f.Name] = true })
	if onlyGlobals(supplied) {
		return usageErrorf("nothing to change; set -name, -groups, or -firewall")
	}
	if err := o.load(); err != nil {
		return err
	}

	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}
	networkID, err := uuid.Parse(network.ID)
	if err != nil {
		return err
	}
	roleID, err := o.client.ResolveRole(ctx, networkID, fs.Arg(0))
	if err != nil {
		return err
	}

	// Pointer fields, and only for what was supplied. wire.UpdateRoleRequest is
	// built that way so "not supplied" differs from "set to empty" — and for a
	// role the difference is not cosmetic: an accidental empty firewall rewrites
	// the rules on every host carrying it.
	var req wire.UpdateRoleRequest
	if supplied["name"] {
		req.Name = name
	}
	if supplied["groups"] {
		g := csvList(*groups)
		req.Groups = &g
	}
	if supplied["firewall"] {
		raw, err := readFirewall(*firewall)
		if err != nil {
			return err
		}
		req.Firewall = &raw
	}

	o.announce(fmt.Sprintf("Editing role %q in network %s", fs.Arg(0), network.Name))

	res, err := o.client.UpdateRole(ctx, roleID, req)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	v := res.Value
	if !v.Changed {
		fmt.Fprintf(out, "%s is unchanged; nothing was written and no agent was woken\n", v.Name)
		return nil
	}
	fmt.Fprintf(out, "updated %s (%s)\n", v.Name, v.ID)

	if !v.Accepted {
		fmt.Fprintf(errOut, "\nFirewall and configuration changes reach every host on its next poll.\n")
		return nil
	}

	// 202. The configuration half of this edit is live and the certificate half
	// is not: groups are carried in the signed certificate, so every host keeps
	// the previous set until it renews. This is a success — exit 0 — but an
	// operator who reads "updated" and walks away has drawn the wrong conclusion
	// about when their policy change is in force, so it is said unmistakably.
	fmt.Fprintf(errOut, `
%s

  groups are carried in the signed certificate, so this change is NOT yet in
  force on hosts that already hold one.

  hosts awaiting a certificate  %d
  last one renews by            %s

  %s

  To force a host sooner, revoke its certificate:  orbit host block <name>
  Watch the configuration half land:               orbit converge -wait 5m
`,
		o.r.bold("ACCEPTED, NOT YET IN FORCE"),
		v.MembershipsAwaitingCertificate,
		orDash(v.CertificatesConvergeBy),
		v.Detail)
	return nil
}

// readFirewall loads a firewall document from a file or stdin.
//
// Validated as JSON here only for a readable error; the server validates it
// strictly against nebula's schema, which is the check that matters. Nebula
// silently ignores keys it does not recognise, so a typo becomes a rule with a
// different meaning than its author wrote — and this side cannot know the schema
// without duplicating it.
func readFirewall(path string) (json.RawMessage, error) {
	var (
		raw []byte
		err error
	)
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, usageErrorf("-firewall: %v", err)
	}
	if !json.Valid(raw) {
		return nil, usageErrorf("-firewall: %s is not valid JSON", path)
	}
	return json.RawMessage(raw), nil
}

func roleRm(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("role rm", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit role rm <name|uuid>")
	}
	if err := o.load(); err != nil {
		return err
	}

	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}
	networkID, err := uuid.Parse(network.ID)
	if err != nil {
		return err
	}
	roleID, err := o.client.ResolveRole(ctx, networkID, fs.Arg(0))
	if err != nil {
		return err
	}

	o.announce(fmt.Sprintf("About to DELETE role %q in network %s", fs.Arg(0), network.Name))
	if err := o.confirm(fmt.Sprintf("Delete role %s? This cannot be undone.", fs.Arg(0))); err != nil {
		return err
	}

	if err := o.client.DeleteRole(ctx, roleID); err != nil {
		if api, ok := isConflict(err); ok {
			// The whole value of rendering this one: the server names the hosts
			// still carrying the role, and behind curl that is a wall of JSON
			// under an "error" key nobody scrolls past.
			hosts := api.BlockingHosts()
			var b strings.Builder
			fmt.Fprintf(&b, "role %s is still assigned to %d host(s):\n", fs.Arg(0), len(hosts))
			for _, h := range hosts {
				// Name and id: the name is what an operator recognises, the id
				// is what the next command takes.
				fmt.Fprintf(&b, "  %-28s %s\n", truncate(h.Name, 28), h.ID)
			}
			b.WriteString("\nReassign them first, one at a time:\n\n" +
				"  orbit host set <host> -role <other-role>\n\n" +
				"Deleting it would change the firewall on every one of them at once, which " +
				"is why the database refuses.")
			return fail(exitConflict, "%s", b.String())
		}
		return err
	}

	fmt.Fprintf(out, "deleted role %s\n", fs.Arg(0))
	return nil
}
