package main

import (
	"context"
	"flag"
	"fmt"
)

// Exit nodes: send everything through a gateway, deliberately.
//
// The choice is a REQUEST to the control plane, not a local edit, and that is
// the design rather than an implementation detail. The agent runs only what the
// control plane signed, so a default route injected on the machine is exactly
// what that guarantee exists to prevent. `use` patches the membership, the
// epoch bumps, and the route arrives in the next signed configuration.
//
// So the command is local and the authority is not — which is also why `ls`
// shows what is OFFERED rather than what is permitted: policy still decides
// whether this machine may reach 0.0.0.0/0 through that gateway, and choosing
// one it may not use produces a default route that carries nothing.

const exitNodeVerbs = "ls, use, off"

func exitNodeCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageErrorf("usage: orbit exit-node <%s>", exitNodeVerbs)
	}
	switch args[0] {
	case "ls":
		return exitNodeList(ctx, args[1:])
	case "use":
		return exitNodeUse(ctx, args[1:], false)
	case "off":
		return exitNodeUse(ctx, args[1:], true)
	default:
		return usageErrorf("unknown exit-node command %q; want one of: %s", args[0], exitNodeVerbs)
	}
}

func exitNodeList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("exit-node ls", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit exit-node ls <membership name|uuid>")
	}
	if err := o.load(); err != nil {
		return err
	}

	id, err := o.resolveMembership(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	res, err := o.client.ExitNodes(ctx, id)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}
	if len(res.Value.Available) == 0 {
		fmt.Fprintf(errOut, "No exit nodes in this network.\n\n"+
			"One is an ordinary route for 0.0.0.0/0:\n\n"+
			"  orbit route add <gateway> 0.0.0.0/0 -masquerade\n\n"+
			"The CA must permit it, which is decided when the CA is created.\n")
		return nil
	}

	t := newTable(o.r,
		column{name: "ROUTE", elastic: true},
		column{name: "VIA"},
		column{name: "NAT"},
		column{name: "IN USE"},
	)
	for _, r := range res.Value.Available {
		// The FULL id. It was shortened with shortFingerprint, which is right for
		// a 64-hex digest and wrong for a uuid: a fingerprint is a handle nobody
		// retypes, an id is the argument the very next command takes. Truncated,
		// the hint below named something the table above could not supply.
		t.add(r.ID, orDash(r.GatewayAddr), yesNo(r.Masquerade),
			yesNo(r.ID == res.Value.CurrentRouteID))
	}
	t.render(out)

	// A command that can be run, not a shape to fill in. If exactly one route is
	// on offer there is nothing to choose, so choose it in the example.
	if len(res.Value.Available) == 1 {
		fmt.Fprintf(errOut, "\n  orbit exit-node use %s %s\n",
			fs.Arg(0), res.Value.Available[0].ID)
	} else {
		fmt.Fprintf(errOut, "\n  orbit exit-node use %s <ROUTE from the first column>\n", fs.Arg(0))
	}
	return nil
}

func exitNodeUse(ctx context.Context, args []string, clear bool) error {
	name := "exit-node use"
	if clear {
		name = "exit-node off"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	want := 2
	if clear {
		want = 1
	}
	if fs.NArg() != want {
		if clear {
			return usageErrorf("usage: orbit exit-node off <membership name|uuid>")
		}
		return usageErrorf("usage: orbit exit-node use <membership name|uuid> <route uuid>\n\n" +
			"Route uuids come from `orbit exit-node ls`.")
	}
	if err := o.load(); err != nil {
		return err
	}

	id, err := o.resolveMembership(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	routeID := ""
	if !clear {
		routeID = fs.Arg(1)
	}
	if err := o.client.SetExitNode(ctx, id, routeID); err != nil {
		return err
	}

	if clear {
		fmt.Fprintf(out, "%s is back on its local internet\n", fs.Arg(0))
		return nil
	}
	fmt.Fprintf(out, "%s will send all traffic through the exit node\n", fs.Arg(0))

	// The thing that is not automatic, said where somebody will read it.
	// Choosing an exit node is not being allowed to use one, and the symptom of
	// confusing them is a default route that silently carries nothing.
	fmt.Fprintf(errOut, "\nIt takes effect on the next poll. What this does NOT do:\n\n"+
		"  - grant access. Policy still decides whether %s may reach 0.0.0.0/0\n"+
		"    through that gateway; if it may not, the route carries nothing.\n",
		fs.Arg(0))
	return nil
}
