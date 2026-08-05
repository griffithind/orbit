package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

// Routes: reaching things that cannot run nebula.
//
// Scoped to a membership because that is what offers one. Two machines offering
// the same prefix is how redundancy is expressed — nebula load balances across
// them and falls to a survivor — so `route add` on a second gateway is the whole
// of high availability here, with nothing else to configure.

const routeVerbs = "ls, add, rm"

func routeCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageErrorf("usage: orbit route <%s>", routeVerbs)
	}
	switch args[0] {
	case "ls":
		return routeList(ctx, args[1:])
	case "add":
		return routeAdd(ctx, args[1:])
	case "rm":
		return routeRemove(ctx, args[1:])
	default:
		return usageErrorf("unknown route command %q; want one of: %s", args[0], routeVerbs)
	}
}

// resolveMembership turns a name or uuid into a membership id, in the selected
// network. The same hop `orbit membership set` makes.
func (o *options) resolveMembership(ctx context.Context, ref string) (uuid.UUID, error) {
	if id, err := uuid.Parse(ref); err == nil {
		return id, nil
	}
	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	networkID, err := uuid.Parse(network.ID)
	if err != nil {
		return uuid.Nil, err
	}
	return o.client.ResolveHost(ctx, networkID, ref)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func routeList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("route ls", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit route ls <membership name|uuid>")
	}
	if err := o.load(); err != nil {
		return err
	}

	id, err := o.resolveMembership(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	res, err := o.client.ListRoutes(ctx, id)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}
	if len(res.Value.Routes) == 0 {
		fmt.Fprintf(errOut, "%s offers no routes.\n", fs.Arg(0))
		return nil
	}

	t := newTable(o.r,
		column{name: "PREFIX", elastic: true},
		column{name: "VIA"},
		column{name: "WEIGHT"},
		column{name: "NAT"},
		column{name: "INSTALL"},
	)
	for _, r := range res.Value.Routes {
		t.add(r.Prefix, orDash(r.GatewayAddr), fmt.Sprint(r.Weight),
			yesNo(r.Masquerade), yesNo(r.Install))
	}
	t.render(out)
	return nil
}

func routeAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("route add", flag.ExitOnError)
	var o options
	o.bind(fs)
	var (
		weight = fs.Int("weight", 0,
			"share of traffic among gateways offering the SAME prefix; 0 means 1. "+
				"It does not order different prefixes against each other — "+
				"longest-prefix match does that")
		masquerade = fs.Bool("masquerade", false,
			"NAT forwarded traffic. Usually wanted for 0.0.0.0/0 and usually not "+
				"for a LAN prefix, where the far side can be told a static route")
		noInstall = fs.Bool("no-install", false,
			"do not put this route in consumers' system routing tables")
		mtu = fs.Int("mtu", 0, "per-route MTU; 0 uses the tun's")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return usageErrorf("usage: orbit route add <membership name|uuid> <prefix>\n\n" +
			"Example: orbit route add lab-pi 192.168.88.0/24")
	}
	if err := o.load(); err != nil {
		return err
	}

	id, err := o.resolveMembership(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	req := wire.CreateRouteRequest{
		Prefix: fs.Arg(1), Weight: *weight, Masquerade: *masquerade, MTU: *mtu,
	}
	if *noInstall {
		no := false
		req.Install = &no
	}

	res, err := o.client.AddRoute(ctx, id, req)
	if err != nil {
		if api, ok := isConflict(err); ok {
			return fail(exitConflict, "%s already offers %s (%s)",
				fs.Arg(0), fs.Arg(1), api.Message)
		}
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	fmt.Fprintf(out, "%s now offers %s\n", res.Value.MembershipName, res.Value.Prefix)

	// The certificate is the authority, and it is the half an operator forgets.
	// A route stored here reaches nobody until the gateway holds a certificate
	// carrying the prefix — which means its next enrollment, and a CA that
	// permits it.
	fmt.Fprintf(errOut,
		"\nThe route takes effect when %s next renews its certificate: nebula "+
			"requires the prefix to be IN that certificate, and the CA must permit "+
			"it.\nIf the CA was created without -unsafe-networks covering %s, "+
			"enrollment will refuse it and say so.\n\nWatch it land:\n\n  orbit converge -wait 2m\n",
		res.Value.MembershipName, res.Value.Prefix)
	return nil
}

func routeRemove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("route rm", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit route rm <route uuid>\n\n" +
			"The uuid is printed by `orbit route ls -json`.")
	}
	if err := o.load(); err != nil {
		return err
	}
	id, err := uuid.Parse(strings.TrimSpace(fs.Arg(0)))
	if err != nil {
		return usageErrorf("route rm takes a route uuid: %q", fs.Arg(0))
	}
	if err := o.client.RemoveRoute(ctx, id); err != nil {
		return err
	}
	fmt.Fprintf(out, "withdrawn\n")
	return nil
}
