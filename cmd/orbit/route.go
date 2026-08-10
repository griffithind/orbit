package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/adminclient"
	"github.com/griffithind/orbit/internal/wire"
)

// Routes: reaching things that cannot run nebula.
//
// Scoped to a membership because that is what offers one. Two machines offering
// the same prefix is how redundancy is expressed — nebula load balances across
// them and falls to a survivor — so `route add` on a second gateway is the whole
// of high availability here, with nothing else to configure.

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
	id, err := o.client.ResolveHost(ctx, networkID, ref)
	if err == nil {
		return id, nil
	}

	// A RESERVED name is not a membership yet, and saying "no membership named X" to
	// somebody who just reserved X sends them looking for a typo. Reservations
	// live in orbit.enrollment_credential; the membership row is created when
	// the machine joins with its code, so until then there is genuinely nothing
	// to attach a route to — but the reason is the lifecycle, not the name.
	//
	// Said here rather than in adminclient because this is the only caller that
	// can be sure the name was meant to be a member of THIS network.
	var nm *adminclient.NoMatchError
	if errors.As(err, &nm) {
		return uuid.Nil, fail(exitNotFound,
			"no membership named %q in this network.\n\n"+
				"If you reserved that name, it is not a membership until the machine joins\n"+
				"with its code — a reservation has no certificate, and a route needs one.\n"+
				"Check what has joined with:\n\n  orbit membership ls\n\n"+
				"already joined: %s", ref, strings.Join(nm.Available, ", "))
	}
	return uuid.Nil, err
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func routeList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("route ls", flag.ContinueOnError)
	var o options
	o.bind(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return usageErrorf("usage: orbit route ls [membership name|uuid]\n\n" +
			"With no argument, every route in the network.")
	}
	if err := o.load(); err != nil {
		return err
	}

	// NO ARGUMENT MEANS THE WHOLE NETWORK, and that is the common question.
	// Routes were listable only per membership, so "what does this fleet route"
	// could only be answered by somebody who already knew which machine to ask —
	// which is the one thing an operator looking at a route table does not know.
	var (
		res   adminclient.Result[wire.RouteListResponse]
		scope string
		err   error
	)
	if fs.NArg() == 0 {
		network, nerr := o.resolveNetwork(ctx)
		if nerr != nil {
			return nerr
		}
		networkID, perr := uuid.Parse(network.ID)
		if perr != nil {
			return perr
		}
		scope = network.Name
		res, err = o.client.ListNetworkRoutes(ctx, networkID)
	} else {
		id, rerr := o.resolveMembership(ctx, fs.Arg(0))
		if rerr != nil {
			return rerr
		}
		scope = fs.Arg(0)
		res, err = o.client.ListRoutes(ctx, id)
	}
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}
	if len(res.Value.Routes) == 0 {
		fmt.Fprintf(errOut, "%s offers no routes.\n", scope)
		return nil
	}

	// GATEWAY only when listing the network. Asked about one machine the column
	// is that machine repeated, which is noise; asked about the network it is
	// the answer to "who carries this".
	cols := []column{{name: "PREFIX", elastic: true}}
	if fs.NArg() == 0 {
		cols = append(cols, column{name: "GATEWAY"})
	}
	cols = append(cols,
		column{name: "VIA"},
		column{name: "WEIGHT"},
		column{name: "NAT"},
		column{name: "INSTALL"},
	)
	t := newTable(o.r, cols...)
	for _, r := range res.Value.Routes {
		row := []string{r.Prefix}
		if fs.NArg() == 0 {
			row = append(row, orDash(r.MembershipName))
		}
		row = append(row, orDash(r.GatewayAddr), fmt.Sprint(r.Weight),
			yesNo(r.Masquerade), yesNo(r.Install))
		t.add(row...)
	}
	t.render(out)
	return nil
}

func routeAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("route add", flag.ContinueOnError)
	var o options
	fl := bindRouteAdd(fs, &o)
	if err := parseLeaf(fs, args); err != nil {
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
		Prefix: fs.Arg(1), Weight: *fl.weight, Masquerade: *fl.masquerade, MTU: *fl.mtu,
	}
	if *fl.noInstall {
		no := false
		req.Install = &no
	}

	o.announce(fmt.Sprintf("Advertising %s from membership %s", req.Prefix, fs.Arg(0)))

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
	fs := flag.NewFlagSet("route rm", flag.ContinueOnError)
	var o options
	o.bind(fs)
	if err := parseLeaf(fs, args); err != nil {
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
	o.announce(fmt.Sprintf("About to REMOVE route %s", id))

	if err := o.client.RemoveRoute(ctx, id); err != nil {
		return err
	}
	fmt.Fprintf(out, "withdrawn\n")
	return nil
}

// routeAddFlags are the flags of `orbit routeAdd`, declared here so the
// command tree can register them: completion offers exactly the set the
// command parses, because there is only one declaration of it.
type routeAddFlags struct {
	weight     *int
	masquerade *bool
	noInstall  *bool
	mtu        *int
}

func bindRouteAdd(fs *flag.FlagSet, o *options) routeAddFlags {
	o.bind(fs)
	return routeAddFlags{
		weight: fs.Int("weight", 0,
			"share of traffic among gateways offering the SAME prefix; 0 means 1. "+
				"It does not order different prefixes against each other — "+
				"longest-prefix match does that"),
		masquerade: fs.Bool("masquerade", false,
			"NAT forwarded traffic. Usually wanted for 0.0.0.0/0 and usually not "+
				"for a LAN prefix, where the far side can be told a static route"),
		noInstall: fs.Bool("no-install", false,
			"do not put this route in consumers' system routing tables"),
		mtu: fs.Int("mtu", 0, "per-route MTU; 0 uses the tun's"),
	}
}
