package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/adminclient"
	"github.com/griffithind/orbit/internal/wire"
)

// orbit device — machines, not memberships.
//
// Every other noun in this CLI is scoped to a network, and these are not. That
// is the point: a laptop on three meshes is one machine with one disk-encryption
// state, and asking "is it encrypted" three times and getting three answers is
// the failure the device noun exists to remove. See docs/model.md §3.

func deviceLs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("device ls", flag.ContinueOnError)
	var o options
	o.bind(fs)
	gaps := fs.Bool("gaps", false, "only machines whose posture is not fully satisfied, unknowns included")
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	res, err := o.client.ListDevices(ctx)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	t := newTable(o.r,
		column{name: "HOSTNAME", elastic: true},
		column{name: "ID"},
		column{name: "OS"},
		// Versions belong to the DEVICE — a laptop on three networks runs one
		// agent — so this is where the fleet's "what is everything running"
		// question is answered. It was only visible per-membership, where the
		// same machine appears once per network.
		column{name: "AGENT"},
		column{name: "POSTURE"},
		column{name: "SEEN"},
	)
	shown := 0
	for _, d := range res.Value.Devices {
		if *gaps && postureSatisfied(d.Posture) {
			continue
		}
		shown++
		name := d.Hostname
		if d.Blocked {
			name += " (blocked)"
		}
		seen := d.LastSeenAt
		t.add(orDash(name), shortFingerprint(d.ID), orDash(d.Facts.OSVersion),
			orDash(d.Facts.AgentVersion),
			postureSummary(d.Posture, d.PostureObservedAt), ago(&seen))
	}
	if shown == 0 {
		if *gaps {
			fmt.Fprintln(out, "every machine's posture is satisfied")
		} else {
			fmt.Fprintln(out, "no devices")
		}
		return nil
	}
	t.render(out)
	return nil
}

func deviceShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("device show", flag.ContinueOnError)
	var o options
	o.bind(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit device show <device uuid>")
	}
	if err := o.load(); err != nil {
		return err
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		return usageErrorf("device show takes a uuid, as printed by `orbit device ls`: %q", fs.Arg(0))
	}

	res, err := o.client.GetDevice(ctx, id)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}
	d := res.Value

	fmt.Fprintf(out, "%s\n", o.r.bold(orDash(d.Hostname)))
	fmt.Fprintf(out, "  id           %s\n", d.ID)
	fmt.Fprintf(out, "  fingerprint  %s\n", d.KeyFingerprint)
	first, last := d.FirstSeenAt, d.LastSeenAt
	fmt.Fprintf(out, "  first seen   %s\n", ago(&first))
	fmt.Fprintf(out, "  last seen    %s\n", ago(&last))
	if d.Blocked {
		fmt.Fprintf(out, "  %s %s\n", o.r.bold("BLOCKED"), orDash(d.BlockedReason))
	}

	fmt.Fprintf(out, "\n%s\n", o.r.bold("facts"))
	fmt.Fprintf(out, "  os      %s\n", orDash(d.Facts.OSVersion))
	fmt.Fprintf(out, "  kernel  %s\n", orDash(d.Facts.Kernel))
	fmt.Fprintf(out, "  arch    %s\n", orDash(d.Facts.Arch))
	fmt.Fprintf(out, "  agent   %s\n", orDash(d.Facts.AgentVersion))
	fmt.Fprintf(out, "  nebula  %s\n", orDash(d.Facts.NebulaVersion))

	fmt.Fprintf(out, "\n%s", o.r.bold("posture"))
	if d.PostureObservedAt == nil {
		fmt.Fprintf(out, " %s\n", "(never reported)")
	} else {
		fmt.Fprintf(out, " (%s)\n", ago(d.PostureObservedAt))
	}
	fmt.Fprintf(out, "  disk encrypted  %s\n", tristate(d.Posture.DiskEncrypted))
	fmt.Fprintf(out, "  secure boot     %s\n", tristate(d.Posture.SecureBoot))
	fmt.Fprintf(out, "  firewall        %s\n", tristate(d.Posture.FirewallEnabled))
	fmt.Fprintf(out, "  tpm present     %s\n", tristate(d.Posture.TPMPresent))

	if len(d.Memberships) > 0 {
		fmt.Fprintf(out, "\n%s\n", o.r.bold("networks"))
		t := newTable(o.r,
			column{name: "NAME", elastic: true},
			column{name: "STATE"},
			column{name: "ADDRESSES"},
			column{name: "MEMBERSHIP"},
		)
		for _, m := range d.Memberships {
			t.add(m.Name, m.State, strings.Join(m.OverlayAddrs, ", "), m.MembershipID)
		}
		t.render(out)
	}
	return nil
}

func deviceBlock(ctx context.Context, args []string, unblock bool) error {
	verb := "block"
	if unblock {
		verb = "unblock"
	}
	fs := flag.NewFlagSet("device "+verb, flag.ContinueOnError)
	var o options
	o.bind(fs)
	reason := fs.String("reason", "", "recorded on the device and in the audit log")
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit device %s <device uuid>", verb)
	}
	if err := o.load(); err != nil {
		return err
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		return usageErrorf("device %s takes a uuid, as printed by `orbit device ls`: %q", verb, fs.Arg(0))
	}

	// Announced with its blast radius, because this is the one action in the
	// CLI whose scope is every network at once. `orbit membership block` cuts a
	// machine out of one mesh; this refuses it on the whole control plane.
	if !unblock {
		o.announce(fmt.Sprintf(
			"About to block device %s on EVERY network of this control plane", fs.Arg(0)))
	}

	var res adminclient.Result[wire.DeviceResponse]
	if unblock {
		res, err = o.client.UnblockDevice(ctx, id)
	} else {
		res, err = o.client.BlockDevice(ctx, id, *reason)
	}
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	fmt.Fprintf(out, "%sed device %s (%s)\n", verb, res.Value.ID, orDash(res.Value.Hostname))
	if !unblock {
		// Worth saying because it is the opposite of how every other
		// revocation in this system behaves, and an operator who expects to
		// have to wait for convergence will go looking for a gauge that is not
		// there.
		fmt.Fprintf(errOut, "\nEffective immediately: there is one enforcement point and no "+
			"propagation.\nExisting nebula tunnels are unaffected — this refuses the machine at the\n"+
			"control plane, it does not revoke certificates. To cut its traffic too:\n\n"+
			"  orbit membership rm <name>\n")
	}
	return nil
}

// tristate renders a posture signal, and never renders unknown as "no".
//
// The whole point of the *bool is that "we could not tell" and "no" are
// different, and a display that collapsed them would undo it at the last step —
// which is exactly where an operator would form the wrong belief.
func tristate(b *bool) string {
	switch {
	case b == nil:
		return "unknown"
	case *b:
		return "yes"
	default:
		return "no"
	}
}

// postureSatisfied reports whether every signal came back affirmative.
//
// Unknown counts as NOT satisfied, deliberately. `-gaps` is the command an
// operator runs to find what needs attention, and a machine that has told us
// nothing needs attention.
func postureSatisfied(p wire.DevicePosture) bool {
	for _, b := range []*bool{p.DiskEncrypted, p.SecureBoot, p.FirewallEnabled} {
		if b == nil || !*b {
			return false
		}
	}
	// TPMPresent is deliberately not part of this. It is a capability, not a
	// compliance signal: a machine without one is not misconfigured, and Orbit
	// does not use it for anything.
	return true
}

// postureSummary is the one-column form for a listing.
func postureSummary(p wire.DevicePosture, observed *time.Time) string {
	if observed == nil {
		return "never reported"
	}
	var missing []string
	for _, s := range []struct {
		label string
		val   *bool
	}{
		{"disk", p.DiskEncrypted},
		{"boot", p.SecureBoot},
		{"fw", p.FirewallEnabled},
	} {
		switch {
		case s.val == nil:
			missing = append(missing, s.label+"?")
		case !*s.val:
			missing = append(missing, "no "+s.label)
		}
	}
	if len(missing) == 0 {
		return "ok"
	}
	return strings.Join(missing, " ")
}

// resolveDevice turns what an operator typed into a device id.
//
// A device uuid, or a membership NAME. The name form exists because the uuid is
// not a handle anybody holds: an operator standing up a lighthouse knows it as
// "lh-01", and telling them to run `orbit device ls`, find the row, and paste a
// uuid in order to record its public address is a step that earns nothing. A
// name resolves within the selected network and then hops to the machine, which
// is the same hop the model makes.
func (o *options) resolveDevice(ctx context.Context, ref string) (uuid.UUID, error) {
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
	membershipID, err := o.client.ResolveHost(ctx, networkID, ref)
	if err != nil {
		return uuid.Nil, err
	}
	m, err := o.client.GetHost(ctx, membershipID)
	if err != nil {
		return uuid.Nil, err
	}
	id, err := uuid.Parse(m.Value.DeviceID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("membership %q reports device id %q, which is not a uuid", ref, m.Value.DeviceID)
	}
	return id, nil
}

// deviceSetAddrs records where a machine is reachable from outside.
//
// On the MACHINE, not on a membership, and that is the point. A lighthouse
// serving three networks has one public address; this sets it once and every
// network's config epoch moves. Setting it per membership was how a partial edit
// left half the fleet dialling somewhere nothing was listening.
func deviceSetAddrs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("device set-addrs", flag.ContinueOnError)
	var o options
	o.bind(fs)
	clear := fs.Bool("clear", false, "remove every public address, so this machine is only found by hole punching")
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}
	if (fs.NArg() < 2) == !*clear {
		return usageErrorf("usage: orbit device set-addrs <machine> <addr>...\n" +
			"       orbit device set-addrs <machine> -clear\n\n" +
			"<machine> is a device uuid from `orbit device ls`, or a membership name in\n" +
			"the selected network.\n\n" +
			"Addresses are hosts WITHOUT ports — 203.0.113.10, or a name. The port comes\n" +
			"from each membership, because two networks on one machine cannot share one.")
	}
	id, err := o.resolveDevice(ctx, fs.Arg(0))
	if err != nil {
		return err
	}

	addrs := fs.Args()[1:]
	if *clear {
		addrs = nil
	}

	o.announce(fmt.Sprintf("Setting the public addresses of device %s", id))

	res, err := o.client.SetDeviceAddrs(ctx, id, addrs)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	if len(addrs) == 0 {
		fmt.Fprintf(out, "cleared the public addresses of %s\n", res.Value.ID)
	} else {
		fmt.Fprintf(out, "%s is reachable at %s\n", res.Value.ID, strings.Join(addrs, ", "))
	}
	if len(res.Value.Memberships) > 0 {
		fmt.Fprintf(errOut, "\nEvery network this machine is on re-renders; watch it land:\n\n  orbit converge -wait 2m\n")
	}
	return nil
}
