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

const deviceVerbs = "ls, show, block, unblock"

func deviceCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return subUsage("device",
			"ls        list every machine this control plane knows",
			"show      one machine: its posture, and the networks it is on",
			"block     refuse a machine everywhere on this control plane",
			"unblock   allow a blocked machine again")
	}
	switch args[0] {
	case "ls":
		return deviceLs(ctx, args[1:])
	case "show":
		return deviceShow(ctx, args[1:])
	case "block":
		return deviceBlock(ctx, args[1:], false)
	case "unblock":
		return deviceBlock(ctx, args[1:], true)
	default:
		return unknownSub("device", args[0], deviceVerbs)
	}
}

func deviceLs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("device ls", flag.ExitOnError)
	var o options
	o.bind(fs)
	gaps := fs.Bool("gaps", false, "only machines whose posture is not fully satisfied, unknowns included")
	if err := parseFlags(fs, args); err != nil {
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
		column{name: "KEY"},
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
			d.KeyBacking, postureSummary(d.Posture, d.PostureObservedAt), ago(&seen))
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
	fs := flag.NewFlagSet("device show", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
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
	// Labelled "claimed" because it is. A host says where it holds its key and
	// nothing yet proves it, and a column that reads as a fact would be the one
	// an operator builds a rollout plan on.
	fmt.Fprintf(out, "  key          %s (claimed)\n", d.KeyBacking)
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
	fs := flag.NewFlagSet("device "+verb, flag.ExitOnError)
	var o options
	o.bind(fs)
	reason := fs.String("reason", "", "recorded on the device and in the audit log")
	if err := parseFlags(fs, args); err != nil {
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
	// CLI whose scope is every network at once. `orbit host block` cuts a
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
			"  orbit host rm <name>\n")
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
	// compliance signal: a machine without one is not misconfigured, it is a
	// machine that cannot hold a hardware-backed key.
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
