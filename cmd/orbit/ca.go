package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

const caVerbs = "create, ls, activate, retire"

func caCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return subUsage("ca",
			"create     mint a new CA, ready to distribute but not yet signing",
			"ls         list a network's certificate authorities",
			"activate   promote a CA to signing",
			"retire     drop a CA from distribution once nothing it signed is live")
	}
	switch args[0] {
	case "create":
		return caCreate(ctx, args[1:])
	case "ls":
		return caLs(ctx, args[1:])
	case "activate":
		return caActivate(ctx, args[1:])
	case "retire":
		return caRetire(ctx, args[1:])
	default:
		return unknownSub("ca", args[0], caVerbs)
	}
}

// caCreate mints a CA. It does not start signing with it.
//
// The two steps are the whole of rotation: every host must hold the new CA before
// anything is signed by it, or the first machine to renew gets a certificate its peers do
// not trust and drops off the mesh. `orbit ca activate` is the second step, and it
// refuses while hosts are still behind.
//
// This is also the only way to widen what gateways may route. UnsafeNetworks is signed
// into the certificate, so it cannot be edited — adding a prefix later means a new CA and
// a rotation. Deciding it here is cheaper than discovering it after ten machines have
// joined.
func caCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ca create", flag.ExitOnError)
	var o options
	o.bind(fs)
	var (
		days = fs.Int("days", 0,
			"certificate lifetime; 0 uses the network's default")
		networks = fs.String("networks", "",
			"comma-separated overlay prefixes subordinates may claim; "+
				"empty uses the network's own CIDRs")
		groups = fs.String("groups", "",
			"comma-separated groups subordinates may claim; empty means unconstrained")
		unsafe = fs.String("unsafe-networks", "",
			"comma-separated EXTERNAL prefixes gateways signed by this CA may route, "+
				"e.g. 192.168.88.0/24,0.0.0.0/0. Empty permits none. This CANNOT be "+
				"widened later — it is signed into the certificate, so adding a prefix "+
				"means another CA and another rotation")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit ca create <name>\n\n" +
			"Example, for a network that will test a LAN route and an exit node:\n" +
			"  orbit ca create lab-ca -unsafe-networks 192.168.88.0/24,0.0.0.0/0")
	}
	if err := o.load(); err != nil {
		return err
	}

	networkID, err := o.networkID(ctx)
	if err != nil {
		return err
	}
	res, err := o.client.CreateCA(ctx, networkID, wire.CreateCARequest{
		Name:           fs.Arg(0),
		Days:           *days,
		Networks:       splitCSV(*networks),
		Groups:         splitCSV(*groups),
		UnsafeNetworks: splitCSV(*unsafe),
	})
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	fmt.Fprintf(out, "created %s (%s)\n", res.Value.Name, res.Value.Fingerprint)
	if len(res.Value.UnsafeNetworks) > 0 {
		fmt.Fprintf(out, "  may route: %s\n", strings.Join(res.Value.UnsafeNetworks, ", "))
	} else {
		fmt.Fprintf(out, "  may route: nothing. Gateways signed by this CA cannot carry routes.\n")
	}

	// The half an operator forgets, said where they will read it. A CA that
	// exists and is not activated signs nothing, and a CA activated before its
	// hosts have it partitions them off the mesh.
	fmt.Fprintf(errOut, "\nIt is NOT signing yet. Hosts pick it up on their next poll; once they\n"+
		"have it:\n\n  orbit ca activate %s\n", res.Value.Name)
	return nil
}

func caLs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ca ls", flag.ExitOnError)
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
	res, err := o.client.ListCAs(ctx, networkID)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	// FINGERPRINT is a column of its own, not a detail behind `show`, because it
	// is the only unique handle a CA has besides its uuid: orbit.ca constrains
	// (network_id, fingerprint) and says nothing about name, and a rotation is
	// exactly when two of them are called the same thing.
	t := newTable(o.r,
		column{name: "NAME", elastic: true},
		column{name: "FINGERPRINT"},
		column{name: "STATE"},
		column{name: "CERTS", right: true},
		column{name: "NOT AFTER"},
		column{name: "ID", optional: true},
	)
	dupes := map[string]int{}
	for _, c := range res.Value {
		dupes[c.Name]++
	}
	for _, c := range res.Value {
		t.add(c.Name, shortFingerprint(c.Fingerprint), c.State,
			strconv.Itoa(c.ActiveCertificates), c.NotAfter, c.ID)
	}
	if t.empty() {
		fmt.Fprintln(errOut, "no certificate authorities in this network")
		return nil
	}
	t.render(out)

	for name, n := range dupes {
		if n > 1 {
			fmt.Fprintf(errOut,
				"\nnote: %d CAs are named %q. Names are not unique within a network, so pass a\n"+
					"fingerprint prefix to `orbit ca activate` and `orbit ca retire`.\n", n, name)
		}
	}
	return nil
}

// caActivate promotes a CA to signing.
//
// The 409 here is the single best argument for this CLI existing. The server
// refuses while hosts have not applied the new CA — promoting past them signs
// their next certificate with an authority they do not trust, which partitions
// them off the mesh — and it puts the lagging hosts in the response body. Through
// curl that body is a wall of JSON, and the names in it are the only actionable
// part.
func caActivate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ca activate", flag.ExitOnError)
	var o options
	o.bind(fs)
	ack := fs.Bool("acknowledge-cutoff", false,
		"promote even though hosts have not converged, cutting them off (emergency use; audited separately)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit ca activate <name|fingerprint-prefix|uuid> [-acknowledge-cutoff]")
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
	ca, err := o.client.ResolveCA(ctx, networkID, fs.Arg(0))
	if err != nil {
		return err
	}
	caID, err := uuid.Parse(ca.ID)
	if err != nil {
		return err
	}

	o.announce(fmt.Sprintf("About to ACTIVATE CA %q (%s) in network %s",
		ca.Name, shortFingerprint(ca.Fingerprint), network.Name))

	// Only the override is prompted. A plain activation is gated by the server's
	// own convergence check, so the failure mode is a refusal; the override
	// removes that gate and its outcome — hosts cut off the mesh — cannot be
	// undone by deactivating, because their certificates will already have been
	// signed by the new authority.
	if *ack {
		if err := o.confirm(fmt.Sprintf(
			"-acknowledge-cutoff skips the convergence check. Every host that has not applied "+
				"CA %s will be cut off the mesh at its next renewal. Continue?",
			shortFingerprint(ca.Fingerprint))); err != nil {
			return err
		}
	}

	res, err := o.client.ActivateCA(ctx, caID, *ack)
	if err != nil {
		if api, ok := isConflict(err); ok {
			lagging := api.Lagging()
			var b strings.Builder
			fmt.Fprintf(&b, "%d host(s) have not applied CA %s yet; promoting it now would cut them off:\n\n",
				len(lagging), shortFingerprint(ca.Fingerprint))

			t := newTable(o.r,
				column{name: "HOST", elastic: true},
				column{name: "CONFIG", right: true},
				column{name: "BLOCKLIST", right: true},
				column{name: "LAST SEEN"},
			)
			for _, l := range lagging {
				t.add(l.Name,
					strconv.FormatInt(l.AppliedConfigEpoch, 10),
					strconv.FormatInt(l.AppliedBlocklistEpoch, 10),
					ago(l.LastSeenAt))
			}
			var tb strings.Builder
			t.render(&tb)
			b.WriteString(indent(tb.String(), "  "))

			b.WriteString("\n\nThey do not yet trust this CA, and their next certificate would be signed\n" +
				"by it. Wait for them:\n\n" +
				"  orbit converge -wait 10m\n\n" +
				"After a signing-key compromise, cutting them off may be the lesser harm.\n" +
				"That path is deliberate and audited as a distinct action:\n\n" +
				"  orbit ca activate " + fs.Arg(0) + " -acknowledge-cutoff")
			return fail(exitConflict, "%s", b.String())
		}
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	fmt.Fprintf(out, "activated %s (%s)\n", res.Value.Name, shortFingerprint(res.Value.Fingerprint))
	fmt.Fprintf(errOut,
		"\nNew certificates are signed by this CA from now on. The previous one stays in\n"+
			"every trust bundle until you retire it, and it cannot be retired until nothing\n"+
			"it signed is still live:\n\n  orbit ca ls\n")
	return nil
}

func caRetire(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ca retire", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit ca retire <name|fingerprint-prefix|uuid>")
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
	ca, err := o.client.ResolveCA(ctx, networkID, fs.Arg(0))
	if err != nil {
		return err
	}
	caID, err := uuid.Parse(ca.ID)
	if err != nil {
		return err
	}

	o.announce(fmt.Sprintf("About to RETIRE CA %q (%s) in network %s",
		ca.Name, shortFingerprint(ca.Fingerprint), network.Name))
	if err := o.confirm(fmt.Sprintf(
		"Retiring %s drops it from every trust bundle. Retirement is a rotation step and "+
			"cannot be undone through the API. Continue?", shortFingerprint(ca.Fingerprint))); err != nil {
		return err
	}

	res, err := o.client.RetireCA(ctx, caID)
	if err != nil {
		if api, ok := isConflict(err); ok {
			return fail(exitConflict,
				"%s\n\n"+
					"CA %s still has %d live certificate(s). Retiring it would stop every host\n"+
					"presenting one from being trusted. Wait for them to renew onto the active CA,\n"+
					"then check:\n\n  orbit ca ls",
				api.Message, shortFingerprint(ca.Fingerprint), ca.ActiveCertificates)
		}
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}
	fmt.Fprintf(out, "retired %s (%s)\n", res.Value.Name, shortFingerprint(res.Value.Fingerprint))
	return nil
}
