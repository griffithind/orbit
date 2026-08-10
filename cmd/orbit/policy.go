package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/griffithind/orbit/internal/policy"
	"github.com/griffithind/orbit/internal/wire"
)

// The network policy document.
//
//	orbit policy show                 read the current document
//	orbit policy check <file|->       validate it, change nothing
//	orbit policy apply <file|->       validate it, then store it
//	orbit policy use <role|policy>    switch which firewall the network draws from
//
// `check` and `apply` both validate LOCALLY FIRST, with the same
// internal/policy that the control plane uses. Not to second-guess the server —
// the server validates again and its answer is the one that decides — but
// because a document with a typo should not cost a round trip, and because the
// fault is named identically either way, so an operator never sees two different
// descriptions of one mistake. A CLI built against a different release than the
// control plane will occasionally disagree; the server refuses in that case, and
// its refusal is a 400 which maps to the same exit 2.

func policyShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy show", flag.ContinueOnError)
	var o options
	o.bind(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}
	res, err := o.client.GetPolicy(ctx, network.Slug)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	p := res.Value
	fmt.Fprintf(out, "%s policy\n", o.r.bold(network.Name))
	fmt.Fprintf(out, "%-14s %d\n", "version", p.Version)
	fmt.Fprintf(out, "%-14s %s\n", "written", ago(&p.CreatedAt))
	fmt.Fprintf(out, "%-14s %s\n", "by", orDash(p.Author))
	fmt.Fprintf(out, "%-14s %d\n", "config epoch", p.ConfigEpoch)
	fmt.Fprintf(out, "%-14s %s\n", "in force", inForce(p.FirewallSource))
	fmt.Fprintln(out, "document")
	fmt.Fprintln(out, indent(prettyJSON(p.Document), "  "))

	// The one thing an operator most often gets wrong: a document can be stored,
	// current, and enforcing nothing. Said on stderr so it never contaminates a
	// pipeline reading stdout.
	if p.FirewallSource != "policy" {
		fmt.Fprintf(errOut,
			"\nThis document is NOT in force: %s draws its firewall from per-role rules.\n"+
				"  Switch it:  orbit policy use policy\n", network.Name)
	}
	return nil
}

func inForce(source string) string {
	if source == "policy" {
		return "yes"
	}
	return "no (network uses per-role firewall rules)"
}

// policyCheck validates a document and changes nothing.
//
// The reason this verb exists at all: a policy edit is fleet-wide and there is no
// staging network, so this is where a typo is found instead of at four hundred
// hosts. It is meant to be cheap enough to put in CI against a policy file in
// review, which is why it exits non-zero on failure and prints nothing on stdout
// unless asked.
func policyCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
	var o options
	o.bind(fs)
	host := fs.String("host", "", "report what this host would compile to (name or uuid)")
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit policy check <file|-> [-host name]")
	}
	if err := o.load(); err != nil {
		return err
	}

	doc, err := readPolicyDocument(fs.Arg(0))
	if err != nil {
		return err
	}

	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}
	res, err := o.client.CheckPolicy(ctx, network.Slug, doc, *host)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	v := res.Value
	fmt.Fprintf(out, "%s\n", o.r.bold("policy document is valid"))
	if v.CurrentVersion == 0 {
		fmt.Fprintf(out, "%-14s %s\n", "stored", "nothing yet; this would be version 1")
	} else if v.WouldChange {
		fmt.Fprintf(out, "%-14s version %d, and applying this would replace it\n", "stored", v.CurrentVersion)
	} else {
		// Worth stating plainly. A no-op apply writes nothing and wakes no agent,
		// so an operator watching for a convergence change would otherwise wait
		// for something that is never going to happen.
		fmt.Fprintf(out, "%-14s version %d, identical to this one; applying would change nothing\n",
			"stored", v.CurrentVersion)
	}
	fmt.Fprintf(out, "%-14s %s\n", "in force", inForce(v.FirewallSource))
	renderCompiled(o, v)
	return nil
}

// renderCompiled prints the dry run for a named host.
//
// The selector inputs are printed ABOVE the rules deliberately. When the rule
// list is shorter than expected the reason is almost always up here — a tag that
// is not on the host, a role that is not the one assumed — and putting it after
// the rules means it is read second, if at all.
func renderCompiled(o options, v wire.PolicyCheckResponse) {
	if v.Membership == nil {
		fmt.Fprintf(errOut,
			"\nTo see what a specific host would get:  orbit policy check <file> -host <name>\n")
		return
	}

	h := v.Membership
	fmt.Fprintf(out, "\n%s\n", o.r.bold("compiled for "+h.Name))
	fmt.Fprintf(out, "%-14s %s\n", "addresses", orDash(strings.Join(h.OverlayAddrs, ", ")))
	fmt.Fprintf(out, "%-14s %s\n", "tags", orDash(strings.Join(h.Tags, ", ")))
	fmt.Fprintf(out, "%-14s %s\n", "role", orDash(h.RoleName))
	fmt.Fprintf(out, "%-14s %s\n", "groups", orDash(strings.Join(h.Groups, ", ")))

	if v.Compiled == nil {
		return
	}
	renderRules(o, "inbound", v.Compiled.Inbound)
	renderRules(o, "outbound", v.Compiled.Outbound)

	if len(v.Compiled.Inbound) == 0 {
		// Not a formatting curiosity. Nebula's firewall is default-deny, so zero
		// inbound rules is a host nothing can reach, and it renders as an empty
		// section that looks like a display bug rather than an outage.
		fmt.Fprintf(errOut,
			"\n%s: %s would accept NO inbound traffic. Nebula's firewall is default-deny,\n"+
				"so an empty inbound set is not \"no restrictions\", it is \"unreachable\".\n",
			o.r.bold("WARNING"), h.Name)
	}
}

func renderRules(o options, dir string, rules []wire.PolicyRule) {
	fmt.Fprintf(out, "\n%s (%d)\n", dir, len(rules))
	if len(rules) == 0 {
		fmt.Fprintln(out, "  (none)")
		return
	}
	t := newTable(o.r,
		column{name: "PROTO"},
		column{name: "PORT"},
		column{name: "CIDR", elastic: true},
		column{name: "LOCAL CIDR", optional: true},
	)
	for _, r := range rules {
		t.add(r.Proto, r.Port, r.CIDR, orDash(r.LocalCIDR))
	}
	t.render(out)
}

// policyApply validates and then stores.
//
// It refuses on a lint failure before sending anything, which is the difference
// between "your document is wrong" and "your document is wrong and is now the
// firewall". Exit 2 either way: a local refusal and the server's 400 are the same
// class of problem, and a script must not have to tell them apart.
func policyApply(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy apply", flag.ContinueOnError)
	var o options
	o.bind(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit policy apply <file|->")
	}
	if err := o.load(); err != nil {
		return err
	}

	doc, err := readPolicyDocument(fs.Arg(0))
	if err != nil {
		return err
	}

	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}

	// Announced before it happens, for the reason every mutating command here is:
	// two shells with different exports look identical, and this one replaces the
	// firewall for a whole network.
	o.announce(fmt.Sprintf("Applying a policy document to network %s", network.Name))

	res, err := o.client.PutPolicy(ctx, network.Slug, doc)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	v := res.Value
	if !v.Changed {
		fmt.Fprintf(out,
			"unchanged at version %d; nothing was written and no agent was woken\n", v.Version)
		return nil
	}
	fmt.Fprintf(out, "applied version %d (was %s) at config epoch %d\n",
		v.Version, versionOrNone(v.PreviousVersion), v.ConfigEpoch)

	if v.FirewallSource != "policy" {
		// The failure this whole message exists for: the request succeeded, the
		// document is stored, and it is enforcing nothing. An operator who reads
		// "applied" and walks away has drawn the wrong conclusion.
		fmt.Fprintf(errOut, `
%s

  %s draws its firewall from per-role rules, so this document is stored and
  is NOT enforced anywhere.

  Switch the network onto it:  orbit policy use policy
`, o.r.bold("STORED, NOT IN FORCE"), network.Name)
		return nil
	}
	fmt.Fprintf(errOut,
		"\nEvery host in %s re-renders its firewall on its next poll; no certificate is\n"+
			"reissued. Watch it land:  orbit converge -wait 5m\n", network.Name)
	return nil
}

func versionOrNone(v int64) string {
	if v == 0 {
		return "none"
	}
	return strconv.FormatInt(v, 10)
}

// policyUse switches which firewall the network draws from.
//
// Confirmed, and gated server-side on top of that. This is the one command here
// that changes the firewall on every host at once, and the failure is silent in a
// way nothing else is: if the new source is narrower, every host applies
// successfully, reports the new epoch, and reads as fully converged while traffic
// stops.
func policyUse(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy use", flag.ContinueOnError)
	var o options
	o.bind(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit policy use <role|policy>")
	}
	source := fs.Arg(0)
	if source != "role" && source != "policy" {
		return usageErrorf("usage: orbit policy use <role|policy>; %q is neither", source)
	}
	if err := o.load(); err != nil {
		return err
	}

	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}
	if network.FirewallSource == source {
		fmt.Fprintf(out, "%s already draws its firewall from %s; nothing to do\n", network.Name, source)
		return nil
	}

	o.announce(fmt.Sprintf("Switching network %s from %s firewall rules to %s",
		network.Name, orDash(network.FirewallSource), source))
	if err := o.confirm(fmt.Sprintf(
		"Replace the firewall on every host in %s with the %s source?", network.Name, source)); err != nil {
		return err
	}

	// The acknowledgement is sent because the operator just gave it, at the
	// prompt above or with -y. Passing it unconditionally would defeat the gate;
	// passing it here is the gate being satisfied.
	res, err := o.client.SetFirewallSource(ctx, network.Slug, source, true)
	if err != nil {
		if api, ok := isConflict(err); ok {
			// Reached when the server refuses for a reason the acknowledgement
			// does not cover. Rendered rather than passed through, because the
			// useful half is the host count, not the sentence.
			g := api.FirewallSourceChange()
			return fail(exitConflict,
				"%s\n\n  from            %s\n  to              %s\n  hosts affected  %d\n\n  %s",
				api.Message, orDash(g.From), orDash(g.To), g.MembershipsAffected, g.Detail)
		}
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	v := res.Value
	if !v.FirewallSourceChanged {
		fmt.Fprintf(out, "%s already draws its firewall from %s; nothing was written\n",
			network.Name, source)
		return nil
	}
	fmt.Fprintf(out, "%s now draws its firewall from %s (config epoch %d)\n",
		network.Name, source, v.ConfigEpoch)
	fmt.Fprintf(errOut, "\n%s\n\nWatch it land:  orbit converge -wait 5m\n", v.Detail)
	return nil
}

// readPolicyDocument loads a document from a file or stdin and lints it.
//
// Validated with the same internal/policy the control plane uses, so the fault is
// named identically on both sides rather than described twice. Unlike
// readFirewall — which deliberately checks only that the bytes are JSON, because
// the CLI cannot know nebula's schema without duplicating it — the policy schema
// IS a shared package, so there is nothing to duplicate and every reason to fail
// before the request rather than after.
func readPolicyDocument(path string) ([]byte, error) {
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
		return nil, usageErrorf("%v", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, usageErrorf("%s is empty; a policy document is required", sourceName(path))
	}
	if err := policy.Validate(raw); err != nil {
		// Exit 2, the same class the server's 400 maps to. The message is the
		// validator's own — it names the fault and where it is, and rewording it
		// here would replace something actionable with something generic.
		return nil, usageErrorf("%s: %v", sourceName(path), err)
	}
	return raw, nil
}

func sourceName(path string) string {
	if path == "-" {
		return "stdin"
	}
	return path
}
