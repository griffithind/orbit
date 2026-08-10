package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/adminclient"
	"github.com/griffithind/orbit/internal/wire"
)

const membershipVerbs = "ls, show, pending, authorize, reserve, set, code, block, unblock, rm"

//------------------------------------------------------------------------------
// ls
//------------------------------------------------------------------------------

func membershipLs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("membership ls", flag.ExitOnError)
	var o options
	o.bind(fs)
	var (
		state  = fs.String("state", "", "created, enrolled, active, or suspended")
		tag    = fs.String("tag", "", "only hosts carrying this tag")
		role   = fs.String("role", "", "only hosts carrying this role (name or uuid)")
		name   = fs.String("name", "", "only hosts whose name contains this substring")
		behind = fs.Bool("behind", false, "only hosts that have not applied the current epochs")
		limit  = fs.Int("limit", 0, "page size; the server's default when unset")
		cursor = fs.String("cursor", "", "next_cursor from a previous page")
		count  = fs.Bool("count", false, "also ask for the total matching the filter")
		all    = fs.Bool("all", false, "follow cursors and print every page")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	// -all and -json are mutually exclusive, and refusing is better than
	// choosing. -json emits the API response verbatim so that it is
	// interchangeable with curl; concatenating several envelopes would produce a
	// stream no curl invocation can produce and no jq filter expects. The
	// envelope's next_cursor is the supported way to page in a script, which is
	// why it is in the response rather than in a header.
	if *all && o.json {
		return usageErrorf("-all cannot be combined with -json: -json emits one API " +
			"response verbatim, and several concatenated envelopes are not a response.\n\n" +
			"Page with -cursor, feeding back .next_cursor from each page.")
	}

	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}
	networkID, err := uuid.Parse(network.ID)
	if err != nil {
		return err
	}

	f := adminclient.MembershipFilter{
		NetworkID:    networkID,
		State:        *state,
		Tag:          *tag,
		NameContains: *name,
		Behind:       *behind,
		Limit:        *limit,
		Cursor:       *cursor,
		Count:        *count,
	}
	// The server refuses a role name — "role_id must be a uuid, not a role name"
	// — because anything else would match no host and read as a role nobody
	// carries. Resolving it here is the whole reason an operator would rather
	// type this than curl.
	if *role != "" {
		id, err := o.client.ResolveRole(ctx, networkID, *role)
		if err != nil {
			return err
		}
		f.RoleID = &id
	}

	res, err := o.client.ListHosts(ctx, f)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	page := res.Value
	hosts := page.Memberships
	// -all follows the cursor the server issued rather than guessing at offsets.
	// The cursor is opaque and is passed back unmodified, which is the only
	// contract the endpoint offers and the only one that survives a concurrent
	// insert.
	for *all && page.NextCursor != "" {
		f.Cursor = page.NextCursor
		next, err := o.client.ListHosts(ctx, f)
		if err != nil {
			return err
		}
		page = next.Value
		hosts = append(hosts, page.Memberships...)
	}

	renderHostTable(o.r, network, hosts)

	if page.NextCursor != "" {
		// stderr, always — even when stdout is a pipe. A truncated listing that
		// says nothing is the failure wire.MembershipListResponse exists to prevent,
		// and suppressing the notice for pipelines would reintroduce it exactly
		// where nobody is watching.
		fmt.Fprintf(errOut, "\nmore hosts match; next page:\n  orbit membership ls -cursor %s\n", page.NextCursor)
	}
	return nil
}

func renderHostTable(r renderer, network *wire.NetworkResponse, hosts []wire.MembershipResponse) {
	t := newTable(r,
		column{name: "NAME", elastic: true},
		column{name: "STATE"},
		column{name: "ADDRESS"},
		column{name: "ROLE", optional: true},
		column{name: "CONFIG", right: true},
		column{name: "LAST SEEN"},
		column{name: "AGENT", optional: true},
	)

	behind := 0
	for _, h := range hosts {
		cfg := strconv.FormatInt(h.AppliedConfigEpoch, 10)
		if h.AppliedConfigEpoch < network.ConfigEpoch || h.AppliedBlocklistEpoch < network.BlocklistEpoch {
			behind++
			cfg = fmt.Sprintf("%d<%d", h.AppliedConfigEpoch, network.ConfigEpoch)
		}
		role := h.RoleName
		if role == "" {
			role = "-"
		}
		agent := h.AgentVersion
		if agent == "" {
			agent = "-"
		}
		t.add(h.Name, h.State, strings.Join(h.OverlayAddrs, ","), role, cfg, ago(h.LastSeenAt), agent)
	}

	if t.empty() {
		fmt.Fprintln(errOut, "no hosts match")
		return
	}
	t.render(out)
	t.footer(out, "\n%d host(s), %d behind — network %s at config epoch %d",
		len(hosts), behind, network.Name, network.ConfigEpoch)
}

//------------------------------------------------------------------------------
// show
//------------------------------------------------------------------------------

// membershipShow is the command the CLI exists to earn.
//
// Membership, current certificate, and convergence on one screen, because "why is this
// host not renewing" is answered by all three at once and by no one of them
// alone. The three sources are GET /v1/memberships/{id} (which carries its active
// certificates), the network's current epochs, and — with -history — the
// certificate list. Behind curl that is three requests, three JSON blobs, and
// arithmetic on RFC3339 strings.
func membershipShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("membership show", flag.ExitOnError)
	var o options
	o.bind(fs)
	history := fs.Int("history", 0, "also list the N most recent certificates")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit membership show <name|uuid>")
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
	membershipID, err := o.client.ResolveHost(ctx, networkID, fs.Arg(0))
	if err != nil {
		return err
	}

	res, err := o.client.GetHost(ctx, membershipID)
	if err != nil {
		return err
	}
	if o.json {
		// The host response verbatim, not a document this command assembled from
		// three. `orbit membership show -json` and `curl /v1/memberships/{id}` have to be the
		// same bytes; the layout below is the value this command adds, and it is
		// a human's, not a script's.
		return emitJSON(res.Raw)
	}
	h := res.Value

	field := func(k, v string) {
		if v != "" {
			fmt.Fprintf(out, "%-12s %s\n", k, v)
		}
	}

	fmt.Fprintln(out, o.r.bold(h.Name))
	field("id", h.ID)
	field("network", fmt.Sprintf("%s (%s)", network.Name, strings.Join(network.CIDRs, ", ")))
	field("state", h.State)
	field("address", strings.Join(h.OverlayAddrs, ", "))
	if h.RoleName != "" {
		field("role", fmt.Sprintf("%s (%s)", h.RoleName, h.RoleID))
	}
	if len(h.Tags) > 0 {
		field("tags", strings.Join(h.Tags, ", "))
	}
	var flags []string
	if h.IsLighthouse {
		flags = append(flags, "lighthouse")
	}
	if h.IsRelay {
		flags = append(flags, "relay")
	}
	if len(flags) > 0 {
		field("roles", strings.Join(flags, ", "))
	}
	if len(h.StaticAddrs) > 0 {
		field("static", strings.Join(h.StaticAddrs, ", "))
	}
	// The two versions an operator asks for first when a host has stopped
	// renewing: an agent too old to know an endpoint, or a nebula that rejects
	// the certificate version the network moved to.
	if h.AgentVersion != "" || h.NebulaVersion != "" {
		field("versions", fmt.Sprintf("agent %s, nebula %s",
			orDash(h.AgentVersion), orDash(h.NebulaVersion)))
	}
	field("created", fmt.Sprintf("%s (%s)", h.CreatedAt.Format(time.RFC3339), ago(&h.CreatedAt)))
	field("last seen", ago(h.LastSeenAt))

	renderCertificates(o.r, h)
	renderHostConvergence(o.r, network, h)

	if *history > 0 {
		hist, err := o.client.MembershipCertificates(ctx, membershipID, adminclient.CertFilter{Limit: *history})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "\n%s\n", o.r.bold("certificate history"))
		t := newTable(o.r,
			column{name: "FINGERPRINT", elastic: true},
			column{name: "STATE"},
			column{name: "CA"},
			column{name: "ISSUED"},
			column{name: "EXPIRES"},
		)
		for _, c := range hist.Value.Certificates {
			t.add(shortFingerprint(c.Fingerprint), c.State, c.CAName,
				ago(&c.IssuedAt), until(c.NotAfter))
		}
		if t.empty() {
			fmt.Fprintln(out, "  none")
		} else {
			t.render(out)
		}
	}
	return nil
}

func renderCertificates(r renderer, h wire.MembershipResponse) {
	fmt.Fprintf(out, "\n%s\n", r.bold("certificate"))
	if len(h.ActiveCertificates) == 0 {
		// Two very different causes, and the state field distinguishes them, so
		// say which one this is rather than leaving a blank section.
		switch h.State {
		case "created":
			fmt.Fprintln(out, "  none — this host has not enrolled yet; mint a code with `orbit membership code`")
		case "suspended":
			fmt.Fprintln(out, "  none — this host is blocked and its certificates were revoked")
		default:
			fmt.Fprintln(out, "  none — no active certificate; re-run `orbit agent join` on the machine")
		}
		return
	}

	now := time.Now()
	for _, c := range h.ActiveCertificates {
		fmt.Fprintf(out, "  %-13s %s\n", "fingerprint", c.Fingerprint)
		// The CA id in full, not shortened. It is a uuid, and half a uuid is not
		// a handle anything accepts — unlike a fingerprint prefix, which
		// `orbit ca activate` does take.
		fmt.Fprintf(out, "  %-13s %s (%s)\n", "issued by", c.CAName, c.CAID)
		fmt.Fprintf(out, "  %-13s %d\n", "version", c.CertVersion)
		fmt.Fprintf(out, "  %-13s %s (%s)\n", "issued", c.IssuedAt.Format(time.RFC3339), ago(&c.IssuedAt))

		// RenewAt is the midpoint of the lifetime — when the agent should have
		// renewed. Past it and still holding this certificate means renewal is
		// already failing, and that is the whole warning. Saying it in words is
		// the difference between this command and two timestamps.
		renew := fmt.Sprintf("  %-13s %s (%s)", "renew at", c.RenewAt.Format(time.RFC3339), until(c.RenewAt))
		if c.RenewAt.Before(now) {
			renew += "   OVERDUE — this host should already have renewed"
		}
		fmt.Fprintln(out, renew)

		expires := fmt.Sprintf("  %-13s %s (%s)", "expires", c.NotAfter.Format(time.RFC3339), until(c.NotAfter))
		if c.NotAfter.Before(now) {
			expires += "   EXPIRED — off the mesh until the machine re-joins"
		}
		fmt.Fprintln(out, expires)
	}
}

func renderHostConvergence(r renderer, network *wire.NetworkResponse, h wire.MembershipResponse) {
	fmt.Fprintf(out, "\n%s\n", r.bold("convergence"))
	line := func(label string, applied, current int64) {
		status := "up to date"
		if applied < current {
			status = fmt.Sprintf("BEHIND by %d", current-applied)
		}
		fmt.Fprintf(out, "  %-13s applied %-8d network %-8d %s\n", label, applied, current, status)
	}
	line("config", h.AppliedConfigEpoch, network.ConfigEpoch)
	line("blocklist", h.AppliedBlocklistEpoch, network.BlocklistEpoch)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// shortFingerprint keeps a fingerprint recognisable without spending a whole
// column on it. 16 hex characters is 64 bits, which is not a collision anyone
// reaches by accident within one network.
func shortFingerprint(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

//------------------------------------------------------------------------------
// create / set
//------------------------------------------------------------------------------

// membershipReserve holds a place in a network for a machine that has not arrived.
//
// This replaced `orbit membership create` followed by `orbit membership code`. Two commands
// became one because they were always one intention: an operator decides what a
// machine will be called, where it goes and what it may do, and hands over a
// code. What changed underneath is that nothing exists until the code is
// redeemed — so there is no half-provisioned row to clean up if the machine
// never arrives, and no membership that names no machine.
func membershipReserve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("membership reserve", flag.ExitOnError)
	var o options
	o.bind(fs)
	var (
		name = fs.String("name", "", "membership name, unique within the network (required)")
		addr = fs.String("addr", "", "pin a specific overlay address; omit to allocate one")
		role = fs.String("role", "", "role name or uuid")
		ttl  = fs.Duration("ttl", 0, "how long the code stays valid; the server's default when unset")

		lighthouse    = fs.Bool("lighthouse", false, "the machine will be a lighthouse; needs -public-addr")
		relay         = fs.Bool("relay", false, "the machine will relay other machines' traffic")
		publicAddr    = fs.String("public-addr", "", "comma-separated public addresses, hosts WITHOUT ports")
		advertisePort = fs.Int("advertise-port", 0, "port other machines dial, when it differs from the bound one (NAT forwarding)")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return usageErrorf("-name is required")
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

	req := wire.ReserveRequest{
		Name:         *name,
		OverlayAddr:  *addr,
		TTLSeconds:   int(ttl.Seconds()),
		IsLighthouse: *lighthouse,
		IsRelay:      *relay,
		PublicAddrs:  csvList(*publicAddr),
	}
	if *advertisePort != 0 {
		req.AdvertisePort = advertisePort
	}
	if *role != "" {
		id, err := o.client.ResolveRole(ctx, networkID, *role)
		if err != nil {
			return err
		}
		req.RoleID = id.String()
	}

	res, err := o.client.Reserve(ctx, network.Slug, req)
	if err != nil {
		if api, ok := isConflict(err); ok {
			return fail(exitConflict,
				"the name %q is already taken in network %s (%s)\n\n"+
					"Names are unique per network, and an unspent reservation holds one. "+
					"Inspect an existing host with `orbit membership show %s`, or pick another name.",
				*name, network.Name, api.Message, *name)
		}
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	fmt.Fprintf(out, "%s\n", res.Value.Code)
	fmt.Fprintf(errOut, "\nReserved %q in %s. The code is single-use, expires %s, and is shown\n"+
		"here and nowhere else — it is not recoverable.\n\nOn the machine:\n\n"+
		"  orbit agent join -url %s -network %s -code %s\n",
		*name, network.Name, res.Value.ExpiresAt.Format(time.RFC3339),
		joinURL(res.Value.EnrollURL, o.url), network.Slug, res.Value.Code)

	// Say what the machine will BE, not just that a code exists. The whole point
	// of putting the topology on the reservation is that nobody has to come back
	// afterwards, and an operator has no other way to confirm the flags took
	// before a machine redeems the code.
	if *lighthouse || *relay {
		roles := "a relay"
		if *lighthouse {
			roles = "a lighthouse"
			if *relay {
				roles = "a lighthouse and a relay"
			}
		}
		fmt.Fprintf(errOut, "\nOn redemption it becomes %s at %s. No follow-up call.\n",
			roles, strings.Join(csvList(*publicAddr), ", "))
	}
	return nil
}

func membershipSet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("membership set", flag.ExitOnError)
	var o options
	o.bind(fs)
	var (
		role          = fs.String("role", "", "role name or uuid")
		tags          = fs.String("tags", "", "comma separated tags, replacing the current set")
		lighthouse    = fs.Bool("lighthouse", false, "act as a lighthouse; the machine needs public addresses (`orbit device set-addrs`)")
		relay         = fs.Bool("relay", false, "act as a relay")
		advertisePort = fs.Int("advertise-port", 0, "port other machines dial, when it differs from the bound port (NAT forwarding). The ADDRESSES are a machine fact: `orbit device set-addrs`")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit membership set <name|uuid> [flags]")
	}
	if err := o.load(); err != nil {
		return err
	}

	// Only fields the operator actually named are sent. wire.UpdateHostRequest
	// uses pointers precisely so "not supplied" differs from "set to false", and
	// a CLI that sent every flag's zero value would turn `orbit membership set -tags x`
	// into an accidental un-lighthousing. fs.Visit reports what was on the
	// command line, which is the only honest source for that.
	supplied := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { supplied[f.Name] = true })
	if len(supplied) == 0 || onlyGlobals(supplied) {
		return usageErrorf("nothing to change; set -role, -tags, -lighthouse, -relay, or -advertise-port")
	}

	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}
	networkID, err := uuid.Parse(network.ID)
	if err != nil {
		return err
	}
	membershipID, err := o.client.ResolveHost(ctx, networkID, fs.Arg(0))
	if err != nil {
		return err
	}

	var req wire.UpdateHostRequest
	if supplied["role"] {
		id, err := o.client.ResolveRole(ctx, networkID, *role)
		if err != nil {
			return err
		}
		s := id.String()
		req.RoleID = &s
	}
	if supplied["tags"] {
		t := csvList(*tags)
		req.Tags = &t
	}
	if supplied["lighthouse"] {
		req.IsLighthouse = lighthouse
	}
	if supplied["relay"] {
		req.IsRelay = relay
	}
	if supplied["advertise-port"] {
		req.AdvertisePort = advertisePort
	}

	o.announce(fmt.Sprintf("Updating host %q in network %s", fs.Arg(0), network.Name))

	res, err := o.client.UpdateHost(ctx, membershipID, req)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}
	fmt.Fprintf(out, "updated %s (%s)\n", res.Value.Name, res.Value.ID)
	return nil
}

// onlyGlobals reports whether the supplied flags are all connection settings, so
// `orbit membership set -network prod web-01` is refused rather than sent as an empty
// PATCH the server would answer 400 to.
func onlyGlobals(supplied map[string]bool) bool {
	globals := map[string]bool{
		"url": true, "token-file": true, "network": true,
		"profile": true, "json": true, "y": true,
	}
	for k := range supplied {
		if !globals[k] {
			return false
		}
	}
	return true
}

//------------------------------------------------------------------------------
// code
//------------------------------------------------------------------------------

// membershipCode mints an enrollment credential.
//
// The plaintext goes alone on stdout and every word of prose to stderr — the
// property `orbitd token create` established and a test there asserts. It is what
// makes `orbit membership code web-01 | op create item` work without the code passing
// through a shell history or a scrollback buffer.
func membershipCode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("membership code", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit membership code <name|uuid>")
	}
	if err := o.load(); err != nil {
		return err
	}

	networkID, err := o.networkID(ctx)
	if err != nil {
		return err
	}
	membershipID, err := o.client.ResolveHost(ctx, networkID, fs.Arg(0))
	if err != nil {
		return err
	}

	o.announce(fmt.Sprintf("Minting an enrollment code for %q", fs.Arg(0)))

	res, err := o.client.EnrollmentCode(ctx, membershipID)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	c := res.Value
	fmt.Fprintf(errOut, `expires %s (%s)
enroll  %s

Single use, and shown once. On the host:

  orbit agent enroll -url %s -code "$ORBIT_ENROLL_CODE"

`, c.ExpiresAt.Format(time.RFC3339), until(c.ExpiresAt), c.EnrollURL, c.EnrollURL)

	fmt.Fprintln(out, c.Code)
	return nil
}

//------------------------------------------------------------------------------
// block / unblock / rm
//------------------------------------------------------------------------------

func membershipBlock(ctx context.Context, args []string, unblock bool) error {
	verb := "block"
	if unblock {
		verb = "unblock"
	}
	fs := flag.NewFlagSet("membership "+verb, flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit membership %s <name|uuid>", verb)
	}
	if err := o.load(); err != nil {
		return err
	}

	networkID, err := o.networkID(ctx)
	if err != nil {
		return err
	}
	membershipID, err := o.client.ResolveHost(ctx, networkID, fs.Arg(0))
	if err != nil {
		return err
	}

	// Announced, but not prompted. Blocking is reversible with `orbit host
	// unblock`, and a prompt on a reversible action trains people to type y
	// without reading — which is what would make the prompt on `host rm`
	// worthless.
	o.announce(fmt.Sprintf("About to %s host %q", verb, fs.Arg(0)))

	var res adminclient.Result[wire.BlockResponse]
	if unblock {
		res, err = o.client.UnblockHost(ctx, membershipID)
	} else {
		res, err = o.client.BlockHost(ctx, membershipID)
	}
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	fmt.Fprintf(out, "%sed %s at blocklist epoch %d\n", verb, fs.Arg(0), res.Value.BlocklistEpoch)
	if !unblock {
		fmt.Fprintf(errOut,
			"\nThe host stays cut off only once the fleet applies that epoch. Watch it:\n\n  orbit converge -wait 5m\n")
	}
	return nil
}

func membershipRm(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("membership rm", flag.ExitOnError)
	var o options
	o.bind(fs)
	reason := fs.String("reason", "", "recorded in the audit log")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit membership rm <name|uuid>")
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
	membershipID, err := o.client.ResolveHost(ctx, networkID, fs.Arg(0))
	if err != nil {
		return err
	}

	o.announce(fmt.Sprintf("About to DECOMMISSION host %q in network %s", fs.Arg(0), network.Name))
	if err := o.confirm(fmt.Sprintf(
		"This revokes %s's certificates and removes the record, releasing its name and address. It cannot be undone. Continue?",
		fs.Arg(0))); err != nil {
		return err
	}

	res, err := o.client.DeleteHost(ctx, membershipID, *reason)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}
	fmt.Fprintf(out, "removed %s at blocklist epoch %d\n", fs.Arg(0), res.Value.BlocklistEpoch)
	fmt.Fprintf(errOut,
		"\nIts certificates are revoked. They stop being accepted once the fleet applies\nthat epoch:\n\n  orbit converge -wait 5m\n")
	return nil
}

// splitCSV matches orbitd's helper of the same name: trimmed, empties dropped.
// enrollPath is what -enroll-url carries beyond the origin. Kept beside the
// trimming rather than imported so the two cannot drift silently: if the route
// moves, this stops matching and the printed URL is wrong again.
const enrollPath = "/enroll/v1/enroll"

// joinURL is the URL to put in the join command printed for an operator to copy.
//
// The control plane's -enroll-url when it has one, because that is the address it knows
// machines can reach it at. Falling back to the address this CLI is itself talking to,
// which is usually right and is at worst a URL the operator recognises.
//
// Never a dash. orDash is right for a table cell, where an empty column is information;
// inside a command somebody is about to paste it is a line that cannot work, and the
// failure lands on the machine being enrolled rather than here.
func joinURL(enrollURL, clientURL string) string {
	if enrollURL != "" {
		// The BASE, not the enroll endpoint. -enroll-url is the full path an
		// agent POSTs to, because that is what the agent needs; `agent join`
		// takes the origin and appends the path itself. Printing the endpoint
		// gave an operator a command that 404s — verified on a real control
		// plane, where the pasted line failed and the same line minus the suffix
		// enrolled first try.
		return strings.TrimSuffix(enrollURL, enrollPath)
	}
	if clientURL != "" {
		return clientURL
	}
	return "<control-plane-url>"
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// csvList is splitCSV for a value that will be sent through a *[]string field,
// and it never returns nil.
//
// A nil slice behind a non-nil pointer marshals to JSON null, and encoding/json
// decodes null into a *[]string by leaving the pointer alone — so `-tags ""`
// would arrive as "not supplied" and clearing a host's tags, or a role's groups,
// would silently do nothing. An empty slice marshals to [] and means what the
// operator typed.
func csvList(s string) []string {
	if v := splitCSV(s); v != nil {
		return v
	}
	return []string{}
}

//------------------------------------------------------------------------------
// pending, authorize
//------------------------------------------------------------------------------

// membershipPending lists the join queue.
//
// The queue exists because `orbit agent join` moved the gate from "holds a
// credential" to "an operator says yes". That trade only works if the queue is
// easy to look at, so this is deliberately the shortest command in the CLI: a
// network, and what is waiting in it.
func membershipPending(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("membership pending", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	network, err := o.resolveNetwork(ctx)
	if err != nil {
		return err
	}
	res, err := o.client.PendingJoins(ctx, network.Slug)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	if len(res.Value.Pending) == 0 {
		fmt.Fprintf(out, "nothing waiting in %s\n", network.Slug)
		return nil
	}

	t := newTable(o.r,
		column{name: "NAME", elastic: true},
		column{name: "MEMBERSHIP"},
		column{name: "DEVICE"},
		column{name: "WAITING"},
	)
	for _, p := range res.Value.Pending {
		requested := p.RequestedAt
		t.add(p.Name, p.MembershipID, shortFingerprint(p.DeviceID), ago(&requested))
	}
	t.render(out)
	fmt.Fprintf(errOut, "\nAuthorize one with:\n\n  orbit membership authorize <membership>\n")
	return nil
}

// membershipAuthorize admits a pending membership.
func membershipAuthorize(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("membership authorize", flag.ExitOnError)
	var o options
	o.bind(fs)
	role := fs.String("role", "", "assign this role while authorizing (name or uuid)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit membership authorize <membership uuid>")
	}
	if err := o.load(); err != nil {
		return err
	}

	// A uuid and nothing else, unlike every other host verb.
	//
	// Resolution by name is what makes the other commands pleasant, and it is
	// exactly wrong here: a pending row's name is a string the JOINING MACHINE
	// chose, and resolving by it would let a machine that joined asking to be
	// called "lighthouse" be authorized by an operator who typed the name of
	// the host they meant. The membership id comes from `orbit membership pending`,
	// which is where the operator is looking anyway.
	membershipID, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		return usageErrorf("authorize takes a membership uuid, as printed by "+
			"`orbit membership pending`, not a name: %q", fs.Arg(0))
	}

	var roleID string
	if *role != "" {
		networkID, err := o.networkID(ctx)
		if err != nil {
			return err
		}
		id, err := o.client.ResolveRole(ctx, networkID, *role)
		if err != nil {
			return err
		}
		roleID = id.String()
	}

	res, err := o.client.Authorize(ctx, membershipID, roleID)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	fmt.Fprintf(out, "authorized %s (%s)\n  addresses %s\n",
		res.Value.Name, res.Value.ID, strings.Join(res.Value.OverlayAddrs, ", "))
	fmt.Fprintf(errOut,
		"\nNo certificate has been issued. The machine collects one by proving it holds\n"+
			"the device key it joined with, which `orbit agent join` does automatically.\n")
	return nil
}
