package adminclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

// Name resolution.
//
// The API takes uuids everywhere, and correctly so: names are per-network, they
// are editable, and a role name reused after a delete would silently retarget a
// script that had memorised it. But an operator holds names, and a CLI that made
// them paste uuids would be a shell alias for curl.
//
// So the CLI resolves, and the discriminator is uuid.Parse: a value that parses
// as a uuid is one, and everything else is a name. Not a prefix, not a flag —
// names are free text and any sigil convention would eventually collide with a
// real hostname.

// ErrAmbiguous is returned when a name matches more than one object.
//
// It exists for one table in particular. orbit.ca has UNIQUE (network_id,
// fingerprint) and no constraint on name, so two CAs in one network may share a
// name — which is exactly what a rotation produces when the new authority is
// named after the old one. Picking the first match would activate an arbitrary
// one of them, and the operator would find out from the fleet.
var ErrAmbiguous = errors.New("ambiguous")

// AmbiguousError names every candidate, and how to disambiguate.
type AmbiguousError struct {
	Kind string
	Ref  string
	// Candidates are pre-rendered lines, each one something the caller could
	// paste back in place of Ref.
	Candidates []string
	// Hint says what kind of unique value to use instead.
	Hint string
}

func (e *AmbiguousError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %q is ambiguous: %d match", e.Kind, e.Ref, len(e.Candidates))
	if len(e.Candidates) != 1 {
		b.WriteString("es")
	}
	for _, c := range e.Candidates {
		b.WriteString("\n  " + c)
	}
	if e.Hint != "" {
		b.WriteString("\n\n" + e.Hint)
	}
	return b.String()
}

func (e *AmbiguousError) Is(target error) bool { return target == ErrAmbiguous }

// ErrNoMatch is returned when a name matches nothing.
//
// Distinct from the server's 404 on purpose: this one is decided locally, from a
// listing the caller could read, so it is a mistyped argument rather than a
// state of the control plane. They get different exit codes for that reason.
var ErrNoMatch = errors.New("no match")

// NoMatchError names what was not found and what is available.
type NoMatchError struct {
	Kind      string
	Ref       string
	Available []string
}

func (e *NoMatchError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "no %s named %q", e.Kind, e.Ref)
	if len(e.Available) == 0 {
		b.WriteString("; there are none to choose from")
	} else {
		b.WriteString("\n\navailable: " + preview(e.Available))
	}
	return b.String()
}

func (e *NoMatchError) Is(target error) bool { return target == ErrNoMatch }

// ResolveNetwork accepts a network name or uuid.
//
// A uuid still costs the listing, because the caller wants the network's epochs
// as often as not and GET /v1/networks/{id} does not exist. If it ever does,
// this is the one place to change.
func (c *Client) ResolveNetwork(ctx context.Context, ref string) (*wire.NetworkResponse, error) {
	// One request. The server resolves a uuid or a name, because network names
	// are globally unique. Listing every network and filtering client-side
	// would cost a full listing on every command that names one.
	res, err := c.GetNetwork(ctx, ref)
	if err == nil {
		return &res.Value, nil
	}

	// Only a 404 is worth a second request. Anything else — unreachable, a bad
	// token, a 500 — is the answer, and listing would just fail the same way
	// with a less useful message.
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusNotFound {
		return nil, err
	}

	// Not found by id or slug. Before giving up, try the display name — a
	// convenience the SERVER deliberately does not offer, because a mutable
	// string must never be an addressing key there: a rename would silently
	// retarget every script that held one.
	//
	// Doing it here is a different trade. The CLI is interactive, the fallback
	// costs a listing that only happens when the fast path already missed, and
	// an operator who types the name they see in `orbit network ls` should not
	// be told it does not exist. Automation that wants stability uses the slug,
	// which is what the fast path resolves and what `orbitd bootstrap` prints.
	all, lerr := c.ListNetworks(ctx)
	if lerr != nil {
		return nil, err // the original 404 is the more useful error
	}
	for i := range all.Value {
		if all.Value[i].Name == ref {
			return &all.Value[i], nil
		}
	}
	return nil, &NoMatchError{Kind: "network", Ref: ref, Available: networkNames(all.Value)}
}

// SoleNetwork returns the only network, or an error naming the choice.
//
// Used when no -network, no ORBIT_NETWORK, and no profile setting was supplied.
// Guessing when there is exactly one is safe and makes a fresh bootstrap work
// with no configuration; guessing when there are several is the failure this
// whole CLI is designed against, so that case is refused rather than defaulted.
func (c *Client) SoleNetwork(ctx context.Context) (*wire.NetworkResponse, error) {
	res, err := c.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}
	switch len(res.Value) {
	case 0:
		return nil, errors.New("this control plane has no networks; run `orbitd bootstrap` first")
	case 1:
		return &res.Value[0], nil
	default:
		return nil, fmt.Errorf(
			"several networks exist, so -network is required (or set ORBIT_NETWORK): %s",
			preview(networkNames(res.Value)))
	}
}

// networkNames lists the alternatives when a reference resolved to nothing.
//
// Slug first, name in parentheses when they differ: the slug is what the caller
// should be typing, since it is immutable and is what a script must hold, but
// the name is what they will recognise from a UI or a colleague.
func networkNames(nets []wire.NetworkResponse) []string {
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		if n.Slug != "" && n.Slug != n.Name {
			out = append(out, n.Slug+" ("+n.Name+")")
			continue
		}
		if n.Slug != "" {
			out = append(out, n.Slug)
			continue
		}
		out = append(out, n.Name)
	}
	sort.Strings(out)
	return out
}

// preview caps a list of candidates.
//
// A deployment can hold hundreds of networks — a long-lived test database
// certainly does — and an error that prints every one of them scrolls the actual
// message off the terminal, which makes it worse than one that prints none.
func preview(names []string) string {
	const max = 20
	if len(names) <= max {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(names[:max], ", "), len(names)-max)
}

// resolvePageSize bounds the substring lookup. Named rather than inlined
// because the error message quotes it, and a message that disagrees with the
// query it describes is worse than no message.
const resolvePageSize = 50

// ResolveHost accepts a host name or uuid and returns the id.
//
// Membership names are UNIQUE (network_id, name), so an exact name match is unique by
// construction — but name_contains is a substring filter, so the page it returns
// has to be narrowed to the exact match here rather than assumed to hold one row,
// and a full page that did not contain it means "ask a narrower question", not
// "no such host".
func (c *Client) ResolveHost(ctx context.Context, networkID uuid.UUID, ref string) (uuid.UUID, error) {
	if id, err := uuid.Parse(ref); err == nil {
		return id, nil
	}

	res, err := c.ListHosts(ctx, MembershipFilter{
		NetworkID:    networkID,
		NameContains: ref,
		Limit:        resolvePageSize,
	})
	if err != nil {
		return uuid.Nil, err
	}

	var near []string
	for _, h := range res.Value.Memberships {
		if h.Name == ref {
			id, perr := uuid.Parse(h.ID)
			if perr != nil {
				return uuid.Nil, fmt.Errorf("host %q has an unparseable id %q: %w", ref, h.ID, perr)
			}
			return id, nil
		}
		near = append(near, h.Name)
	}

	// The page was full and the exact match was not on it.
	//
	// Reporting "no such host" here would be a lie, and the most expensive kind:
	// name_contains is a SUBSTRING filter, so on a fleet where more than Limit
	// names contain the typed string the exact match can sit on page two. An
	// operator running `orbit membership rm web-1` mid-incident would be told
	// web-1 does not exist. Say what is actually true instead, and name the
	// command that gives an unambiguous answer.
	if res.Value.NextCursor != "" {
		return uuid.Nil, fmt.Errorf(
			"more than %d hosts have %q in their name and none of the first %d matched it exactly; "+
				"narrow the name or pass the uuid from `orbit membership ls`",
			resolvePageSize, ref, resolvePageSize)
	}

	// Nothing matched the substring. The suggestion list must NOT come from the
	// filtered page — it is empty by construction, and reporting it as
	// "available" tells an operator who typo'd a name that their fleet does not
	// exist. One unfiltered fetch, on the error path only, so the cost is paid
	// when someone is already confused rather than on every lookup.
	if len(near) == 0 {
		if all, aerr := c.ListHosts(ctx, MembershipFilter{NetworkID: networkID, Limit: 50}); aerr == nil {
			for _, h := range all.Value.Memberships {
				near = append(near, h.Name)
			}
		}
	}
	return uuid.Nil, &NoMatchError{Kind: "host", Ref: ref, Available: near}
}

// ResolveRole accepts a role name or uuid. Role names are UNIQUE (network_id,
// name), so a name match cannot be ambiguous.
func (c *Client) ResolveRole(ctx context.Context, networkID uuid.UUID, ref string) (uuid.UUID, error) {
	if id, err := uuid.Parse(ref); err == nil {
		return id, nil
	}

	res, err := c.ListRoles(ctx, networkID)
	if err != nil {
		return uuid.Nil, err
	}
	var names []string
	for _, r := range res.Value {
		if r.Name == ref {
			return uuid.Parse(r.ID)
		}
		names = append(names, r.Name)
	}
	return uuid.Nil, &NoMatchError{Kind: "role", Ref: ref, Available: names}
}

// ResolveCA accepts a uuid, a name, or a fingerprint prefix.
//
// The fingerprint prefix is not a convenience: it is the only unique handle a CA
// has besides its uuid. orbit.ca constrains (network_id, fingerprint) and says
// nothing about name, and the moment a rotation matters is exactly the moment
// two CAs are called the same thing — "prod-ca" the one being retired and
// "prod-ca" the one taking over. So a name that matches two is refused, with
// both fingerprints printed to paste back.
func (c *Client) ResolveCA(ctx context.Context, networkID uuid.UUID, ref string) (*wire.CAResponse, error) {
	res, err := c.ListCAs(ctx, networkID)
	if err != nil {
		return nil, err
	}
	cas := res.Value

	if id, perr := uuid.Parse(ref); perr == nil {
		for i := range cas {
			if cas[i].ID == id.String() {
				return &cas[i], nil
			}
		}
		return nil, &NoMatchError{Kind: "certificate authority", Ref: ref, Available: caLabels(cas)}
	}

	// Fingerprints are lowercase hex. Match case-insensitively so a fingerprint
	// pasted from a terminal that upcased it still works.
	lower := strings.ToLower(ref)
	var byFingerprint, byName []*wire.CAResponse
	for i := range cas {
		if strings.HasPrefix(strings.ToLower(cas[i].Fingerprint), lower) && lower != "" {
			byFingerprint = append(byFingerprint, &cas[i])
		}
		if cas[i].Name == ref {
			byName = append(byName, &cas[i])
		}
	}

	// A fingerprint prefix wins over a name. It is the more specific handle, and
	// it is the one this function tells an operator to reach for when a name was
	// ambiguous — that advice has to actually work.
	matches := byFingerprint
	if len(matches) == 0 {
		matches = byName
	}

	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, &NoMatchError{Kind: "certificate authority", Ref: ref, Available: caLabels(cas)}
	default:
		cand := make([]string, 0, len(matches))
		for _, m := range matches {
			cand = append(cand, caLabel(m))
		}
		return nil, &AmbiguousError{
			Kind:       "certificate authority",
			Ref:        ref,
			Candidates: cand,
			Hint: "CA names are not unique within a network (orbit.ca constrains the " +
				"fingerprint, not the name). Use a fingerprint prefix or the uuid.",
		}
	}
}

// caLabel is one line an operator can paste back: a fingerprint prefix long
// enough to be unique in practice, plus what it is.
func caLabel(c *wire.CAResponse) string {
	fp := c.Fingerprint
	if len(fp) > 16 {
		fp = fp[:16]
	}
	return fmt.Sprintf("%-16s  %-8s  %s  (expires %s)", fp, c.State, c.Name, c.NotAfter)
}

func caLabels(cas []wire.CAResponse) []string {
	out := make([]string, 0, len(cas))
	for i := range cas {
		out = append(out, caLabel(&cas[i]))
	}
	return out
}
