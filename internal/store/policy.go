package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/griffithind/orbit/internal/policy"
)

// The network policy document: one per network, versioned, and the switch that
// decides whether it or the per-role rules are what hosts actually render.
//
// See migrations/0009_network_policy.sql for why this is a table with history
// rather than a column, why the document is jsonb, and why the two firewall
// sources are mutually exclusive. The short form of the last one: nebula's
// firewall is allow-only and rules across config files concatenate, so two
// sources can only ever widen reachability — which is the "lower bound
// presented as an answer" that authoritative config mode was built to remove.

// Firewall sources. These mirror the CHECK constraint added in migration 0009;
// adding a value requires changing both.
const (
	// FirewallSourceRole renders orbit.role.firewall_rules for the host's role.
	// The default, and what every existing network is.
	FirewallSourceRole = "role"

	// FirewallSourcePolicy renders the compiled network policy document.
	FirewallSourcePolicy = "policy"
)

// ErrNoPolicy is returned when a network has never had a policy document.
//
// Distinct from ErrNotFound, which for these calls means the NETWORK does not
// exist. The two demand different responses: a bad network reference is a typo,
// while an absent document on a real network is the ordinary state of every
// network that has not opted in, and a caller wanting to switch on policy mode
// needs to be told to write one rather than told the network is missing.
var ErrNoPolicy = errors.New("network has no policy document")

// Policy is one version of a network's policy document.
type Policy struct {
	NetworkID uuid.UUID
	Version   int64

	// Document is the stored jsonb, which is NOT byte-identical to what was
	// submitted: Postgres normalizes jsonb on input, so key order and formatting
	// are lost. That is the deliberate cost of comparing semantically; the
	// migration says why it is the better half of the trade.
	Document []byte

	// ConfigEpoch is the epoch this version produced. It is the only join
	// between a policy version and what a host reported applying: a host at
	// applied_config_epoch = 41 was enforcing the greatest version whose
	// ConfigEpoch is <= 41.
	ConfigEpoch int64

	// Author is who wrote it, as they were named at the time.
	Author    string
	CreatedAt time.Time
}

// PolicyChange describes what a PutPolicy call actually did.
type PolicyChange struct {
	// Policy is the version now current — the newly written one, or the
	// unchanged existing one.
	Policy Policy

	// Changed is false when the submitted document was semantically identical to
	// the stored one. The caller must not bump the config epoch in that case: a
	// bump wakes every agent in the network to fetch and re-render, so a
	// reconcile loop re-applying the same desired state would be fleet-wide work
	// forever. Same reasoning as RoleChange.Changed and
	// UpdateNetworkInstanceDefaults.
	//
	// The comparison is made by Postgres, not here. jsonb normalizes on input,
	// so `=` is a semantic comparison and a re-send with different key order or
	// indentation is correctly nothing. A []byte comparison in Go would call
	// that an edit.
	Changed bool

	// PreviousVersion is 0 when this was the first document the network ever
	// had. Reported so a caller can say "1 -> 2" without a second read.
	PreviousVersion int64
}

// GetPolicy returns the network's current policy document.
//
// Returns ErrNoPolicy when the network exists and has never had one; the caller
// distinguishes that from a bad network reference, which is ErrNotFound.
func (t *Tx) GetPolicy(ctx context.Context, networkID uuid.UUID) (*Policy, error) {
	// The backwards scan the primary key (network_id, version) serves directly.
	p, err := scanPolicy(t.tx.QueryRow(ctx, `
		SELECT network_id, version, document, config_epoch, coalesce(author, ''), created_at
		  FROM orbit.network_policy
		 WHERE network_id = $1
		 ORDER BY version DESC
		 LIMIT 1`, networkID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoPolicy
	}
	if err != nil {
		return nil, mapErr(err, "get policy")
	}
	return p, nil
}

// PolicyAt returns the version that was in force at an instant.
//
// This is the question an incident asks — "what did the policy say last
// Tuesday" — and it is the reason this is a table with history rather than a
// column on orbit.network. Same backwards scan, one extra predicate.
//
// Returns ErrNoPolicy when the network had no document at that time, which is
// the truthful answer for any instant before the first PUT.
func (t *Tx) PolicyAt(ctx context.Context, networkID uuid.UUID, at time.Time) (*Policy, error) {
	p, err := scanPolicy(t.tx.QueryRow(ctx, `
		SELECT network_id, version, document, config_epoch, coalesce(author, ''), created_at
		  FROM orbit.network_policy
		 WHERE network_id = $1 AND created_at <= $2
		 ORDER BY version DESC
		 LIMIT 1`, networkID, at))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoPolicy
	}
	if err != nil {
		return nil, mapErr(err, "policy at")
	}
	return p, nil
}

// ListPolicyVersions returns a network's policy history, newest first.
//
// Bounded by limit rather than unbounded, for the reason every listing here is:
// a document is small but a fleet edited by automation can have thousands of
// versions, and an unbounded read is one a caller cannot recover from.
func (t *Tx) ListPolicyVersions(ctx context.Context, networkID uuid.UUID, limit int) ([]Policy, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := t.tx.Query(ctx, `
		SELECT network_id, version, document, config_epoch, coalesce(author, ''), created_at
		  FROM orbit.network_policy
		 WHERE network_id = $1
		 ORDER BY version DESC
		 LIMIT $2`, networkID, limit)
	if err != nil {
		return nil, mapErr(err, "list policy versions")
	}
	defer rows.Close()

	var out []Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, mapErr(err, "scan policy version")
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func scanPolicy(row interface{ Scan(...any) error }) (*Policy, error) {
	var p Policy
	if err := row.Scan(&p.NetworkID, &p.Version, &p.Document,
		&p.ConfigEpoch, &p.Author, &p.CreatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// PolicyMatches reports whether a document is semantically the one already
// stored.
//
// The dry-run half of PutPolicy's decision, and it exists as its own method
// rather than being reimplemented at the check endpoint so that "would this
// change anything" and "did this change anything" cannot disagree. Both are the
// same jsonb comparison, made by Postgres, over the same column.
//
// False for a network with no document at all: everything is a change to a
// network that has none.
func (t *Tx) PolicyMatches(ctx context.Context, networkID uuid.UUID, document []byte) (bool, error) {
	var same bool
	err := t.tx.QueryRow(ctx, `
		SELECT document = $2::jsonb
		  FROM orbit.network_policy
		 WHERE network_id = $1
		 ORDER BY version DESC
		 LIMIT 1`, networkID, document).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mapErr(err, "compare policy")
	}
	return same, nil
}

// PutPolicy replaces a network's policy document wholesale and reports what it
// did.
//
// WHOLESALE, never merged, for the reason RoleUpdate.Firewall is: merging makes
// "remove this entry" inexpressible, and an entry an operator believes they
// deleted is the worst possible outcome for a firewall.
//
// The sequence is read-compare-bump-insert, and every step is deliberate.
//
// The network row is locked FIRST. That does three jobs with one statement: it
// proves the network exists (so a bad reference is ErrNotFound before anything
// else happens), it serializes concurrent PUTs so two writers cannot both decide
// the next version is N+1, and it orders this against BumpEpoch — which takes
// the same row lock — so the epoch recorded on the row is the epoch this change
// produced and not one a concurrent writer slipped in between.
//
// The comparison is `document IS DISTINCT FROM $2::jsonb`, evaluated by
// Postgres. document is jsonb and jsonb is normalized on input, so this is a
// SEMANTIC comparison: a re-send with different key order, indentation, or
// duplicate keys is correctly recognised as changing nothing, and no epoch is
// bumped for it. Doing this in Go over the raw bytes would make a reformat an
// edit and wake the whole fleet for it.
//
// The epoch is bumped BEFORE the insert, because config_epoch is a column on the
// new row: bumping after would mean writing the row and then updating it, and a
// version that briefly exists with the wrong epoch is a version an incident can
// read at exactly the wrong moment. Nothing is bumped when nothing changed, so
// bumping first costs nothing on the no-op path — it is never reached.
func (t *Tx) PutPolicy(ctx context.Context, networkID uuid.UUID, document []byte, author string) (*PolicyChange, error) {
	if len(document) == 0 {
		// Not a valid policy document and not a meaningful "clear it" either:
		// there is no way to un-set a policy, because a network in policy mode
		// with no document renders an empty firewall, and nebula's firewall is
		// default-deny. Switching firewall_source back to 'role' is how a policy
		// stops being in force.
		return nil, fmt.Errorf("put policy: %w: document is empty", ErrInvalid)
	}

	// Lock the network. See the doc comment: existence, serialization, and
	// epoch ordering, in one statement.
	var lockedID uuid.UUID
	if err := t.tx.QueryRow(ctx,
		`SELECT id FROM orbit.network WHERE id = $1 FOR UPDATE`, networkID).Scan(&lockedID); err != nil {
		return nil, mapErr(err, "lock network for policy write")
	}

	var (
		current Policy
		differs bool
	)
	err := t.tx.QueryRow(ctx, `
		SELECT network_id, version, document, config_epoch, coalesce(author, ''), created_at,
		       document IS DISTINCT FROM $2::jsonb
		  FROM orbit.network_policy
		 WHERE network_id = $1
		 ORDER BY version DESC
		 LIMIT 1`, networkID, document,
	).Scan(&current.NetworkID, &current.Version, &current.Document,
		&current.ConfigEpoch, &current.Author, &current.CreatedAt, &differs)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// The network has never had a document. Everything is a change.
		differs = true
	case err != nil:
		return nil, mapErr(err, "read current policy")
	}

	if !differs {
		// Return what is actually stored rather than what was submitted, so the
		// caller reports the document the network is running.
		return &PolicyChange{Policy: current, PreviousVersion: current.Version}, nil
	}

	epoch, err := t.BumpEpoch(ctx, networkID, EpochConfig)
	if err != nil {
		return nil, err
	}

	next, err := scanPolicy(t.tx.QueryRow(ctx, `
		INSERT INTO orbit.network_policy (network_id, version, document, config_epoch, author)
		VALUES ($1, $2, $3::jsonb, $4, $5)
		RETURNING network_id, version, document, config_epoch, coalesce(author, ''), created_at`,
		networkID, current.Version+1, document, epoch, nullIfEmpty(author)))
	if err != nil {
		return nil, mapErr(err, "insert policy version")
	}
	return &PolicyChange{Policy: *next, Changed: true, PreviousVersion: current.Version}, nil
}

// SetFirewallSource switches which firewall a network's hosts render.
//
// Fleet-wide by construction: every host in the network re-renders its rule set
// on the next poll. The API gates this behind a typed acknowledgement for that
// reason; this function performs it.
//
// Nothing is written and no epoch is bumped when the source already matches. A
// re-issued switch must not wake a fleet to re-render a byte-identical
// configuration — the same argument UpdateNetworkInstanceDefaults makes, and the
// same conditional-UPDATE shape.
//
// Switching TO 'policy' with no document is refused by the trigger added in
// migration 0009, which surfaces here as ErrInvalid. The API checks first so the
// operator gets a sentence; the trigger is what makes the invariant true for
// every other caller, including psql.
//
// No restart is marked, unlike an address change. A firewall is rendered into
// the configuration and nebula applies rules on a hot reload, so this converges
// on the next poll with no process restart anywhere.
func (t *Tx) SetFirewallSource(ctx context.Context, networkID uuid.UUID, source string) (*Network, bool, error) {
	if source != FirewallSourceRole && source != FirewallSourcePolicy {
		return nil, false, fmt.Errorf("set firewall source: %w: source must be %q or %q",
			ErrInvalid, FirewallSourceRole, FirewallSourcePolicy)
	}

	before, err := t.GetNetwork(ctx, networkID)
	if err != nil {
		return nil, false, err
	}

	after, err := scanNetwork(t.tx.QueryRow(ctx, `
		UPDATE orbit.network SET firewall_source = $2
		 WHERE id = $1 AND firewall_source IS DISTINCT FROM $2::text
		RETURNING `+networkCols, networkID, source))
	if errors.Is(err, pgx.ErrNoRows) {
		return before, false, nil // unchanged; no epoch bump, no fleet-wide re-render
	}
	if err != nil {
		return nil, false, mapErr(err, "set firewall source")
	}

	epoch, err := t.BumpEpoch(ctx, networkID, EpochConfig)
	if err != nil {
		return nil, false, err
	}
	after.ConfigEpoch = epoch
	return after, true, nil
}

// PolicyFleet reads the hosts a policy document's selectors resolve against.
//
// Returns policy.Membership directly rather than a store-native struct a caller then
// translates. The translation layer was considered and rejected: it would be a
// field-by-field copy whose only failure mode is a field NOT copied, and the
// field most likely to be forgotten is Tags — at which point every tag:
// selector matches nothing, the document still compiles, every host still
// renders, and the rules are simply narrower than the operator wrote. That is
// invisible from every direction. A shared struct makes it a build error
// instead.
//
// The dependency is safe in the direction that matters: internal/policy imports
// nothing but the standard library and knows nothing about a database, which is
// the property enroll.PolicySource's comment is protecting. This is store
// depending on a pure type package, in the same way it already depends on
// net/netip.
//
// Every host in the network, not only the enrolled ones. A host that has been
// created but never enrolled has no addresses yet and the compiler skips it
// deliberately (an unassigned host compiles to nothing rather than to a rule
// naming an address somebody else will be given) — but a host that IS named by
// a host: selector and is merely not enrolled yet must still resolve, or
// declaring policy before bringing machines up would be impossible.
//
// Deleted hosts are excluded. Their addresses are released and their
// certificates revoked, so a rule naming one would authorise a prefix the next
// host to be allocated will hold.
func (t *Tx) PolicyFleet(ctx context.Context, networkID uuid.UUID) ([]policy.Membership, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT h.id, h.name, coalesce(r.name, ''), h.tags,
		       coalesce(array(SELECT a.addr FROM orbit.membership_address a
		                       WHERE a.membership_id = h.id ORDER BY a.addr), '{}')
		  FROM orbit.membership h
		  LEFT JOIN orbit.role r ON (r.network_id, r.id) = (h.network_id, h.role_id)
		 WHERE h.network_id = $1 AND h.state <> 'deleted'
		 ORDER BY h.name`, networkID)
	if err != nil {
		return nil, mapErr(err, "policy fleet")
	}
	defer rows.Close()

	var out []policy.Membership
	for rows.Next() {
		var (
			id uuid.UUID
			h  policy.Membership
		)
		if err := rows.Scan(&id, &h.Name, &h.Role, &h.Tags, &h.Addrs); err != nil {
			return nil, mapErr(err, "scan policy fleet host")
		}
		h.ID = id.String()
		out = append(out, h)
	}
	return out, rows.Err()
}

// NetworkPolicy is the enroll.PolicySource for this store.
//
// A free function rather than a method because it has to MATCH that type
// exactly — the whole point of the seam is that a deployment wires it in or does
// not, and a method's receiver would put a store handle in a signature the
// compiler package is deliberately kept away from.
//
// THE OPT-IN IS ENFORCED HERE, and this is the only place it can be enforced
// once. doc is nil unless the network's firewall_source is 'policy', so a
// document that has been written but not switched on is never rendered by
// anything — the render path cannot forget to check, because it is never handed
// a document to render. A network in role mode reads exactly as a network with
// no document at all, which is what keeps the per-role path byte-identical to
// what it was before any of this existed.
//
// The fleet is read in the SAME transaction as the document, which is why the
// tx is threaded through rather than a Store: a fleet from one snapshot compiled
// against a document from another produces rules for a network that never
// existed.
func NetworkPolicy(ctx context.Context, tx *Tx, networkID uuid.UUID) ([]byte, []policy.Membership, error) {
	net, err := tx.GetNetwork(ctx, networkID)
	if err != nil {
		return nil, nil, err
	}
	if net.FirewallSource != FirewallSourcePolicy {
		return nil, nil, nil
	}

	p, err := tx.GetPolicy(ctx, networkID)
	if err != nil {
		if errors.Is(err, ErrNoPolicy) {
			// Unreachable through the API and the schema both — the trigger in
			// migration 0009 refuses this combination — so reaching it means the
			// row was written by something that bypassed both. Reported as no
			// policy rather than as an error, because the alternative is refusing
			// to render a certificate, and a network stuck in this state needs an
			// operator either way.
			return nil, nil, nil
		}
		return nil, nil, err
	}

	fleet, err := tx.PolicyFleet(ctx, networkID)
	if err != nil {
		return nil, nil, err
	}
	return p.Document, fleet, nil
}

// LiveHostCount is how many hosts of a network are actually on the mesh.
//
// The number that decides whether a fleet-wide change needs an acknowledgement:
// a switch on a network with no live hosts disrupts nothing, and demanding a
// confirmation there would teach operators to always pass the flag, which is
// what makes a confirmation on the dangerous case worthless.
//
// 'enrolled' and 'active' only, matching every other place that means "carrying
// traffic": a created-but-never-enrolled host has no configuration to change,
// and a suspended or deleted one is not rendering anything.
func (t *Tx) LiveHostCount(ctx context.Context, networkID uuid.UUID) (int, error) {
	var n int
	err := t.tx.QueryRow(ctx, `
		SELECT count(*) FROM orbit.membership
		 WHERE network_id = $1 AND state IN ('enrolled', 'active')`, networkID).Scan(&n)
	if err != nil {
		return 0, mapErr(err, "live host count")
	}
	return n, nil
}

// Audit actions for the policy document.
//
// Declared here rather than with their siblings in audit.go for the reason
// ActionRoleGroupsChanged is declared beside UpdateRole: what matters about them
// is the split between them, and the split is only legible next to the code that
// explains it.
//
// ActionPolicyUpdated is a document edit — fleet-wide, but reversible by another
// edit and in force within seconds.
//
// ActionFirewallSourceChanged is the posture change, and it is a separate action
// rather than metadata on the first for the same reason ca.force_activated is
// separate from ca.activated: "when did this network stop enforcing its role
// rules" is the question an incident review asks, and it should be a WHERE
// clause rather than a scan through JSON. It is also the entry that explains why
// a rule an operator can still see on a role stopped having any effect.
const (
	ActionPolicyUpdated         = "policy.updated"
	ActionFirewallSourceChanged = "network.firewall_source_changed"
)
