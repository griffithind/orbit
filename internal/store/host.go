package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateHost inserts a host and claims its overlay addresses.
//
// Addresses go into host_address, whose primary key is (network_id, addr). Two
// concurrent requests racing for the same address therefore cannot both
// succeed: one gets ErrConflict from the database. An application-level "is
// this address taken?" check would have a window between the check and the
// insert, and the loser of that race would be a host that cannot communicate.
//
// A host created with no address is legal and is what the allocating path wants:
// CreateHostAllocating inserts the row and then allocates inside the same
// transaction, so the allocation and the host commit together or neither does.
func (t *Tx) CreateHost(ctx context.Context, h *Host) error {
	if h.State == "" {
		h.State = HostCreated
	}
	if len(h.Overrides) == 0 {
		h.Overrides = []byte(`{}`)
	}

	err := t.tx.QueryRow(ctx, `
		INSERT INTO orbit.host (network_id, name, role_id, tags,
		                        is_lighthouse, is_relay, static_addrs, state,
		                        listen_port, tun_dev, config_mode, config_overrides)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at`,
		h.NetworkID, h.Name, h.RoleID, nonNil(h.Tags),
		h.IsLighthouse, h.IsRelay, nonNil(h.StaticAddrs), h.State,
		h.ListenPort, nullIfEmpty(h.TunDev), nullIfEmpty(h.ConfigMode), h.Overrides,
	).Scan(&h.ID, &h.CreatedAt)
	if err != nil {
		return mapErr(err, "create host")
	}

	for _, addr := range h.Addrs {
		if _, err := t.tx.Exec(ctx, `
			INSERT INTO orbit.host_address (network_id, host_id, addr)
		VALUES ($1, $2, $3)`,
			h.NetworkID, h.ID, addr); err != nil {
			return mapErr(err, "claim overlay address")
		}
	}
	return nil
}

// CreateHostAllocating inserts a host and allocates it an address.
//
// One transaction, deliberately. Splitting it into "create the host, then ask
// for an address" would leave a host with no address every time the second half
// failed — and a host with no address is not a partially-configured host, it is
// one that can never be issued a certificate (enroll.certNetworks refuses it).
//
// prefix selects which of the network's prefixes to allocate from; the zero
// value takes the first. No epoch bump and no restart marking: the host does not
// exist yet as far as any running nebula is concerned.
func (t *Tx) CreateHostAllocating(ctx context.Context, net *Network, h *Host, prefix netip.Prefix) error {
	h.Addrs = nil
	if err := t.CreateHost(ctx, h); err != nil {
		return err
	}
	addr, err := t.AllocateHostAddress(ctx, net, h.ID, prefix)
	if err != nil {
		return err
	}
	h.Addrs = []netip.Addr{addr}
	return nil
}

const hostCols = `h.id, h.network_id, h.name, h.role_id, h.tags,
	h.is_lighthouse, h.is_relay, h.static_addrs, h.state,
	h.applied_config_epoch, h.applied_blocklist_epoch,
	h.last_seen_at, coalesce(h.nebula_version, ''), coalesce(h.agent_version, ''),
	h.created_at, coalesce(r.name, ''),
	coalesce(array(SELECT a.addr FROM orbit.host_address a WHERE a.host_id = h.id
	               ORDER BY a.addr), '{}'),
	h.listen_port, coalesce(h.tun_dev, ''), coalesce(h.config_mode, ''),
	h.config_overrides, h.restart_required_epoch, h.addr_changed_at`

// hostFrom is the FROM clause hostCols is written against; the two travel
// together because hostCols selects the role name out of it.
//
// The join is composite — (network_id, id) — for the same reason the schema's
// foreign key is: a role belongs to exactly one network, and a join on role id
// alone would happily attach another network's name to a host if a row ever got
// past that constraint. LEFT, because a host may have no role at all.
const hostFrom = `FROM orbit.host h
	LEFT JOIN orbit.role r ON (r.network_id, r.id) = (h.network_id, h.role_id)`

func scanHost(row interface{ Scan(...any) error }) (*Host, error) {
	var h Host
	err := row.Scan(&h.ID, &h.NetworkID, &h.Name, &h.RoleID, &h.Tags,
		&h.IsLighthouse, &h.IsRelay, &h.StaticAddrs, &h.State,
		&h.AppliedConfigEpoch, &h.AppliedBlocklistEpoch,
		&h.LastSeenAt, &h.NebulaVersion, &h.AgentVersion, &h.CreatedAt,
		&h.RoleName, &h.Addrs,
		&h.ListenPort, &h.TunDev, &h.ConfigMode, &h.Overrides,
		&h.RestartRequiredEpoch, &h.AddrChangedAt)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func (t *Tx) GetHost(ctx context.Context, id uuid.UUID) (*Host, error) {
	h, err := scanHost(t.tx.QueryRow(ctx,
		`SELECT `+hostCols+` `+hostFrom+` WHERE h.id = $1`, id))
	if err != nil {
		return nil, mapErr(err, "get host")
	}
	return h, nil
}

// HostCursor is a position in a host listing: the sort key of the last row a
// caller has already seen.
//
// Keyset, not OFFSET. An offset is a count of rows the database must walk and
// then discard, and it is computed against whatever the table looks like at the
// moment of the second request: a host created or deleted between two page
// fetches shifts every later page by one, silently skipping or repeating a row.
// A key comparison names a position instead of a distance, so concurrent
// inserts change what comes after the cursor without moving what came before.
//
// Name alone would be unique — UNIQUE (network_id, name), and a listing is
// scoped to one network — so ID is not breaking a tie. It is there so the
// cursor is a total order over a single index-friendly row comparison, and so
// the key survives that uniqueness constraint ever being relaxed.
type HostCursor struct {
	Name string
	ID   uuid.UUID
}

// HostFilter narrows a host listing. Zero values mean "no constraint".
//
// Every field is applied in SQL. Filtering in Go would mean fetching the whole
// host table on every request to answer a question about a handful of rows —
// the same argument NetworkTopology makes, and it matters most here because the
// filter an operator reaches for during an incident (Behind) is the one that
// runs against the largest network they have.
type HostFilter struct {
	NetworkID uuid.UUID

	// State, Tag, RoleID, and NameContains are the operator's four questions:
	// what is suspended, what carries this tag, what carries this role, and
	// "the web boxes, I don't remember the exact names".
	State        string
	Tag          string
	RoleID       *uuid.UUID
	NameContains string

	// Behind selects hosts that have not applied the network's current config
	// or blocklist epoch. It is the question /v1/networks/{id}/convergence
	// answers as a summary, asked here as a filter so the answer is a list that
	// can be acted on rather than a count.
	//
	// Scoped to enrolled and active hosts, exactly as Convergence counts them.
	// A host in 'created' has never held a certificate and can never report an
	// epoch, so including it would make this filter permanently non-empty and
	// make its result disagree with the number on the convergence endpoint.
	Behind bool

	// After is the keyset cursor; nil starts at the beginning.
	After *HostCursor

	// Limit bounds the page. Out of range falls back to the default, which is
	// why the API layer refuses a limit it cannot honour instead of passing it
	// through — a caller who asks for 5000 and receives 100 has no way to tell.
	Limit int

	// WithCount asks for the total matching the filter. Opt-in because it is a
	// second query that visits every matching row: a CLI printing one page does
	// not need it, and a UI wants it once rather than on every scroll.
	WithCount bool
}

// HostPage is one page of a host listing.
type HostPage struct {
	Hosts []Host

	// More reports whether another page exists. Determined by reading one row
	// past the limit, not by comparing len(Hosts) with it: a final page that is
	// exactly full is indistinguishable from a full page with more behind it,
	// and guessing wrong hands the client a cursor that returns nothing.
	More bool

	// Total is the number of hosts matching the filter, ignoring pagination.
	// nil unless WithCount asked for it, so "not requested" and "zero" are
	// different values rather than the same 0.
	Total *int
}

const (
	hostPageDefault = 100
	// HostPageMax is the largest page this store will produce. Exported because
	// the API layer refuses anything larger rather than silently returning the
	// default, and the two numbers must be the same one.
	HostPageMax = 1000
)

// hostFilterWhere is shared verbatim by the page query and the count query.
//
// One text, so a filter cannot come to mean two different things — a count that
// disagrees with the rows it is supposed to be counting is worse than no count.
// Parameters $1..$6 are the same in both, and only the page query adds a cursor
// and a limit after them.
//
// Deleted hosts are excluded unconditionally: DeleteHost removes the row
// outright, so the state exists for a host on its way out, and a decommissioned
// machine is not part of the fleet a listing describes.
const hostFilterWhere = `
	 WHERE h.network_id = $1
	   AND h.state <> 'deleted'
	   AND ($2 = '' OR h.state = $2)
	   AND ($3 = '' OR $3 = ANY (h.tags))
	   AND ($4::uuid IS NULL OR h.role_id = $4)
	   -- strpos rather than LIKE: a name containing % or _ is a legal name, and
	   -- with LIKE it would silently become a pattern that matches other hosts.
	   AND ($5 = '' OR strpos(lower(h.name), lower($5)) > 0)
	   AND (NOT $6 OR (h.state IN ('enrolled', 'active')
	                   AND (h.applied_config_epoch < n.config_epoch
	                     OR h.applied_blocklist_epoch < n.blocklist_epoch)))`

// ListHosts returns one page of the hosts in a network, ordered by (name, id).
func (t *Tx) ListHosts(ctx context.Context, f HostFilter) (HostPage, error) {
	if f.Limit <= 0 || f.Limit > HostPageMax {
		f.Limit = hostPageDefault
	}

	var roleID, cursorName, cursorID any
	if f.RoleID != nil {
		roleID = *f.RoleID
	}
	if f.After != nil {
		cursorName, cursorID = f.After.Name, f.After.ID
	}

	var page HostPage
	if f.WithCount {
		// Before the page, so the count describes the same snapshot the rows
		// come from. Both statements run in the caller's transaction, which is
		// what makes that true rather than merely likely.
		var total int
		if err := t.tx.QueryRow(ctx, `
			SELECT count(*) FROM orbit.host h
			  JOIN orbit.network n ON n.id = h.network_id`+hostFilterWhere,
			f.NetworkID, f.State, f.Tag, roleID, f.NameContains, f.Behind,
		).Scan(&total); err != nil {
			return HostPage{}, mapErr(err, "count hosts")
		}
		page.Total = &total
	}

	rows, err := t.tx.Query(ctx,
		`SELECT `+hostCols+` `+hostFrom+`
		  JOIN orbit.network n ON n.id = h.network_id`+hostFilterWhere+`
		   AND ($7::text IS NULL OR (h.name, h.id) > ($7, $8::uuid))
		 ORDER BY h.name, h.id
		 LIMIT $9`,
		f.NetworkID, f.State, f.Tag, roleID, f.NameContains, f.Behind,
		cursorName, cursorID, f.Limit+1)
	if err != nil {
		return HostPage{}, mapErr(err, "list hosts")
	}
	defer rows.Close()

	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return HostPage{}, mapErr(err, "scan host")
		}
		page.Hosts = append(page.Hosts, *h)
	}
	if err := rows.Err(); err != nil {
		return HostPage{}, mapErr(err, "list hosts")
	}

	if len(page.Hosts) > f.Limit {
		page.Hosts = page.Hosts[:f.Limit]
		page.More = true
	}
	return page, nil
}

// SetHostState transitions a host. Returns ErrNotFound if it does not exist.
func (t *Tx) SetHostState(ctx context.Context, id uuid.UUID, state string) error {
	tag, err := t.tx.Exec(ctx, `UPDATE orbit.host SET state = $2 WHERE id = $1`, id, state)
	if err != nil {
		return mapErr(err, "set host state")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AgentReport is what an agent tells us after applying a configuration.
type AgentReport struct {
	ConfigEpoch    int64
	BlocklistEpoch int64
	NebulaVersion  string
	AgentVersion   string

	// RevertedFromConfigEpoch and RevertedFromBlocklistEpoch name the generation
	// the host was running before its guard reverted it. They are the only way a
	// recorded epoch may move backwards; see RecordAgentReport.
	RevertedFromConfigEpoch    int64
	RevertedFromBlocklistEpoch int64

	// QuarantinedConfigEpoch is a generation the agent is refusing to apply.
	// Recorded in the revert's audit entry so an operator can see which push the
	// host rejected, rather than inferring it from a host that is merely behind.
	QuarantinedConfigEpoch int64
}

// ActionConfigReverted is the audit action for a host whose guard put the
// previous generation back.
//
// Declared here rather than beside its siblings in audit.go because this is the
// only place that writes it, and because the alternative — reusing
// ActionHostUpdated — would file an automatic, agent-initiated rollback under
// the same name as an operator editing a host. The one question this entry
// exists to answer ("which push severed hosts, and how many?") is a `WHERE
// action = ...` away only if the action is its own.
const ActionConfigReverted = "host.config_reverted"

// RecordAgentReport stores what a host has actually applied.
//
// The epochs move forward only, with one audited exception.
//
// Monotonic is the right default: an agent that reports a lower epoch than we
// already recorded is usually replaying, or its reports arrived out of order,
// and letting either lower the number would make a network look less converged
// than it is and could stall a CA rotation waiting on a value that keeps
// regressing.
//
// The exception is the unreachable-guard. When a host applies a configuration
// that severs its own path back here, the guard reverts it and the host really
// is no longer running what it last reported. Keeping the higher number then is
// not conservatism, it is a lie in the one direction that matters: the
// convergence gate whose entire purpose is stopping a CA rotation from
// partitioning the fleet would pass on evidence that every host converged on a
// generation every host has since thrown away.
//
// So a lowering is accepted only when the agent names the epoch it reverted FROM
// and that name matches what we currently hold. Two properties follow, and both
// are load-bearing:
//
//   - A replayed revert report is a no-op. Once the lowering has been applied
//     the stored epoch no longer equals RevertedFrom, so a duplicate cannot
//     regress the host a second time.
//   - A report that merely carries a smaller number still cannot lower anything.
//     Regression stays impossible except as a deliberate, matched statement.
//
// The whole decision is one statement so it cannot interleave, and the row is
// locked first so the value the CASE compares against is the value we audit.
//
// The audit entry is written here rather than returned for the caller to write.
// The caller is the agent report handler, which has no other reason to open the
// audit path, and an audit record that can be dropped by forgetting to call
// something is not an audit record. Writing it inside the caller's transaction
// is the same guarantee AppendAudit exists to give: the regression and the
// evidence for it commit together or not at all.
func (t *Tx) RecordAgentReport(ctx context.Context, hostID uuid.UUID, r AgentReport) error {
	var (
		name string
		wasConfig, wasBlock,
		nowConfig, nowBlock int64
	)
	err := t.tx.QueryRow(ctx, `
		WITH locked AS (
			SELECT id, name,
			       applied_config_epoch    AS was_config,
			       applied_blocklist_epoch AS was_block
			  FROM orbit.host WHERE id = $1 FOR UPDATE
		)
		UPDATE orbit.host h
		   SET applied_config_epoch = CASE
		           WHEN $6 <> 0 AND locked.was_config = $6 AND $2 < locked.was_config
		           THEN $2
		           ELSE greatest(locked.was_config, $2) END,
		       applied_blocklist_epoch = CASE
		           WHEN $7 <> 0 AND locked.was_block = $7 AND $3 < locked.was_block
		           THEN $3
		           ELSE greatest(locked.was_block, $3) END,
		       nebula_version = coalesce(nullif($4, ''), h.nebula_version),
		       agent_version  = coalesce(nullif($5, ''), h.agent_version),
		       last_seen_at   = now()
		  FROM locked
		 WHERE h.id = locked.id
		RETURNING locked.name, locked.was_config, locked.was_block,
		          h.applied_config_epoch, h.applied_blocklist_epoch`,
		hostID, r.ConfigEpoch, r.BlocklistEpoch, r.NebulaVersion, r.AgentVersion,
		r.RevertedFromConfigEpoch, r.RevertedFromBlocklistEpoch,
	).Scan(&name, &wasConfig, &wasBlock, &nowConfig, &nowBlock)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return mapErr(err, "record agent report")
	}

	if nowConfig >= wasConfig && nowBlock >= wasBlock {
		return nil
	}

	// A regression got through, which by construction means the guard reverted.
	// Nobody watching convergence would otherwise learn that a number went down.
	meta, err := json.Marshal(map[string]any{
		"was_config_epoch":         wasConfig,
		"was_blocklist_epoch":      wasBlock,
		"applied_config_epoch":     nowConfig,
		"applied_blocklist_epoch":  nowBlock,
		"quarantined_config_epoch": r.QuarantinedConfigEpoch,
		"agent_version":            r.AgentVersion,
	})
	if err != nil {
		return fmt.Errorf("encode revert audit metadata: %w", err)
	}
	return t.AppendAudit(ctx, AuditEntry{
		ActorType: ActorAgent, ActorID: hostID.String(), ActorDisplay: name,
		Action:     ActionConfigReverted,
		TargetType: "host", TargetID: hostID.String(),
		Meta: meta,
	})
}

//------------------------------------------------------------------------------
// Certificates
//------------------------------------------------------------------------------

// InsertCertificate records a newly issued certificate and supersedes the
// previous active one for the same host and certificate version.
//
// Scoping by version matters: during a v1 to v2 migration a host legitimately
// holds one active certificate of each version, and superseding across versions
// would revoke half of a working configuration.
func (t *Tx) InsertCertificate(ctx context.Context, c *Certificate) error {
	if c.State == "" {
		c.State = CertActive
	}

	if c.State == CertActive {
		if _, err := t.tx.Exec(ctx, `
			UPDATE orbit.certificate SET state = 'superseded'
			 WHERE host_id = $1 AND cert_version = $2 AND state = 'active'`,
			c.HostID, c.CertVer); err != nil {
			return mapErr(err, "supersede previous certificate")
		}
	}

	// Idempotent on an identical certificate for the same host.
	//
	// Nebula encodes validity to second granularity, so two renewals inside the
	// same second that reuse the key produce byte-identical certificates and
	// therefore the same fingerprint. That is not an error: the certificate
	// exists and belongs to this host. A retried renewal must not 500.
	//
	// The WHERE clause keeps this narrow. If the fingerprint somehow belongs to
	// a different host, no row is returned and the caller sees a conflict, which
	// is the correct outcome for what would be a genuine collision.
	// network_id is selected from the host rather than accepted as a parameter.
	//
	// The column exists to carry certificate's composite references to host and
	// ca (see 0001_schema.sql), and a caller-supplied value would be one more
	// place the two could disagree — the exact failure the composite keys are
	// there to prevent. Deriving it in the same statement means the row cannot
	// be written with a network that is not the host's, no matter what any
	// caller does. A host id that resolves to nothing selects no row and the
	// insert affects nothing, which surfaces as the ErrNotFound below.
	err := t.tx.QueryRow(ctx, `
		INSERT INTO orbit.certificate (network_id, host_id, ca_id, fingerprint, pem,
		                               cert_version, not_before, not_after, state)
		SELECT h.network_id, $1, $2, $3, $4, $5, $6, $7, $8
		  FROM orbit.host h WHERE h.id = $1
		ON CONFLICT (fingerprint) DO UPDATE
		   SET state = EXCLUDED.state
		 WHERE orbit.certificate.host_id = EXCLUDED.host_id
		RETURNING id, issued_at`,
		c.HostID, c.CAID, c.Fingerprint, c.PEM,
		c.CertVer, c.NotBefore, c.NotAfter, c.State,
	).Scan(&c.ID, &c.IssuedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("insert certificate: %w: fingerprint belongs to another host", ErrConflict)
		}
		return mapErr(err, "insert certificate")
	}
	return nil
}

const certCols = `id, host_id, ca_id, fingerprint, pem, cert_version,
	not_before, not_after, state, issued_at`

func scanCert(row interface{ Scan(...any) error }) (*Certificate, error) {
	var c Certificate
	err := row.Scan(&c.ID, &c.HostID, &c.CAID, &c.Fingerprint, &c.PEM, &c.CertVer,
		&c.NotBefore, &c.NotAfter, &c.State, &c.IssuedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (t *Tx) ActiveCertificates(ctx context.Context, hostID uuid.UUID) ([]Certificate, error) {
	rows, err := t.tx.Query(ctx,
		`SELECT `+certCols+` FROM orbit.certificate
		  WHERE host_id = $1 AND state = 'active' ORDER BY cert_version`, hostID)
	if err != nil {
		return nil, mapErr(err, "active certificates")
	}
	defer rows.Close()

	var out []Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, mapErr(err, "scan certificate")
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// CertificateRow is one row of a host's certificate history.
//
// Not store.Certificate, and the difference is the point: this carries the
// issuing CA's NAME, and it carries no PEM.
//
// The name, because "which CA signed this" is asked during a rotation, where
// the answer decides whether a host has moved to the new authority — and a uuid
// turns that into a second lookup per row for a client that then has to render
// it anyway. The join is composite, so a row cannot be labelled with another
// network's CA name.
//
// No PEM, because it is the largest column by an order of magnitude and a host
// that has renewed hourly for a year has thousands of rows here. Nothing an
// operator reads out of a history needs the bytes; LatestCertificate is where
// the PEM comes from when something actually needs it.
type CertificateRow struct {
	ID          uuid.UUID
	HostID      uuid.UUID
	CAID        uuid.UUID
	CAName      string
	Fingerprint string
	CertVer     int16
	NotBefore   time.Time
	NotAfter    time.Time
	State       string
	IssuedAt    time.Time
}

// RenewAt reports when this certificate should have been renewed. It delegates
// to Certificate.RenewAt so the 50%-of-lifetime rule has exactly one definition;
// a second copy of that arithmetic is a second thing to get out of step with the
// agent's schedule and the renewal sweep.
func (c CertificateRow) RenewAt() time.Time {
	return Certificate{NotBefore: c.NotBefore, NotAfter: c.NotAfter}.RenewAt()
}

// CertCursor is a position in a certificate history: the sort key of the last
// row already seen. Keyset for the same reason HostCursor is, and over
// (issued_at, id) because issued_at is not unique — two renewals in the same
// second are ordinary, and a cursor on a non-unique key alone either repeats or
// skips them.
type CertCursor struct {
	IssuedAt time.Time
	ID       uuid.UUID
}

// CertFilter narrows a host's certificate history.
type CertFilter struct {
	// State selects one of pending, active, superseded, revoked. Empty means
	// the whole history, which is what makes "has this host been renewing"
	// answerable at all.
	State string
	After *CertCursor
	Limit int
}

// CertPage is one page of a certificate history.
type CertPage struct {
	Certificates []CertificateRow
	More         bool
}

const (
	certPageDefault = 50
	// CertPageMax bounds a page for the same reason HostPageMax does.
	CertPageMax = 500
)

// HostCertificates returns one page of a host's certificates, newest first.
//
// Paginated from the start, not once it hurts: certificate rows are never
// deleted except by host cascade, so a host renewing hourly accumulates
// thousands, and an unbounded "history" endpoint would be a way to make the
// control plane serialize megabytes on request.
//
// Newest first because every question asked of this — when does it expire, has
// it been renewing, which CA signed the current one — is about the recent end.
func (t *Tx) HostCertificates(ctx context.Context, hostID uuid.UUID, f CertFilter) (CertPage, error) {
	if f.Limit <= 0 || f.Limit > CertPageMax {
		f.Limit = certPageDefault
	}

	var cursorAt, cursorID any
	if f.After != nil {
		cursorAt, cursorID = f.After.IssuedAt, f.After.ID
	}

	rows, err := t.tx.Query(ctx, `
		SELECT c.id, c.host_id, c.ca_id, ca.name, c.fingerprint, c.cert_version,
		       c.not_before, c.not_after, c.state, c.issued_at
		  FROM orbit.certificate c
		  JOIN orbit.ca ca ON (ca.network_id, ca.id) = (c.network_id, c.ca_id)
		 WHERE c.host_id = $1
		   AND ($2 = '' OR c.state = $2)
		   AND ($3::timestamptz IS NULL OR (c.issued_at, c.id) < ($3, $4::uuid))
		 ORDER BY c.issued_at DESC, c.id DESC
		 LIMIT $5`,
		hostID, f.State, cursorAt, cursorID, f.Limit+1)
	if err != nil {
		return CertPage{}, mapErr(err, "host certificates")
	}
	defer rows.Close()

	var page CertPage
	for rows.Next() {
		var c CertificateRow
		if err := rows.Scan(&c.ID, &c.HostID, &c.CAID, &c.CAName, &c.Fingerprint,
			&c.CertVer, &c.NotBefore, &c.NotAfter, &c.State, &c.IssuedAt); err != nil {
			return CertPage{}, mapErr(err, "scan certificate")
		}
		page.Certificates = append(page.Certificates, c)
	}
	if err := rows.Err(); err != nil {
		return CertPage{}, mapErr(err, "host certificates")
	}

	if len(page.Certificates) > f.Limit {
		page.Certificates = page.Certificates[:f.Limit]
		page.More = true
	}
	return page, nil
}

// CertificatesDueForRenewal returns active certificates past the midpoint of
// their lifetime, oldest first. This drives the renewal sweep; agents also
// renew on their own schedule, and the sweep exists to catch the ones that
// are not.
func (t *Tx) CertificatesDueForRenewal(ctx context.Context, networkID uuid.UUID, now time.Time, limit int) ([]Certificate, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT c.id, c.host_id, c.ca_id, c.fingerprint, c.pem, c.cert_version,
		       c.not_before, c.not_after, c.state, c.issued_at
		  FROM orbit.certificate c
		  JOIN orbit.host h ON h.id = c.host_id
		 WHERE h.network_id = $1
		   AND c.state = 'active'
		   AND h.state IN ('enrolled', 'active')
		   AND $2 >= c.not_before + (c.not_after - c.not_before) / 2
		 ORDER BY c.not_after
		 LIMIT $3`, networkID, now, limit)
	if err != nil {
		return nil, mapErr(err, "certificates due for renewal")
	}
	defer rows.Close()

	var out []Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, mapErr(err, "scan certificate")
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

//------------------------------------------------------------------------------
// Enrollment credentials
//------------------------------------------------------------------------------

// CreateEnrollmentCredential stores the hash of an enrollment secret.
//
// The caller supplies a keyed hash and never persists the plaintext; it exists
// only in the HTTP response that created it. Keying it means a database leak on
// its own yields nothing usable.
func (t *Tx) CreateEnrollmentCredential(ctx context.Context, c *EnrollmentCredential, secretHash []byte) error {
	if c.Method == "" {
		c.Method = MethodCode
	}
	err := t.tx.QueryRow(ctx, `
		INSERT INTO orbit.enrollment_credential
			(network_id, host_id, method, secret_hash, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at`,
		c.NetworkID, c.HostID, c.Method, secretHash, c.ExpiresAt, c.CreatedBy,
	).Scan(&c.ID, &c.CreatedAt)
	return mapErr(err, "create enrollment credential")
}

// PruneExpiredCredentials deletes unredeemed credentials past their expiry.
// Redeemed ones are retained: they are evidence.
func (t *Tx) PruneExpiredCredentials(ctx context.Context, before time.Time) (int64, error) {
	tag, err := t.tx.Exec(ctx, `
		DELETE FROM orbit.enrollment_credential
		 WHERE used_at IS NULL AND expires_at < $1`, before)
	if err != nil {
		return 0, mapErr(err, "prune credentials")
	}
	return tag.RowsAffected(), nil
}

// FindHostByAddr looks up a host by one of its overlay addresses.
//
// Used by the control plane to find its own record across restarts. Distinct
// from ResolveAgentHost, which answers an agent request from a source address;
// this one runs inside the caller's transaction.
func (t *Tx) FindHostByAddr(ctx context.Context, networkID uuid.UUID, addr netip.Addr) (*Host, error) {
	h, err := scanHost(t.tx.QueryRow(ctx,
		`SELECT `+hostCols+` `+hostFrom+`
		   JOIN orbit.host_address a ON a.host_id = h.id
		  WHERE a.network_id = $1 AND a.addr = $2`, networkID, addr))
	if err != nil {
		return nil, mapErr(err, "find host by address")
	}
	return h, nil
}

// LatestCertificate returns the most recently issued certificate for a host,
// whatever its state.
//
// Recovery needs this: a host past expiry has no *active* certificate, but the
// public key in its last one is the only thing that can prove the host is who it
// claims to be.
func (t *Tx) LatestCertificate(ctx context.Context, hostID uuid.UUID) (*Certificate, error) {
	c, err := scanCert(t.tx.QueryRow(ctx,
		`SELECT `+certCols+` FROM orbit.certificate
		  WHERE host_id = $1 ORDER BY issued_at DESC LIMIT 1`, hostID))
	if err != nil {
		return nil, mapErr(err, "latest certificate")
	}
	return c, nil
}

// SetHostRoles updates a host's data-plane roles and advertised addresses.
//
// Bumps the config epoch when anything changed, because these are exactly the
// fields other hosts render into their static_host_map and relay list. A change
// nobody is told about is a lighthouse half the mesh still dials and half does
// not.
func (t *Tx) SetHostRoles(ctx context.Context, hostID uuid.UUID, isLighthouse, isRelay bool, staticAddrs []string) error {
	var networkID uuid.UUID
	err := t.tx.QueryRow(ctx, `
		UPDATE orbit.host
		   SET is_lighthouse = $2, is_relay = $3, static_addrs = $4
		 WHERE id = $1
		   AND (is_lighthouse, is_relay, static_addrs) IS DISTINCT FROM ($2, $3, $4::text[])
		RETURNING network_id`,
		hostID, isLighthouse, isRelay, nonNil(staticAddrs)).Scan(&networkID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // unchanged; no epoch bump, no needless config churn
		}
		return mapErr(err, "set host roles")
	}
	_, err = t.BumpEpoch(ctx, networkID, EpochConfig)
	return err
}

// UpdateHostMeta changes a host's role assignment and tags.
//
// Separate from SetHostRoles because these do not change network topology: a
// tag is metadata, and a role change alters the host's own firewall rules and
// groups but not what other hosts render about it. Both still advance the
// config epoch, since the host itself needs the new configuration.
func (t *Tx) UpdateHostMeta(ctx context.Context, hostID uuid.UUID, roleID *string, tags *[]string) error {
	host, err := t.GetHost(ctx, hostID)
	if err != nil {
		return err
	}

	newRole := host.RoleID
	if roleID != nil {
		if *roleID == "" {
			newRole = nil
		} else {
			parsed, err := uuid.Parse(*roleID)
			if err != nil {
				return fmt.Errorf("invalid role_id: %w", err)
			}
			newRole = &parsed
		}
	}
	newTags := host.Tags
	if tags != nil {
		newTags = *tags
	}

	if _, err := t.tx.Exec(ctx,
		`UPDATE orbit.host SET role_id = $2, tags = $3 WHERE id = $1`,
		hostID, newRole, nonNil(newTags)); err != nil {
		return mapErr(err, "update host")
	}
	_, err = t.BumpEpoch(ctx, host.NetworkID, EpochConfig)
	return err
}
