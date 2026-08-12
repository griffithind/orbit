package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Lookups that answer a question before any request context exists:
// authenticating a token, redeeming an enrollment credential, resolving an
// agent by its overlay address.
//
// There is nothing privileged about them: they are ordinary queries, and the
// schema contains no SECURITY DEFINER functions at all.

// AuthenticateToken resolves an API token hash to its identity and scopes.
//
// tokenHash must be SHA-256 of the presented token. Callers must still check
// the scope the operation requires; this establishes identity only.
//
// Returns ErrNotFound for an unknown, revoked, or expired token without
// distinguishing between them, so the failure carries no information to a
// prober.
func (s *Store) AuthenticateToken(ctx context.Context, tokenHash []byte) (*Identity, error) {
	var id Identity
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, scopes, expires_at FROM orbit.api_token
		 WHERE token_hash = $1
		   AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > now())`,
		tokenHash,
	).Scan(&id.TokenID, &id.Display, &id.Scopes, &id.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapErr(err, "authenticate token")
	}
	// The name comes from the row that already had to be read for the scopes,
	// so a readable actor in the audit log costs nothing per request.
	id.Kind = ActorToken
	id.Subject = id.TokenID.String()
	return &id, nil
}

// TouchToken records that a token was used. Best effort and deliberately
// outside the request transaction: failing to update last_used_at must not fail
// the request it was authenticating.
func (s *Store) TouchToken(ctx context.Context, tokenID uuid.UUID) {
	_, _ = s.pool.Exec(ctx,
		`UPDATE orbit.api_token SET last_used_at = now() WHERE id = $1`, tokenID)
}

// RedeemEnrollmentCredential atomically consumes an enrollment secret.
//
// Exactly one caller can succeed for a given credential. A replay, or two
// racing agents given the same code, resolves to one winner and ErrNotFound for
// everyone else, because the conditional UPDATE is the arbiter rather than a
// check-then-write in application code. That single statement is the property
// the whole enrollment path rests on.
//
// secretHash must be the keyed hash of the presented credential.
func (s *Store) RedeemEnrollmentCredential(ctx context.Context, secretHash []byte, from netip.Addr) (*RedeemedCredential, error) {
	var (
		r       RedeemedCredential
		fromArg any = nil
		res     reservedCols
	)
	if from.IsValid() {
		fromArg = from
	}

	err := s.pool.QueryRow(ctx, `
		UPDATE orbit.enrollment_credential
		   SET used_at = now(), used_from = $2
		 WHERE secret_hash = $1
		   AND used_at IS NULL
		   AND expires_at > now()
		RETURNING id, network_id, membership_id, method, `+reservedColumns,
		secretHash, fromArg,
	).Scan(append([]any{&r.CredentialID, &r.NetworkID, &r.MembershipID, &r.Method},
		res.dest()...)...)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapErr(err, "redeem enrollment credential")
	}
	r.Reserved = res.reservation()
	return &r, nil
}

// RedeemCredential consumes a credential inside the caller's transaction.
//
// The transactional twin of RedeemEnrollmentCredential, and the difference in
// scope is the whole reason both exist rather than one.
//
// The pool-level version redeems BEFORE and OUTSIDE the work it authorizes,
// because that work is a certificate issuance: an attacker replaying a spent
// code must not be able to cost one, so the spend has to survive whatever
// happens next. This one is for the join path, where redemption authorizes the
// creation of two rows and nothing expensive. There the realistic failure is a
// name collision, and burning the operator's code on an attempt that created
// nothing would be the wrong outcome.
//
// Neither is a safe substitute for the other. Using this one for enrollment
// would make a rejected enrollment refund the code.
func (t *Tx) RedeemCredential(ctx context.Context, secretHash []byte, from netip.Addr) (*RedeemedCredential, error) {
	var (
		r       RedeemedCredential
		fromArg any = nil
		res     reservedCols
	)
	if from.IsValid() {
		fromArg = from
	}

	err := t.tx.QueryRow(ctx, `
		UPDATE orbit.enrollment_credential
		   SET used_at = now(), used_from = $2
		 WHERE secret_hash = $1
		   AND used_at IS NULL
		   AND expires_at > now()
		RETURNING id, network_id, membership_id, method, `+reservedColumns,
		secretHash, fromArg,
	).Scan(append([]any{&r.CredentialID, &r.NetworkID, &r.MembershipID, &r.Method},
		res.dest()...)...)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapErr(err, "redeem credential")
	}
	r.Reserved = res.reservation()
	return &r, nil
}

// ResolveAgentHost maps an agent request's source overlay address to a host.
//
// networkID is required and is not inferable from the address: two networks may
// legitimately use the same prefix, so a single Orbit deployment runs a distinct
// nebula interface per network and must pass the one the request physically
// arrived on. Passing the wrong network resolves to the wrong host, so this
// argument must come from the listener, never from the request.
func (s *Store) ResolveAgentHost(ctx context.Context, networkID uuid.UUID, addr netip.Addr) (*AgentIdentity, error) {
	var id AgentIdentity
	// The device join is load-bearing, not decoration. Without it a blocked
	// device kept renewing its certificate every twelve hours, indefinitely —
	// while docs/credential-model.md promised that `orbit device block` "refuses
	// a device everywhere on the control plane immediately", which is the entire
	// argument for holding device keys in plaintext on disk.
	// See docs/adr/0023-blocking-a-device-stops-issuance.md.
	err := s.pool.QueryRow(ctx, `
		SELECT h.id, h.state, d.blocked_at IS NOT NULL
		  FROM orbit.membership_address a
		  JOIN orbit.membership h ON h.id = a.membership_id
		  JOIN orbit.device d ON d.id = h.device_id
		 WHERE a.network_id = $1 AND a.addr = $2`,
		networkID, addr,
	).Scan(&id.MembershipID, &id.State, &id.DeviceBlocked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapErr(err, "resolve agent host")
	}
	return &id, nil
}

// Ready is the readiness probe's query, and it reads an orbit table.
//
// count(*) over orbit.network rather than a bare SELECT 1: a fresh deployment
// legitimately has zero networks, so the ROW COUNT is not the signal — the
// signal is that the table exists and this role may read it.
//
// The probe used to run `func(context.Context, *store.Tx) error { return nil }`
// inside a READ ONLY transaction, which touches no orbit table at all. It
// returned 200 against a database with no orbit schema, against one whose
// grants had been revoked, against a read-only replica, and — the one that
// matters — against a Postgres that is out of disk, where reads succeed and
// every write fails, so there is no enrolment, no renewal, no BumpEpoch and
// therefore NO REVOCATION DELIVERY.
//
// The comment above it said "the only honest test of 'can I serve a request' is
// to do what serving a request does". This is that test.
// See docs/adr/0027-a-restore-is-a-rehearsed-procedure.md.
func (t *Tx) Ready(ctx context.Context) error {
	var n int
	if err := t.tx.QueryRow(ctx, `SELECT count(*) FROM orbit.network`).Scan(&n); err != nil {
		return mapErr(err, "readiness")
	}
	return nil
}

// ListNetworkIDs enumerates every network, for the maintenance sweep.
func (s *Store) ListNetworkIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM orbit.network ORDER BY id`)
	if err != nil {
		return nil, mapErr(err, "list network ids")
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, mapErr(err, "scan network id")
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Register satisfies mesh.Registrar, opening its own transaction.
//
// A method on Store rather than Tx because the heartbeat runs on its own timer
// with no surrounding request to borrow a transaction from.
func (s *Store) Register(ctx context.Context, networkID, membershipID uuid.UUID, addr netip.Addr, agentPort int) error {
	return s.Tx(ctx, func(ctx context.Context, tx *Tx) error {
		return tx.RegisterControlPlane(ctx, networkID, membershipID, addr, agentPort)
	})
}

// PruneExpiredCredentialsAll removes unredeemed credentials past their expiry
// across every network. Redeemed ones are retained: they are evidence.
func (t *Tx) PruneExpiredCredentialsAll(ctx context.Context, before time.Time) (int64, error) {
	tag, err := t.tx.Exec(ctx, `
		DELETE FROM orbit.enrollment_credential
		 WHERE used_at IS NULL AND expires_at < $1`, before)
	if err != nil {
		return 0, mapErr(err, "prune credentials")
	}
	return tag.RowsAffected(), nil
}
