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
func (s *Store) AuthenticateToken(ctx context.Context, tokenHash []byte) (*TokenIdentity, error) {
	var id TokenIdentity
	err := s.pool.QueryRow(ctx, `
		SELECT id, scopes FROM orbit.api_token
		 WHERE token_hash = $1
		   AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > now())`,
		tokenHash,
	).Scan(&id.TokenID, &id.Scopes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapErr(err, "authenticate token")
	}
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
		RETURNING id, network_id, host_id, method`,
		secretHash, fromArg,
	).Scan(&r.CredentialID, &r.NetworkID, &r.HostID, &r.Method)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapErr(err, "redeem enrollment credential")
	}
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
	err := s.pool.QueryRow(ctx, `
		SELECT h.id, h.state
		  FROM orbit.host_address a
		  JOIN orbit.host h ON h.id = a.host_id
		 WHERE a.network_id = $1 AND a.addr = $2`,
		networkID, addr,
	).Scan(&id.HostID, &id.State)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapErr(err, "resolve agent host")
	}
	return &id, nil
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
func (s *Store) Register(ctx context.Context, networkID, hostID uuid.UUID, addr netip.Addr, agentPort int) error {
	return s.Tx(ctx, func(ctx context.Context, tx *Tx) error {
		return tx.RegisterControlPlane(ctx, networkID, hostID, addr, agentPort)
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
