package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BlockHost revokes every active certificate a host holds, adds each
// fingerprint to the network blocklist, suspends the host, advances the
// blocklist epoch, and queues the notification. All in one transaction.
//
// The atomicity is the point. A blocklist entry that is visible to agents
// before the epoch advances would not be fetched; an epoch that advances before
// the entry is written would cause agents to fetch a blocklist that does not
// yet contain it and then consider themselves converged. Splitting this across
// transactions produces a host that everyone believes is blocked and that is
// still trusted.
//
// Returns the new blocklist epoch.
func (t *Tx) BlockHost(ctx context.Context, membershipID uuid.UUID, reason string) (int64, error) {
	host, err := t.GetHost(ctx, membershipID)
	if err != nil {
		return 0, err
	}

	epoch, err := t.nextBlocklistEpoch(ctx, host.NetworkID)
	if err != nil {
		return 0, err
	}

	// Move every active certificate to revoked and capture what we revoked, so
	// the blocklist entries carry the correct expiry for later pruning.
	rows, err := t.tx.Query(ctx, `
		UPDATE orbit.certificate
		   SET state = 'revoked'
		 WHERE membership_id = $1 AND state IN ('active', 'pending')
		RETURNING fingerprint, not_after`, membershipID)
	if err != nil {
		return 0, mapErr(err, "revoke certificates")
	}

	type revoked struct {
		fingerprint string
		notAfter    time.Time
	}
	var list []revoked
	for rows.Next() {
		var r revoked
		if err := rows.Scan(&r.fingerprint, &r.notAfter); err != nil {
			rows.Close()
			return 0, mapErr(err, "scan revoked certificate")
		}
		list = append(list, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, mapErr(err, "revoke certificates")
	}

	for _, r := range list {
		// ON CONFLICT DO NOTHING: re-blocking an already-blocked fingerprint is
		// idempotent rather than an error, so a retried admin request is safe.
		if _, err := t.tx.Exec(ctx, `
			INSERT INTO orbit.blocklist_entry
				(network_id, fingerprint, reason, epoch, not_after)
		VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (network_id, fingerprint) DO NOTHING`,
			host.NetworkID, r.fingerprint, reason, epoch, r.notAfter); err != nil {
			return 0, mapErr(err, "insert blocklist entry")
		}
	}

	if err := t.SetHostState(ctx, membershipID, MembershipSuspended); err != nil {
		return 0, err
	}
	return epoch, nil
}

// DeleteHost removes a host permanently, revoking it on the way out.
//
// The order is the entire point. Deleting the row first would destroy the
// certificate records that name the fingerprints to revoke, leaving a
// decommissioned machine holding a certificate that stays valid until it
// expires — a delete that is weaker than a block, which is the opposite of what
// the word leads anyone to expect. So this blocks first, then deletes.
//
// The blocklist entries survive the host: blocklist_entry references
// network_id, not membership_id, so nothing cascades them away. They are pruned
// normally once the revoked certificates pass their expiry, at which point
// nebula rejects those certificates on age alone and the fingerprints stop
// being worth distributing.
//
// One consequence worth stating: a deleted host cannot be unblocked, because
// UnblockHost finds entries by joining through certificates that no longer
// exist. Deletion is not reversible, and it releases the name for reuse by a
// new host with a new identity.
//
// Returns the new blocklist epoch.
func (t *Tx) DeleteHost(ctx context.Context, membershipID uuid.UUID, reason string) (int64, error) {
	host, err := t.GetHost(ctx, membershipID)
	if err != nil {
		return 0, err
	}

	epoch, err := t.BlockHost(ctx, membershipID, reason)
	if err != nil {
		return 0, err
	}

	// Cascades to membership_address, certificate, and enrollment_credential.
	tag, err := t.tx.Exec(ctx, `DELETE FROM orbit.membership WHERE id = $1`, membershipID)
	if err != nil {
		return 0, mapErr(err, "delete host")
	}
	if tag.RowsAffected() == 0 {
		return 0, fmt.Errorf("delete host: %w", ErrNotFound)
	}

	// A deleted host changes what every other host renders — most visibly a
	// lighthouse leaving static_host_map. Without this the fleet keeps dialling
	// a machine that is gone.
	if _, err := t.BumpEpoch(ctx, host.NetworkID, EpochConfig); err != nil {
		return 0, err
	}
	return epoch, nil
}

// nextBlocklistEpoch advances the counter and notifies, returning the new
// value so callers can stamp entries with the epoch that introduced them.
func (t *Tx) nextBlocklistEpoch(ctx context.Context, networkID uuid.UUID) (int64, error) {
	return t.BumpEpoch(ctx, networkID, EpochBlocklist)
}

// UnblockHost lifts a block and removes the host's blocklist entries.
//
// Note this does not un-revoke the certificates: those are gone for good and
// the host must enroll or renew to get a new one. Removing the entries only
// stops distributing fingerprints that are no longer meaningful.
//
// The state it returns to is DERIVED from what the host actually has, not set to
// a constant. BlockHost suspends a host from whatever state it held — pending,
// created, enrolled or active — and revokes any certificate it had, so returning
// every host to 'active' promoted hosts that had never enrolled and, worse,
// hosts that had never been authorized and therefore hold no address.
//
// That was not merely untidy. Convergence and FleetStats both count
// state IN ('enrolled','active'), so such a host sits in the denominator and can
// never report an epoch — pinning convergence below 100% forever, and convergence
// is the gate on CA rotation. One unblock of a never-enrolled host blocked CA
// rotation for that network indefinitely.
func (t *Tx) UnblockHost(ctx context.Context, membershipID uuid.UUID) (int64, error) {
	host, err := t.GetHost(ctx, membershipID)
	if err != nil {
		return 0, err
	}

	if _, err := t.tx.Exec(ctx, `
		DELETE FROM orbit.blocklist_entry
		 WHERE network_id = $1
		   AND fingerprint IN (
		       SELECT fingerprint FROM orbit.certificate WHERE membership_id = $2)`,
		host.NetworkID, membershipID); err != nil {
		return 0, mapErr(err, "remove blocklist entries")
	}

	// Evidence, in descending order of what it proves: a live certificate means
	// enrolled; an allocated address means authorized but not yet enrolled;
	// neither means it is still waiting to be authorized.
	if _, err := t.tx.Exec(ctx, `
		UPDATE orbit.membership SET state = CASE
		  WHEN EXISTS (SELECT 1 FROM orbit.certificate
		                WHERE membership_id = $1 AND state = 'active') THEN 'enrolled'
		  WHEN EXISTS (SELECT 1 FROM orbit.membership_address
		                WHERE membership_id = $1)                      THEN 'created'
		  ELSE 'pending' END
		 WHERE id = $1`, membershipID); err != nil {
		return 0, mapErr(err, "restore membership state")
	}
	return t.nextBlocklistEpoch(ctx, host.NetworkID)
}

// LiveBlocklist returns the fingerprints that belong in distributed config:
// entries whose revoked certificate has not yet expired.
//
// Expired entries are omitted deliberately. Nebula rejects an expired
// certificate before it consults the blocklist (cert/ca_pool.go verify), so
// carrying the fingerprint costs bytes in every host's config and buys nothing.
// With short certificate lifetimes this keeps the blocklist proportional to
// recent revocations rather than to all history. See docs/revocation.md 4.1.
func (t *Tx) LiveBlocklist(ctx context.Context, networkID uuid.UUID, now time.Time) ([]string, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT fingerprint FROM orbit.blocklist_entry
		 WHERE network_id = $1 AND not_after > $2
		 ORDER BY fingerprint`, networkID, now)
	if err != nil {
		return nil, mapErr(err, "live blocklist")
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, mapErr(err, "scan fingerprint")
		}
		out = append(out, fp)
	}
	return out, rows.Err()
}

// PruneBlocklist deletes entries whose certificates expired before cutoff.
// Full history remains in the audit log.
func (t *Tx) PruneBlocklist(ctx context.Context, networkID uuid.UUID, cutoff time.Time) (int64, error) {
	tag, err := t.tx.Exec(ctx, `
		DELETE FROM orbit.blocklist_entry WHERE network_id = $1 AND not_after < $2`,
		networkID, cutoff)
	if err != nil {
		return 0, mapErr(err, "prune blocklist")
	}
	return tag.RowsAffected(), nil
}

//------------------------------------------------------------------------------
// Convergence
//------------------------------------------------------------------------------

// Convergence reports how much of a network has applied the current epochs.
//
// This gates CA rotation (docs/design.md 6 step 3) and is the measurement
// behind the revocation SLO. It counts hosts that reported applying an epoch at
// least as high as the current one; a host that fetched but failed to apply is
// correctly counted as lagging.
func (t *Tx) Convergence(ctx context.Context, networkID uuid.UUID, laggingLimit int) (*Convergence, error) {
	var c Convergence
	err := t.tx.QueryRow(ctx, `
		SELECT n.config_epoch, n.blocklist_epoch,
		       count(h.id),
		       count(h.id) FILTER (WHERE h.applied_config_epoch    >= n.config_epoch),
		       count(h.id) FILTER (WHERE h.applied_blocklist_epoch >= n.blocklist_epoch)
		  FROM orbit.network n
		  LEFT JOIN orbit.membership h
		         ON h.network_id = n.id AND h.state IN ('enrolled', 'active')
		 WHERE n.id = $1
		 GROUP BY n.config_epoch, n.blocklist_epoch`, networkID,
	).Scan(&c.ConfigEpoch, &c.BlocklistEpoch, &c.MembershipsTotal, &c.ConfigApplied, &c.BlockApplied)
	if err != nil {
		return nil, mapErr(err, "convergence")
	}

	rows, err := t.tx.Query(ctx, `
		SELECT h.id, h.name, h.applied_config_epoch, h.applied_blocklist_epoch, d.last_seen_at
		  FROM orbit.membership h
		  JOIN orbit.network n ON n.id = h.network_id
		  JOIN orbit.device d ON d.id = h.device_id
		 WHERE h.network_id = $1
		   AND h.state IN ('enrolled', 'active')
		   AND (h.applied_config_epoch < n.config_epoch
		     OR h.applied_blocklist_epoch < n.blocklist_epoch)
		 ORDER BY d.last_seen_at NULLS FIRST
		 LIMIT $2`, networkID, laggingLimit)
	if err != nil {
		return nil, mapErr(err, "lagging hosts")
	}
	defer rows.Close()

	for rows.Next() {
		var l LaggingHost
		if err := rows.Scan(&l.MembershipID, &l.Name, &l.AppliedConfigEpoch,
			&l.AppliedBlocklistEpoch, &l.LastSeenAt); err != nil {
			return nil, mapErr(err, "scan lagging host")
		}
		c.Lagging = append(c.Lagging, l)
	}
	return &c, rows.Err()
}
