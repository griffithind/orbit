package store

import (
	"context"

	"github.com/google/uuid"
)

// NetworkStats is one network's operational state, for the metrics endpoint.
//
// Everything here answers a question an operator asks during an incident, and
// nothing here is per-host: a gauge labelled by host id would grow a time
// series per machine and make Prometheus the most expensive part of a
// deployment that otherwise runs on one small VM. The per-host detail lives in
// /v1/networks/{id}/convergence, which is queried when someone is looking.
type NetworkStats struct {
	NetworkID      uuid.UUID
	Name           string
	ConfigEpoch    int64
	BlocklistEpoch int64

	MembershipsTotal int
	ConfigApplied    int
	BlockApplied     int

	// LagSeconds is how long the most stale un-converged host has gone without
	// reporting. Zero when everything has converged.
	//
	// This is the number the revocation SLO is actually about. It is a gauge
	// and not the histogram docs/revocation.md originally proposed, because a
	// histogram measures the distribution of completed events and convergence
	// lag is a level: at any instant a host either is or is not behind, and
	// what matters is how long the worst one has been.
	LagSeconds float64

	// CertsExpiringSoon counts active certificates with under a quarter of
	// their lifetime left. Renewal targets roughly half, so a nonzero value
	// means renewal is failing for someone, well before anything drops off.
	CertsExpiringSoon int

	// MinCertRemainingSeconds is the closest active certificate to expiry.
	// Negative if one has already expired and nothing has cleaned it up.
	MinCertRemainingSeconds float64

	// BlocklistSize is the number of distributed fingerprints. It bounds the
	// size of every host's config, so unbounded growth is worth seeing.
	BlocklistSize int

	// DataPlaneDown counts hosts whose agent is healthy and whose nebula is
	// not. They poll, they report an applied epoch, and every other number here
	// counts them as converged — which is exactly why this one exists.
	DataPlaneDown int

	// ClockSkewed counts machines whose clock is further from the control
	// plane's than issuance assumes. See ADR-0031.
	ClockSkewed int

	// MinCARemainingSeconds is the active signer closest to expiry. When it
	// reaches zero, enrolment and renewal stop for the whole network at once.
	// Negative if one has already expired.
	MinCARemainingSeconds float64
}

// FleetStats returns one row per network in a single round trip.
//
// One query rather than a loop over networks: this runs on every Prometheus
// scrape, and a per-network query would make scrape cost scale with the number
// of networks for data that is a single aggregate.
func (t *Tx) FleetStats(ctx context.Context) ([]NetworkStats, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT n.id, n.name, n.config_epoch, n.blocklist_epoch,
		       -- Only enrolled and active hosts count. A host in 'created' has
		       -- never had a certificate and can never converge, so including
		       -- it would peg the ratio below 100% forever.
		       (SELECT count(*) FROM orbit.membership h
		         WHERE h.network_id = n.id AND h.state IN ('enrolled', 'active')),
		       (SELECT count(*) FROM orbit.membership h
		         WHERE h.network_id = n.id AND h.state IN ('enrolled', 'active')
		           AND h.applied_config_epoch >= n.config_epoch),
		       (SELECT count(*) FROM orbit.membership h
		         WHERE h.network_id = n.id AND h.state IN ('enrolled', 'active')
		           AND h.applied_blocklist_epoch >= n.blocklist_epoch),
		       -- Liveness comes from the DEVICE: it is the machine that talks to
		       -- the control plane, and a machine on three networks is heard
		       -- from once. A device row is created at the same moment as its
		       -- first membership and stamps last_seen_at then, so this is
		       -- never null — the old COALESCE to created_at, which existed
		       -- because a host could be pre-created and never report, has
		       -- nothing left to guard.
		       COALESCE((SELECT max(extract(epoch FROM now() - d.last_seen_at))
		                   FROM orbit.membership h
		                   JOIN orbit.device d ON d.id = h.device_id
		                  WHERE h.network_id = n.id AND h.state IN ('enrolled', 'active')
		                    AND (h.applied_config_epoch < n.config_epoch
		                      OR h.applied_blocklist_epoch < n.blocklist_epoch)), 0),
		       (SELECT count(*) FROM orbit.certificate c
		          JOIN orbit.membership h ON h.id = c.membership_id
		         WHERE h.network_id = n.id AND c.state = 'active'
		           AND (c.not_after - now()) < (c.not_after - c.not_before) * 0.25),
		       COALESCE((SELECT min(extract(epoch FROM c.not_after - now()))
		                   FROM orbit.certificate c
		                   JOIN orbit.membership h ON h.id = c.membership_id
		                  WHERE h.network_id = n.id AND c.state = 'active'), 0),
		       (SELECT count(*) FROM orbit.blocklist_entry b
		         WHERE b.network_id = n.id AND b.not_after > now()),
		       -- Converged on paper and carrying nothing. Counted rather than
		       -- only logged: every other gauge here calls such a host healthy.
		       (SELECT count(*) FROM orbit.membership h
		         WHERE h.network_id = n.id AND h.data_plane_down
		           AND h.state IN ('enrolled', 'active')),
		       -- Machines whose clock disagrees with the control plane by more
		       -- than issuance assumes. Nebula validates certificate windows
		       -- against raw wall time with zero leeway, so such a host rejects
		       -- its own brand-new certificate and the failure names something
		       -- else entirely. Counted rather than reported per host: a gauge
		       -- with a label per machine is how a metrics endpoint becomes the
		       -- thing that falls over (ADR-0008).
		       (SELECT count(DISTINCT d.id)
		          FROM orbit.device d
		          JOIN orbit.membership h ON h.device_id = d.id
		         WHERE h.network_id = n.id AND h.state IN ('enrolled', 'active')
		           AND abs(coalesce(d.clock_skew_seconds, 0)) > 60),
		       -- The signer's own expiry. An expired active CA is a fleet-wide
		       -- enrolment and renewal outage, and had only a log line.
		       COALESCE((SELECT min(extract(epoch FROM ca.not_after - now()))
		                   FROM orbit.ca ca
		                  WHERE ca.network_id = n.id AND ca.state = 'active'), 0)
		  FROM orbit.network n
		 ORDER BY n.name`)
	if err != nil {
		return nil, mapErr(err, "fleet stats")
	}
	defer rows.Close()

	var out []NetworkStats
	for rows.Next() {
		var s NetworkStats
		if err := rows.Scan(&s.NetworkID, &s.Name, &s.ConfigEpoch, &s.BlocklistEpoch,
			&s.MembershipsTotal, &s.ConfigApplied, &s.BlockApplied,
			&s.LagSeconds, &s.CertsExpiringSoon, &s.MinCertRemainingSeconds,
			&s.BlocklistSize, &s.DataPlaneDown, &s.ClockSkewed, &s.MinCARemainingSeconds); err != nil {
			return nil, mapErr(err, "scan fleet stats")
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
