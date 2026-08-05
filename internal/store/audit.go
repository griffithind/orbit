package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Audit returns an append-only record of what happened in this deployment.
//
// The application role holds no UPDATE or DELETE grant on orbit.audit_log (see
// migrations/0002_rls.sql). That is deliberate: an audit trail the application
// can rewrite is not an audit trail. Corrections are new entries.

// AppendAudit writes an audit record inside the caller's transaction.
//
// It takes a *Tx rather than a *Store specifically so that the audit record and
// the change it describes commit or roll back together. A mutation that
// succeeds without its audit entry, or an entry describing a mutation that
// rolled back, are both worse than a failed request.
func (t *Tx) AppendAudit(ctx context.Context, e AuditEntry) error {
	if len(e.Meta) == 0 {
		e.Meta = []byte(`{}`)
	}
	if e.ActorType == "" {
		e.ActorType = ActorSystem
	}

	var ip any
	if e.SourceIP != nil && e.SourceIP.IsValid() {
		ip = *e.SourceIP
	}

	_, err := t.tx.Exec(ctx, `
		INSERT INTO orbit.audit_log
			(actor_type, actor_id, actor_display, action, target_type, target_id, meta, source_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.ActorType, nullIfEmpty(e.ActorID), nullIfEmpty(e.ActorDisplay), e.Action,
		nullIfEmpty(e.TargetType), nullIfEmpty(e.TargetID), e.Meta, ip)
	return mapErr(err, "append audit")
}

// AuditFilter narrows a listing. Zero values mean "no constraint".
type AuditFilter struct {
	Action     string
	TargetType string
	TargetID   string
	Since      time.Time
	Until      time.Time
	Limit      int
}

// AuditRecord is a stored entry, with the fields the database assigns.
type AuditRecord struct {
	ID int64
	AuditEntry
	At time.Time
}

// ListAudit returns entries newest first.
func (t *Tx) ListAudit(ctx context.Context, f AuditFilter) ([]AuditRecord, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}

	rows, err := t.tx.Query(ctx, `
		SELECT id, actor_type, coalesce(actor_id, ''), coalesce(actor_display, ''), action,
		       coalesce(target_type, ''), coalesce(target_id, ''), meta, source_ip, at
		  FROM orbit.audit_log
		 WHERE ($1 = '' OR action = $1)
		   AND ($2 = '' OR target_type = $2)
		   AND ($3 = '' OR target_id = $3)
		   AND ($4::timestamptz IS NULL OR at >= $4)
		   AND ($5::timestamptz IS NULL OR at <= $5)
		 ORDER BY at DESC, id DESC
		 LIMIT $6`,
		f.Action, f.TargetType, f.TargetID,
		nullIfZeroTime(f.Since), nullIfZeroTime(f.Until), f.Limit)
	if err != nil {
		return nil, mapErr(err, "list audit")
	}
	defer rows.Close()

	var out []AuditRecord
	for rows.Next() {
		var r AuditRecord
		if err := rows.Scan(&r.ID, &r.ActorType, &r.ActorID, &r.ActorDisplay, &r.Action,
			&r.TargetType, &r.TargetID, &r.Meta, &r.SourceIP, &r.At); err != nil {
			return nil, mapErr(err, "scan audit")
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullIfZeroTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// Audit action names. Keeping them as constants makes the set greppable and
// keeps a typo from silently creating a new action nobody queries for.
const (
	ActionNetworkCreated = "network.created"
	ActionCACreated      = "ca.created"
	ActionCAActivated    = "ca.activated"
	// Distinct from ca.activated: a promotion that knowingly cut off hosts is
	// a different event, and an auditor should not have to infer it.
	ActionCAForceActivated    = "ca.force_activated"
	ActionCARetired           = "ca.retired"
	ActionMembershipCreated   = "membership.created"
	ActionRouteAdded          = "route.added"
	ActionRouteRemoved        = "route.removed"
	ActionMembershipBlocked   = "membership.blocked"
	ActionMembershipUnblocked = "membership.unblocked"
	ActionMembershipDeleted   = "membership.deleted"
	ActionCertificateIssued   = "certificate.issued"
	ActionEnrollCodeCreated   = "enrollment_code.created"
	ActionEnrolled            = "membership.enrolled"
	ActionEnrollFailed        = "membership.enroll_failed"

	// The join path. A device asks (device.join), an operator says yes
	// (membership.authorized), the device collects what that entitles it to
	// (membership.claimed).
	//
	// Three actions rather than reusing membership.created and membership.enrolled, because
	// the questions an auditor asks about a join are different ones: WHO
	// authorized this machine, and how long did it sit in the queue. Folding
	// them into the enrollment actions would make both unanswerable.
	ActionDeviceJoin           = "device.join"
	ActionMembershipAuthorized = "membership.authorized"
	ActionMembershipClaimed    = "membership.claimed"
	ActionDeviceUpdated        = "device.updated"
	ActionDeviceBlocked        = "device.blocked"
	ActionDeviceUnblocked      = "device.unblocked"
	ActionMembershipUpdated    = "membership.updated"
	ActionRoleCreated          = "role.created"
	ActionTokenCreated         = "token.created"
	ActionTokenRevoked         = "token.revoked"
)

// AuditTarget is a small helper for the common "target is a UUID" case.
func AuditTarget(kind string, id uuid.UUID) (string, string) {
	return kind, id.String()
}
