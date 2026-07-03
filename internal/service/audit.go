package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/rev3rsedev/cerberusauth/internal/store"
)

// Audit action names. Stable strings: the dashboard and anything shipping
// the log elsewhere filter on them, so changing one is a breaking change.
const (
	AuditAppCreate        = "app.create"
	AuditAppRotateKey     = "app.rotate_key"
	AuditLicenseIssue     = "license.issue"
	AuditLicenseBan       = "license.ban"
	AuditLicenseUnban     = "license.unban"
	AuditLicenseResetHWID = "license.reset_hwid"
	AuditAdminCreate      = "admin.create"
	AuditLogin            = "admin.login"
	AuditLoginFailed      = "admin.login_failed"
	AuditLogout           = "admin.logout"
)

type actorKeyType struct{}

var actorKey actorKeyType

// WithActor attaches the authenticated admin's ID to the context so audit
// entries written downstream carry it. The HTTP layer sets it in
// requireAdmin; service code only ever reads it.
func WithActor(ctx context.Context, adminID uuid.UUID) context.Context {
	return context.WithValue(ctx, actorKey, adminID)
}

func actorFrom(ctx context.Context) *uuid.UUID {
	if id, ok := ctx.Value(actorKey).(uuid.UUID); ok {
		return &id
	}
	return nil
}

// audit appends one entry to the trail, attributed to the context actor.
// Failures propagate to the caller: the mutation has already happened at
// that point, but surfacing the error makes the gap in the trail loud
// instead of silent.
func (s *Service) audit(ctx context.Context, action, targetID, detail string) error {
	return s.auditAs(ctx, actorFrom(ctx), action, targetID, detail)
}

// auditAs is audit with an explicit actor, for the paths where the actor
// is not on the context yet (login) or genuinely absent (failed login,
// bootstrap).
func (s *Service) auditAs(ctx context.Context, adminID *uuid.UUID, action, targetID, detail string) error {
	return s.store.AppendAudit(ctx, store.AuditEntry{
		At:       s.now().UTC(),
		AdminID:  adminID,
		Action:   action,
		TargetID: targetID,
		Detail:   detail,
	})
}

// ListAudit returns the trail newest-first.
func (s *Service) ListAudit(ctx context.Context, limit, offset int) ([]store.AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	return s.store.ListAudit(ctx, limit, offset)
}

// Stats returns the aggregate counts shown on the dashboard overview.
func (s *Service) Stats(ctx context.Context) (store.Stats, error) {
	return s.store.Stats(ctx, s.now())
}
