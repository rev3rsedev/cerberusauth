// Package store defines the domain types and the persistence interface.
// It contains no SQL; internal/store/postgres implements it for production
// and internal/store/storetest provides an in-memory fake for tests.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned by all Get* methods when no row matches.
var ErrNotFound = errors.New("store: not found")

// Application is a tenant: one product/app with its own signing keypair.
type Application struct {
	ID            uuid.UUID
	Name          string
	PublicKey     []byte // raw Ed25519 public key (32 bytes)
	PrivateKeyEnc []byte // Ed25519 private key, AES-256-GCM under the master key
	CreatedAt     time.Time
}

type LicenseStatus string

const (
	// StatusIssued: created, never redeemed. Validation answers not_redeemed.
	StatusIssued LicenseStatus = "issued"
	// StatusActive: redeemed; validates until expiry/ban.
	StatusActive LicenseStatus = "active"
	// StatusBanned: refused regardless of expiry. Unban restores the prior state.
	StatusBanned LicenseStatus = "banned"
)

type License struct {
	ID        uuid.UUID
	AppID     uuid.UUID
	KeyHash   []byte // SHA-256 of the canonical key; plaintext is never stored
	KeyHint   string // last key group, for admin listings
	Tier      string
	Status    LicenseStatus
	BanReason *string

	// DurationSeconds: relative expiry; the clock starts at redemption.
	DurationSeconds *int64
	// ExpiresAt: absolute expiry. Set at issuance (fixed date) or computed
	// at redemption from DurationSeconds. Nil = perpetual.
	ExpiresAt *time.Time

	HWIDHash   []byte // SHA-256 of the bound device id; nil = unbound
	RedeemedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type AdminUser struct {
	ID           uuid.UUID
	EmailHash    []byte // HMAC-SHA-256(master key, email); plaintext never stored
	PasswordHash string // argon2id, PHC format
	CreatedAt    time.Time
}

type AdminToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash []byte // SHA-256 of the bearer token
	ExpiresAt time.Time
	CreatedAt time.Time
}

// AuditEntry is one recorded admin action. The log is append-only: there
// is no update or delete path anywhere, by design.
type AuditEntry struct {
	ID int64
	At time.Time
	// AdminID is the acting admin; nil for events without an authenticated
	// actor (failed logins, bootstrap provisioning).
	AdminID *uuid.UUID
	// Action is a stable dotted name like "license.ban"; see the service
	// Audit* constants.
	Action string
	// TargetID is the acted-on entity's UUID as text; empty when the action
	// has no single target.
	TargetID string
	// Detail is short human-readable context. Never secrets, never
	// plaintext license keys, never emails.
	Detail string
}

// Store is the persistence boundary. Mutations that enforce a state
// transition (RedeemLicense, BindHWID) return false instead of writing when
// the precondition no longer holds, so concurrent requests cannot both win.
type Store interface {
	CreateApplication(ctx context.Context, app Application) error
	GetApplication(ctx context.Context, id uuid.UUID) (Application, error)
	ListApplications(ctx context.Context) ([]Application, error)

	CreateLicenses(ctx context.Context, lics []License) error
	GetLicenseByID(ctx context.Context, id uuid.UUID) (License, error)
	GetLicenseByKeyHash(ctx context.Context, appID uuid.UUID, keyHash []byte) (License, error)
	ListLicenses(ctx context.Context, appID uuid.UUID, limit, offset int) ([]License, error)

	// RedeemLicense atomically moves an issued license to active, binding
	// the HWID and setting expiry. Returns false if the license was not in
	// status issued (lost race, already redeemed, banned...).
	RedeemLicense(ctx context.Context, id uuid.UUID, hwidHash []byte, redeemedAt time.Time, expiresAt *time.Time) (bool, error)

	// BindHWID sets the device binding only if none exists yet.
	BindHWID(ctx context.Context, id uuid.UUID, hwidHash []byte) (bool, error)

	ResetHWID(ctx context.Context, id uuid.UUID) error
	SetLicenseStatus(ctx context.Context, id uuid.UUID, status LicenseStatus, banReason *string) error

	CreateAdminUser(ctx context.Context, u AdminUser) error
	GetAdminUserByEmailHash(ctx context.Context, emailHash []byte) (AdminUser, error)
	CreateAdminToken(ctx context.Context, t AdminToken) error
	GetAdminTokenByHash(ctx context.Context, tokenHash []byte) (AdminToken, error)

	// DeleteAdminToken revokes a token by its hash. Deleting a token that
	// does not exist is not an error; revocation is idempotent.
	DeleteAdminToken(ctx context.Context, tokenHash []byte) error

	// AppendAudit records one admin action. ID and At are assigned by the
	// caller-facing service, not the store.
	AppendAudit(ctx context.Context, e AuditEntry) error
	// ListAudit returns entries newest-first.
	ListAudit(ctx context.Context, limit, offset int) ([]AuditEntry, error)
}
