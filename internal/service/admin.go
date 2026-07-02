package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/rev3rsedev/cerberusauth/internal/auth"
	"github.com/rev3rsedev/cerberusauth/internal/license"
	"github.com/rev3rsedev/cerberusauth/internal/signing"
	"github.com/rev3rsedev/cerberusauth/internal/store"
)

// CreateApplication provisions a tenant: generates its Ed25519 keypair and
// stores the private key encrypted under the derived encryption key.
func (s *Service) CreateApplication(ctx context.Context, name string) (store.Application, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return store.Application{}, fmt.Errorf("%w: name must be 1-200 characters", ErrInvalidInput)
	}
	kp, err := signing.Generate()
	if err != nil {
		return store.Application{}, err
	}
	enc, err := signing.EncryptPrivateKey(s.encKey, kp.Private)
	if err != nil {
		return store.Application{}, err
	}
	app := store.Application{
		ID:            uuid.New(),
		Name:          name,
		PublicKey:     kp.Public,
		PrivateKeyEnc: enc,
		CreatedAt:     s.now().UTC(),
	}
	if err := s.store.CreateApplication(ctx, app); err != nil {
		return store.Application{}, err
	}
	if err := s.audit(ctx, AuditAppCreate, app.ID.String(), name); err != nil {
		return store.Application{}, err
	}
	return app, nil
}

func (s *Service) GetApplication(ctx context.Context, id uuid.UUID) (store.Application, error) {
	app, err := s.store.GetApplication(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Application{}, ErrAppNotFound
	}
	return app, err
}

func (s *Service) ListApplications(ctx context.Context) ([]store.Application, error) {
	return s.store.ListApplications(ctx)
}

// IssuedLicense pairs a stored license with its plaintext key, the only
// moment the plaintext exists server-side. It is returned once and never
// persisted.
type IssuedLicense struct {
	License store.License
	Key     string
}

// IssueLicenses batch-creates licenses for an app. Expiry is either
// relative (durationSeconds, clock starts at redemption) or absolute
// (expiresAt), not both.
func (s *Service) IssueLicenses(ctx context.Context, appID uuid.UUID, count int, tier string, durationSeconds *int64, expiresAt *time.Time) ([]IssuedLicense, error) {
	if _, err := s.GetApplication(ctx, appID); err != nil {
		return nil, err
	}
	if count < 1 || count > 1000 {
		return nil, fmt.Errorf("%w: count must be 1-1000", ErrInvalidInput)
	}
	tier = strings.TrimSpace(tier)
	if tier == "" {
		tier = "default"
	}
	if len(tier) > 64 {
		return nil, fmt.Errorf("%w: tier must be at most 64 characters", ErrInvalidInput)
	}
	if durationSeconds != nil && expiresAt != nil {
		return nil, fmt.Errorf("%w: set duration_seconds or expires_at, not both", ErrInvalidInput)
	}
	if durationSeconds != nil && *durationSeconds <= 0 {
		return nil, fmt.Errorf("%w: duration_seconds must be positive", ErrInvalidInput)
	}
	if expiresAt != nil && !expiresAt.After(s.now()) {
		return nil, fmt.Errorf("%w: expires_at must be in the future", ErrInvalidInput)
	}

	now := s.now().UTC()
	issued := make([]IssuedLicense, 0, count)
	rows := make([]store.License, 0, count)
	for i := 0; i < count; i++ {
		key, err := license.Generate()
		if err != nil {
			return nil, err
		}
		canonical, err := license.Canonicalize(key)
		if err != nil {
			return nil, err // unreachable for generated keys
		}
		lic := store.License{
			ID:              uuid.New(),
			AppID:           appID,
			KeyHash:         license.Hash(canonical),
			KeyHint:         license.Hint(key),
			Tier:            tier,
			Status:          store.StatusIssued,
			DurationSeconds: durationSeconds,
			ExpiresAt:       expiresAt,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		rows = append(rows, lic)
		issued = append(issued, IssuedLicense{License: lic, Key: key})
	}
	if err := s.store.CreateLicenses(ctx, rows); err != nil {
		return nil, err
	}
	if err := s.audit(ctx, AuditLicenseIssue, appID.String(), fmt.Sprintf("%d x %s", count, tier)); err != nil {
		return nil, err
	}
	return issued, nil
}

func (s *Service) GetLicense(ctx context.Context, id uuid.UUID) (store.License, error) {
	lic, err := s.store.GetLicenseByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.License{}, ErrLicenseNotFound
	}
	return lic, err
}

func (s *Service) ListLicenses(ctx context.Context, appID uuid.UUID, limit, offset int) ([]store.License, error) {
	if _, err := s.GetApplication(ctx, appID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return s.store.ListLicenses(ctx, appID, limit, offset)
}

// BanLicense refuses a license unconditionally until unbanned.
func (s *Service) BanLicense(ctx context.Context, id uuid.UUID, reason string) (store.License, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 500 {
		return store.License{}, fmt.Errorf("%w: reason must be at most 500 characters", ErrInvalidInput)
	}
	if _, err := s.GetLicense(ctx, id); err != nil {
		return store.License{}, err
	}
	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}
	if err := s.store.SetLicenseStatus(ctx, id, store.StatusBanned, reasonPtr); err != nil {
		return store.License{}, err
	}
	if err := s.audit(ctx, AuditLicenseBan, id.String(), reason); err != nil {
		return store.License{}, err
	}
	return s.GetLicense(ctx, id)
}

// UnbanLicense restores the state the ban interrupted: active if the
// license had been redeemed, issued otherwise. Unbanning a non-banned
// license is a no-op.
func (s *Service) UnbanLicense(ctx context.Context, id uuid.UUID) (store.License, error) {
	lic, err := s.GetLicense(ctx, id)
	if err != nil {
		return store.License{}, err
	}
	if lic.Status != store.StatusBanned {
		return lic, nil
	}
	target := store.StatusIssued
	if lic.RedeemedAt != nil {
		target = store.StatusActive
	}
	if err := s.store.SetLicenseStatus(ctx, id, target, nil); err != nil {
		return store.License{}, err
	}
	if err := s.audit(ctx, AuditLicenseUnban, id.String(), ""); err != nil {
		return store.License{}, err
	}
	return s.GetLicense(ctx, id)
}

// ResetHWID unbinds the device; the next validation binds whichever device
// shows up first.
func (s *Service) ResetHWID(ctx context.Context, id uuid.UUID) (store.License, error) {
	if _, err := s.GetLicense(ctx, id); err != nil {
		return store.License{}, err
	}
	if err := s.store.ResetHWID(ctx, id); err != nil {
		return store.License{}, err
	}
	if err := s.audit(ctx, AuditLicenseResetHWID, id.String(), ""); err != nil {
		return store.License{}, err
	}
	return s.GetLicense(ctx, id)
}

// CreateAdminUser registers a dashboard admin. The email is stored only as
// a peppered HMAC (lookup, not display); the password as argon2id.
func (s *Service) CreateAdminUser(ctx context.Context, email, password string) (store.AdminUser, error) {
	email = strings.TrimSpace(email)
	if len(email) < 3 || len(email) > 320 || !strings.Contains(email, "@") {
		return store.AdminUser{}, fmt.Errorf("%w: invalid email", ErrInvalidInput)
	}
	if len(password) < 10 || len(password) > 1024 {
		return store.AdminUser{}, fmt.Errorf("%w: password must be 10-1024 characters", ErrInvalidInput)
	}
	emailHash := auth.HashEmail(s.emailPepper, email)
	if _, err := s.store.GetAdminUserByEmailHash(ctx, emailHash); err == nil {
		return store.AdminUser{}, fmt.Errorf("%w: admin with this email", ErrAlreadyExists)
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.AdminUser{}, err
	}
	phc, err := auth.HashPassword(password)
	if err != nil {
		return store.AdminUser{}, err
	}
	u := store.AdminUser{
		ID:           uuid.New(),
		EmailHash:    emailHash,
		PasswordHash: phc,
		CreatedAt:    s.now().UTC(),
	}
	if err := s.store.CreateAdminUser(ctx, u); err != nil {
		return store.AdminUser{}, err
	}
	if err := s.audit(ctx, AuditAdminCreate, u.ID.String(), ""); err != nil {
		return store.AdminUser{}, err
	}
	return u, nil
}

// Login verifies admin credentials and mints a bearer token. Unknown emails
// burn a fake argon2 verification so timing does not reveal which addresses
// exist. Volume is capped by the per-IP limiter at the HTTP layer
// (internal/server/ratelimit.go).
func (s *Service) Login(ctx context.Context, email, password string) (string, time.Time, error) {
	u, err := s.store.GetAdminUserByEmailHash(ctx, auth.HashEmail(s.emailPepper, email))
	if errors.Is(err, store.ErrNotFound) {
		auth.FakeVerify(password)
		if aerr := s.auditAs(ctx, nil, AuditLoginFailed, "", ""); aerr != nil {
			return "", time.Time{}, aerr
		}
		return "", time.Time{}, ErrInvalidCredentials
	}
	if err != nil {
		return "", time.Time{}, err
	}
	if !auth.VerifyPassword(password, u.PasswordHash) {
		if aerr := s.auditAs(ctx, nil, AuditLoginFailed, "", ""); aerr != nil {
			return "", time.Time{}, aerr
		}
		return "", time.Time{}, ErrInvalidCredentials
	}
	token, err := auth.NewToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := s.now().Add(s.tokenTTL).UTC()
	t := store.AdminToken{
		ID:        uuid.New(),
		UserID:    u.ID,
		TokenHash: auth.HashToken(token),
		ExpiresAt: expiresAt,
		CreatedAt: s.now().UTC(),
	}
	if err := s.store.CreateAdminToken(ctx, t); err != nil {
		return "", time.Time{}, err
	}
	if err := s.auditAs(ctx, &u.ID, AuditLogin, "", ""); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// Logout revokes the presented bearer token. Revoking a token that is
// already gone succeeds: the caller's goal (token no longer works) is met
// either way.
func (s *Service) Logout(ctx context.Context, token string) error {
	if err := s.store.DeleteAdminToken(ctx, auth.HashToken(token)); err != nil {
		return err
	}
	return s.audit(ctx, AuditLogout, "", "")
}

// AuthenticateToken resolves a bearer token to the admin who owns it.
func (s *Service) AuthenticateToken(ctx context.Context, token string) (uuid.UUID, error) {
	t, err := s.store.GetAdminTokenByHash(ctx, auth.HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return uuid.Nil, ErrInvalidToken
	}
	if err != nil {
		return uuid.Nil, err
	}
	if s.now().After(t.ExpiresAt) {
		return uuid.Nil, ErrInvalidToken
	}
	return t.UserID, nil
}
