// Package postgres implements store.Store on PostgreSQL via pgx.
//
// Deliberately plain: hand-written queries in one file, typed against the
// store.Store interface. If the query count outgrows this shape, moving to
// sqlc is mechanical (the interface stays).
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rev3rsedev/cerberusauth/internal/store"
)

type Store struct {
	pool *pgxpool.Pool
}

var _ store.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// --- applications ---

func (s *Store) CreateApplication(ctx context.Context, app store.Application, key store.AppKey) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if _, err := tx.Exec(ctx, `
		INSERT INTO applications (id, name, created_at)
		VALUES ($1, $2, $3)`,
		app.ID, app.Name, app.CreatedAt); err != nil {
		return fmt.Errorf("postgres: create application: %w", err)
	}
	if _, err := tx.Exec(ctx, insertAppKeySQL,
		key.ID, key.AppID, key.PublicKey, key.PrivateKeyEnc, key.Active, key.CreatedAt, key.RetiredAt); err != nil {
		return fmt.Errorf("postgres: create app key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit application: %w", err)
	}
	return nil
}

const appColumns = "id, name, created_at"

func scanApplication(row pgx.Row) (store.Application, error) {
	var app store.Application
	err := row.Scan(&app.ID, &app.Name, &app.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Application{}, store.ErrNotFound
	}
	if err != nil {
		return store.Application{}, fmt.Errorf("postgres: scan application: %w", err)
	}
	return app, nil
}

func (s *Store) GetApplication(ctx context.Context, id uuid.UUID) (store.Application, error) {
	row := s.pool.QueryRow(ctx, "SELECT "+appColumns+" FROM applications WHERE id = $1", id)
	return scanApplication(row)
}

func (s *Store) ListApplications(ctx context.Context) ([]store.Application, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+appColumns+" FROM applications ORDER BY created_at, id")
	if err != nil {
		return nil, fmt.Errorf("postgres: list applications: %w", err)
	}
	defer rows.Close()

	apps := []store.Application{}
	for rows.Next() {
		app, err := scanApplication(rows)
		if err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	return apps, rows.Err()
}

// --- app keys ---

const insertAppKeySQL = `
	INSERT INTO app_keys (id, app_id, public_key, private_key_enc, active, created_at, retired_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7)`

const appKeyColumns = "id, app_id, public_key, private_key_enc, active, created_at, retired_at"

func scanAppKey(row pgx.Row) (store.AppKey, error) {
	var k store.AppKey
	err := row.Scan(&k.ID, &k.AppID, &k.PublicKey, &k.PrivateKeyEnc, &k.Active, &k.CreatedAt, &k.RetiredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.AppKey{}, store.ErrNotFound
	}
	if err != nil {
		return store.AppKey{}, fmt.Errorf("postgres: scan app key: %w", err)
	}
	return k, nil
}

func (s *Store) GetActiveAppKey(ctx context.Context, appID uuid.UUID) (store.AppKey, error) {
	row := s.pool.QueryRow(ctx,
		"SELECT "+appKeyColumns+" FROM app_keys WHERE app_id = $1 AND active", appID)
	return scanAppKey(row)
}

func (s *Store) ListAppKeys(ctx context.Context, appID uuid.UUID) ([]store.AppKey, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+appKeyColumns+" FROM app_keys WHERE app_id = $1 ORDER BY created_at DESC, id", appID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list app keys: %w", err)
	}
	defer rows.Close()

	keys := []store.AppKey{}
	for rows.Next() {
		k, err := scanAppKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// RotateAppKey retires the active key and installs the new one in a single
// transaction, so there is no instant with zero or two active keys.
func (s *Store) RotateAppKey(ctx context.Context, appID uuid.UUID, newKey store.AppKey, retiredAt time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	tag, err := tx.Exec(ctx, `
		UPDATE app_keys SET active = false, retired_at = $2
		WHERE app_id = $1 AND active`,
		appID, retiredAt)
	if err != nil {
		return fmt.Errorf("postgres: retire app key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	if _, err := tx.Exec(ctx, insertAppKeySQL,
		newKey.ID, newKey.AppID, newKey.PublicKey, newKey.PrivateKeyEnc, newKey.Active, newKey.CreatedAt, newKey.RetiredAt); err != nil {
		return fmt.Errorf("postgres: insert rotated key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit rotation: %w", err)
	}
	return nil
}

func (s *Store) ListAllAppKeys(ctx context.Context) ([]store.AppKey, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+appKeyColumns+" FROM app_keys ORDER BY app_id, created_at")
	if err != nil {
		return nil, fmt.Errorf("postgres: list all app keys: %w", err)
	}
	defer rows.Close()

	keys := []store.AppKey{}
	for rows.Next() {
		k, err := scanAppKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *Store) UpdateAppKeyCiphertext(ctx context.Context, id uuid.UUID, privateKeyEnc []byte) error {
	tag, err := s.pool.Exec(ctx,
		"UPDATE app_keys SET private_key_enc = $2 WHERE id = $1", id, privateKeyEnc)
	if err != nil {
		return fmt.Errorf("postgres: update app key ciphertext: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// --- licenses ---

const licenseColumns = `id, app_id, key_hash, key_hint, tier, status, ban_reason,
	duration_seconds, expires_at, hwid_hash, redeemed_at, created_at, updated_at`

func scanLicense(row pgx.Row) (store.License, error) {
	var l store.License
	err := row.Scan(&l.ID, &l.AppID, &l.KeyHash, &l.KeyHint, &l.Tier, &l.Status, &l.BanReason,
		&l.DurationSeconds, &l.ExpiresAt, &l.HWIDHash, &l.RedeemedAt, &l.CreatedAt, &l.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.License{}, store.ErrNotFound
	}
	if err != nil {
		return store.License{}, fmt.Errorf("postgres: scan license: %w", err)
	}
	return l, nil
}

func (s *Store) CreateLicenses(ctx context.Context, lics []store.License) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	for _, l := range lics {
		if _, err := tx.Exec(ctx, `
			INSERT INTO licenses (id, app_id, key_hash, key_hint, tier, status, ban_reason,
				duration_seconds, expires_at, hwid_hash, redeemed_at, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			l.ID, l.AppID, l.KeyHash, l.KeyHint, l.Tier, l.Status, l.BanReason,
			l.DurationSeconds, l.ExpiresAt, l.HWIDHash, l.RedeemedAt, l.CreatedAt, l.UpdatedAt); err != nil {
			return fmt.Errorf("postgres: insert license: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit licenses: %w", err)
	}
	return nil
}

func (s *Store) GetLicenseByID(ctx context.Context, id uuid.UUID) (store.License, error) {
	row := s.pool.QueryRow(ctx, "SELECT "+licenseColumns+" FROM licenses WHERE id = $1", id)
	return scanLicense(row)
}

func (s *Store) GetLicenseByKeyHash(ctx context.Context, appID uuid.UUID, keyHash []byte) (store.License, error) {
	row := s.pool.QueryRow(ctx,
		"SELECT "+licenseColumns+" FROM licenses WHERE app_id = $1 AND key_hash = $2", appID, keyHash)
	return scanLicense(row)
}

func (s *Store) ListLicenses(ctx context.Context, appID uuid.UUID, limit, offset int) ([]store.License, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+licenseColumns+" FROM licenses WHERE app_id = $1 ORDER BY created_at DESC, id LIMIT $2 OFFSET $3",
		appID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: list licenses: %w", err)
	}
	defer rows.Close()

	lics := []store.License{}
	for rows.Next() {
		l, err := scanLicense(rows)
		if err != nil {
			return nil, err
		}
		lics = append(lics, l)
	}
	return lics, rows.Err()
}

// RedeemLicense is the atomic issued→active transition; the WHERE clause is
// the guard that makes concurrent redemptions single-winner.
func (s *Store) RedeemLicense(ctx context.Context, id uuid.UUID, hwidHash []byte, redeemedAt time.Time, expiresAt *time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE licenses
		SET status = 'active', hwid_hash = $2, redeemed_at = $3, expires_at = $4, updated_at = now()
		WHERE id = $1 AND status = 'issued'`,
		id, hwidHash, redeemedAt, expiresAt)
	if err != nil {
		return false, fmt.Errorf("postgres: redeem license: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// BindHWID wins only if no device is bound yet; same single-winner pattern.
func (s *Store) BindHWID(ctx context.Context, id uuid.UUID, hwidHash []byte) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE licenses SET hwid_hash = $2, updated_at = now()
		WHERE id = $1 AND hwid_hash IS NULL`,
		id, hwidHash)
	if err != nil {
		return false, fmt.Errorf("postgres: bind hwid: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) ResetHWID(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		"UPDATE licenses SET hwid_hash = NULL, updated_at = now() WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("postgres: reset hwid: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) SetLicenseStatus(ctx context.Context, id uuid.UUID, status store.LicenseStatus, banReason *string) error {
	tag, err := s.pool.Exec(ctx,
		"UPDATE licenses SET status = $2, ban_reason = $3, updated_at = now() WHERE id = $1",
		id, status, banReason)
	if err != nil {
		return fmt.Errorf("postgres: set license status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// --- admin users & tokens ---

func (s *Store) CreateAdminUser(ctx context.Context, u store.AdminUser) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO admin_users (id, email_hash, password_hash, created_at)
		VALUES ($1, $2, $3, $4)`,
		u.ID, u.EmailHash, u.PasswordHash, u.CreatedAt)
	if err != nil {
		return fmt.Errorf("postgres: create admin user: %w", err)
	}
	return nil
}

func (s *Store) GetAdminUserByEmailHash(ctx context.Context, emailHash []byte) (store.AdminUser, error) {
	var u store.AdminUser
	err := s.pool.QueryRow(ctx,
		"SELECT id, email_hash, password_hash, created_at FROM admin_users WHERE email_hash = $1",
		emailHash).Scan(&u.ID, &u.EmailHash, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.AdminUser{}, store.ErrNotFound
	}
	if err != nil {
		return store.AdminUser{}, fmt.Errorf("postgres: get admin user: %w", err)
	}
	return u, nil
}

func (s *Store) CreateAdminToken(ctx context.Context, t store.AdminToken) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO admin_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)`,
		t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.CreatedAt)
	if err != nil {
		return fmt.Errorf("postgres: create admin token: %w", err)
	}
	return nil
}

func (s *Store) GetAdminTokenByHash(ctx context.Context, tokenHash []byte) (store.AdminToken, error) {
	var t store.AdminToken
	err := s.pool.QueryRow(ctx,
		"SELECT id, user_id, token_hash, expires_at, created_at FROM admin_tokens WHERE token_hash = $1",
		tokenHash).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.AdminToken{}, store.ErrNotFound
	}
	if err != nil {
		return store.AdminToken{}, fmt.Errorf("postgres: get admin token: %w", err)
	}
	return t, nil
}

// DeleteExpiredAdminTokens is the cleanup job's workhorse; the partial
// index admin_tokens_expires_at_idx from 0001_init.sql keeps it cheap.
func (s *Store) DeleteExpiredAdminTokens(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, "DELETE FROM admin_tokens WHERE expires_at < $1", before)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// --- audit log ---

func (s *Store) AppendAudit(ctx context.Context, e store.AuditEntry) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (at, admin_id, action, target_id, detail)
		VALUES ($1, $2, $3, $4, $5)`,
		e.At, e.AdminID, e.Action, e.TargetID, e.Detail)
	if err != nil {
		return fmt.Errorf("postgres: append audit: %w", err)
	}
	return nil
}

func (s *Store) ListAudit(ctx context.Context, limit, offset int) ([]store.AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, at, admin_id, action, target_id, detail
		FROM audit_log ORDER BY at DESC, id DESC LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: list audit: %w", err)
	}
	defer rows.Close()

	entries := []store.AuditEntry{}
	for rows.Next() {
		var e store.AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.AdminID, &e.Action, &e.TargetID, &e.Detail); err != nil {
			return nil, fmt.Errorf("postgres: scan audit: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// DeleteAdminToken also sweeps already-expired tokens in the same statement:
// logouts are rare enough that the extra work is free, and it keeps the
// table from growing until the real cleanup job exists (TODO(v0.2), the
// admin_tokens_expires_at_idx index is already in place).
func (s *Store) DeleteAdminToken(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx,
		"DELETE FROM admin_tokens WHERE token_hash = $1 OR expires_at < now()",
		tokenHash)
	if err != nil {
		return fmt.Errorf("postgres: delete admin token: %w", err)
	}
	return nil
}
