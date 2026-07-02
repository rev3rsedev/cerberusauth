package postgres_test

import (
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rev3rsedev/cerberusauth/internal/store"
	"github.com/rev3rsedev/cerberusauth/internal/store/postgres"
)

// TestStoreIntegration exercises the real SQL against a live PostgreSQL:
// the semantics the storetest fake promises to mirror. Skipped unless
// CERBERUS_TEST_DATABASE_URL is set (CI sets it; locally, point it at a
// DISPOSABLE database, because the test truncates every table).
func TestStoreIntegration(t *testing.T) {
	url := os.Getenv("CERBERUS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CERBERUS_TEST_DATABASE_URL not set")
	}
	ctx := t.Context()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if _, err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE applications, licenses, admin_users, admin_tokens CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	s := postgres.New(pool)
	now := time.Now().UTC().Truncate(time.Microsecond) // timestamptz keeps microseconds, not nanos

	app := store.Application{
		ID:            uuid.New(),
		Name:          "Integration App",
		PublicKey:     randBytes(t, 32),
		PrivateKeyEnc: randBytes(t, 76),
		CreatedAt:     now,
	}

	t.Run("applications", func(t *testing.T) {
		if err := s.CreateApplication(ctx, app); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetApplication(ctx, app.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != app.Name || string(got.PublicKey) != string(app.PublicKey) || !got.CreatedAt.Equal(app.CreatedAt) {
			t.Fatalf("roundtrip mismatch: %+v", got)
		}
		if _, err := s.GetApplication(ctx, uuid.New()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown app: want ErrNotFound, got %v", err)
		}
		apps, err := s.ListApplications(ctx)
		if err != nil || len(apps) != 1 {
			t.Fatalf("list: %v, len %d", err, len(apps))
		}
	})

	duration := int64(3600)
	lic := store.License{
		ID:              uuid.New(),
		AppID:           app.ID,
		KeyHash:         randBytes(t, 32),
		KeyHint:         "ABCDE",
		Tier:            "pro",
		Status:          store.StatusIssued,
		DurationSeconds: &duration,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	t.Run("licenses", func(t *testing.T) {
		if err := s.CreateLicenses(ctx, []store.License{lic}); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetLicenseByKeyHash(ctx, app.ID, lic.KeyHash)
		if err != nil || got.ID != lic.ID {
			t.Fatalf("get by key hash: %v, id %v", err, got.ID)
		}
		// Same hash under a different app must not match.
		if _, err := s.GetLicenseByKeyHash(ctx, uuid.New(), lic.KeyHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("foreign app: want ErrNotFound, got %v", err)
		}
		lics, err := s.ListLicenses(ctx, app.ID, 10, 0)
		if err != nil || len(lics) != 1 {
			t.Fatalf("list: %v, len %d", err, len(lics))
		}
	})

	t.Run("redeem state machine", func(t *testing.T) {
		expiry := now.Add(time.Hour)
		ok, err := s.RedeemLicense(ctx, lic.ID, randBytes(t, 32), now, &expiry)
		if err != nil || !ok {
			t.Fatalf("first redeem: ok=%v err=%v", ok, err)
		}
		// Second redemption loses: the row is no longer status=issued.
		ok, err = s.RedeemLicense(ctx, lic.ID, randBytes(t, 32), now, &expiry)
		if err != nil || ok {
			t.Fatalf("second redeem: ok=%v err=%v, want false", ok, err)
		}
		got, err := s.GetLicenseByID(ctx, lic.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != store.StatusActive || got.HWIDHash == nil || got.RedeemedAt == nil || got.ExpiresAt == nil {
			t.Fatalf("post-redeem row: %+v", got)
		}

		// HWID: bind only when unbound.
		if ok, err := s.BindHWID(ctx, lic.ID, randBytes(t, 32)); err != nil || ok {
			t.Fatalf("bind over existing: ok=%v err=%v, want false", ok, err)
		}
		if err := s.ResetHWID(ctx, lic.ID); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.BindHWID(ctx, lic.ID, randBytes(t, 32)); err != nil || !ok {
			t.Fatalf("bind after reset: ok=%v err=%v, want true", ok, err)
		}

		// Ban with reason, unban clears it.
		reason := "chargeback"
		if err := s.SetLicenseStatus(ctx, lic.ID, store.StatusBanned, &reason); err != nil {
			t.Fatal(err)
		}
		got, _ = s.GetLicenseByID(ctx, lic.ID)
		if got.Status != store.StatusBanned || got.BanReason == nil || *got.BanReason != reason {
			t.Fatalf("post-ban row: %+v", got)
		}
		if err := s.SetLicenseStatus(ctx, lic.ID, store.StatusActive, nil); err != nil {
			t.Fatal(err)
		}
		got, _ = s.GetLicenseByID(ctx, lic.ID)
		if got.Status != store.StatusActive || got.BanReason != nil {
			t.Fatalf("post-unban row: %+v", got)
		}
	})

	t.Run("admin users and tokens", func(t *testing.T) {
		u := store.AdminUser{
			ID:           uuid.New(),
			EmailHash:    randBytes(t, 32),
			PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$fake$fake",
			CreatedAt:    now,
		}
		if err := s.CreateAdminUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		if got, err := s.GetAdminUserByEmailHash(ctx, u.EmailHash); err != nil || got.ID != u.ID {
			t.Fatalf("get admin: %v, id %v", err, got.ID)
		}
		if _, err := s.GetAdminUserByEmailHash(ctx, randBytes(t, 32)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown email hash: want ErrNotFound, got %v", err)
		}

		valid := store.AdminToken{
			ID: uuid.New(), UserID: u.ID, TokenHash: randBytes(t, 32),
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}
		expired := store.AdminToken{
			ID: uuid.New(), UserID: u.ID, TokenHash: randBytes(t, 32),
			ExpiresAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Hour),
		}
		for _, tok := range []store.AdminToken{valid, expired} {
			if err := s.CreateAdminToken(ctx, tok); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := s.GetAdminTokenByHash(ctx, valid.TokenHash); err != nil || got.UserID != u.ID {
			t.Fatalf("get token: %v", err)
		}

		// Revoking the valid token also sweeps the expired one.
		if err := s.DeleteAdminToken(ctx, valid.TokenHash); err != nil {
			t.Fatal(err)
		}
		for name, hash := range map[string][]byte{"revoked": valid.TokenHash, "swept expired": expired.TokenHash} {
			if _, err := s.GetAdminTokenByHash(ctx, hash); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("%s token still present: %v", name, err)
			}
		}
		// Idempotent.
		if err := s.DeleteAdminToken(ctx, valid.TokenHash); err != nil {
			t.Fatalf("second delete: %v", err)
		}
	})
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
