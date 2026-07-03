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
	if _, err := pool.Exec(ctx, "TRUNCATE applications, licenses, admin_users, admin_tokens, audit_log CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	s := postgres.New(pool)
	now := time.Now().UTC().Truncate(time.Microsecond) // timestamptz keeps microseconds, not nanos

	app := store.Application{
		ID:        uuid.New(),
		Name:      "Integration App",
		CreatedAt: now,
	}
	firstKey := store.AppKey{
		ID:            uuid.New(),
		AppID:         app.ID,
		PublicKey:     randBytes(t, 32),
		PrivateKeyEnc: randBytes(t, 76),
		Active:        true,
		CreatedAt:     now,
	}

	t.Run("applications", func(t *testing.T) {
		if err := s.CreateApplication(ctx, app, firstKey); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetApplication(ctx, app.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != app.Name || !got.CreatedAt.Equal(app.CreatedAt) {
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

	t.Run("app keys", func(t *testing.T) {
		got, err := s.GetActiveAppKey(ctx, app.ID)
		if err != nil || string(got.PublicKey) != string(firstKey.PublicKey) || !got.Active {
			t.Fatalf("active key: %v, %+v", err, got)
		}
		if _, err := s.GetActiveAppKey(ctx, uuid.New()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown app active key: want ErrNotFound, got %v", err)
		}

		// Rotation retires the old key and installs the new one atomically.
		second := store.AppKey{
			ID:            uuid.New(),
			AppID:         app.ID,
			PublicKey:     randBytes(t, 32),
			PrivateKeyEnc: randBytes(t, 76),
			Active:        true,
			CreatedAt:     now.Add(time.Second),
		}
		if err := s.RotateAppKey(ctx, app.ID, second, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		got, err = s.GetActiveAppKey(ctx, app.ID)
		if err != nil || got.ID != second.ID {
			t.Fatalf("active after rotation: %v, %+v", err, got)
		}
		keys, err := s.ListAppKeys(ctx, app.ID)
		if err != nil || len(keys) != 2 {
			t.Fatalf("list keys: %v, len %d", err, len(keys))
		}
		if keys[0].ID != second.ID || keys[1].ID != firstKey.ID {
			t.Fatalf("order wrong: %+v", keys)
		}
		if keys[1].RetiredAt == nil {
			t.Fatal("old key not marked retired")
		}
		if err := s.RotateAppKey(ctx, uuid.New(), second, now); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("rotate unknown app: want ErrNotFound, got %v", err)
		}

		// Master-key re-encryption path.
		all, err := s.ListAllAppKeys(ctx)
		if err != nil || len(all) != 2 {
			t.Fatalf("list all keys: %v, len %d", err, len(all))
		}
		newCipher := randBytes(t, 76)
		if err := s.UpdateAppKeyCiphertext(ctx, firstKey.ID, newCipher); err != nil {
			t.Fatal(err)
		}
		keys, _ = s.ListAppKeys(ctx, app.ID)
		if string(keys[1].PrivateKeyEnc) != string(newCipher) {
			t.Fatal("ciphertext not updated")
		}
		if err := s.UpdateAppKeyCiphertext(ctx, uuid.New(), newCipher); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("update unknown key: want ErrNotFound, got %v", err)
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

	t.Run("audit log", func(t *testing.T) {
		actor := uuid.New()
		first := store.AuditEntry{At: now, Action: "license.ban", TargetID: uuid.NewString(), Detail: "chargeback"}
		second := store.AuditEntry{At: now.Add(time.Second), AdminID: &actor, Action: "license.unban"}
		for _, e := range []store.AuditEntry{first, second} {
			if err := s.AppendAudit(ctx, e); err != nil {
				t.Fatal(err)
			}
		}

		entries, err := s.ListAudit(ctx, 10, 0)
		if err != nil || len(entries) != 2 {
			t.Fatalf("list: %v, len %d", err, len(entries))
		}
		// Newest first.
		if entries[0].Action != "license.unban" || entries[1].Action != "license.ban" {
			t.Fatalf("order wrong: %+v", entries)
		}
		if entries[0].AdminID == nil || *entries[0].AdminID != actor {
			t.Errorf("actor lost: %+v", entries[0])
		}
		if entries[1].AdminID != nil {
			t.Errorf("nil actor not preserved: %+v", entries[1])
		}
		if entries[1].TargetID != first.TargetID || entries[1].Detail != "chargeback" {
			t.Errorf("fields lost: %+v", entries[1])
		}
		if !entries[1].At.Equal(first.At) {
			t.Errorf("timestamp mismatch: %v vs %v", entries[1].At, first.At)
		}

		if page, err := s.ListAudit(ctx, 1, 1); err != nil || len(page) != 1 || page[0].Action != "license.ban" {
			t.Fatalf("pagination: %v, %+v", err, page)
		}
	})

	t.Run("stats", func(t *testing.T) {
		// State so far: one app, one active license expiring at now+1h.
		st, err := s.Stats(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		if st.Applications != 1 || st.Licenses != 1 || st.ActiveLicenses != 1 || st.BannedLicenses != 0 {
			t.Fatalf("baseline: %+v", st)
		}

		// A banned license and an active-but-expired one must both stay
		// out of the active count.
		past := now.Add(-time.Minute)
		reason := "abuse"
		extra := []store.License{
			{ID: uuid.New(), AppID: app.ID, KeyHash: randBytes(t, 32), KeyHint: "FGHIJ", Tier: "pro", Status: store.StatusBanned, BanReason: &reason, CreatedAt: now, UpdatedAt: now},
			{ID: uuid.New(), AppID: app.ID, KeyHash: randBytes(t, 32), KeyHint: "KLMNO", Tier: "pro", Status: store.StatusActive, ExpiresAt: &past, CreatedAt: now, UpdatedAt: now},
		}
		if err := s.CreateLicenses(ctx, extra); err != nil {
			t.Fatal(err)
		}
		st, err = s.Stats(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		if st.Licenses != 3 || st.ActiveLicenses != 1 || st.BannedLicenses != 1 {
			t.Fatalf("after extras: %+v", st)
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
