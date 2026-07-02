package service_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rev3rsedev/cerberusauth/internal/service"
	"github.com/rev3rsedev/cerberusauth/internal/store"
	"github.com/rev3rsedev/cerberusauth/internal/store/storetest"
)

// wellFormedUnknownKey passes canonicalization but is not in the store.
const wellFormedUnknownKey = "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA"

type env struct {
	svc *service.Service
	st  *storetest.FakeStore
	now *time.Time
	app store.Application
	ctx context.Context
}

func newEnv(t *testing.T) *env {
	t.Helper()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	e := &env{
		st:  storetest.New(),
		now: &now,
		ctx: context.Background(),
	}
	e.svc = service.New(e.st, service.Options{
		MasterKey: bytes.Repeat([]byte{0x42}, 32),
		ClockSkew: 5 * time.Minute,
		TokenTTL:  24 * time.Hour,
		Now:       func() time.Time { return *e.now },
	})
	app, err := e.svc.CreateApplication(e.ctx, "Test App")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	e.app = app
	return e
}

func (e *env) advance(d time.Duration) {
	*e.now = e.now.Add(d)
}

func (e *env) issue(t *testing.T, durationSeconds *int64, expiresAt *time.Time) service.IssuedLicense {
	t.Helper()
	issued, err := e.svc.IssueLicenses(e.ctx, e.app.ID, 1, "pro", durationSeconds, expiresAt)
	if err != nil {
		t.Fatalf("IssueLicenses: %v", err)
	}
	return issued[0]
}

func (e *env) req(key, hwid string) service.ValidationRequest {
	return service.ValidationRequest{
		AppID:      e.app.ID,
		LicenseKey: key,
		HWID:       hwid,
		Nonce:      "nonce-0123456789abcdef",
		Timestamp:  e.now.Unix(),
	}
}

// verify checks the envelope signature against the app key and returns the
// parsed payload — the exact procedure a real client must follow.
func (e *env) verify(t *testing.T, resp service.SignedResponse) service.Payload {
	t.Helper()
	if resp.Alg != "ed25519" {
		t.Fatalf("alg = %q", resp.Alg)
	}
	p, err := service.VerifyResponse(ed25519.PublicKey(e.app.PublicKey), resp)
	if err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}
	return p
}

func i64(n int64) *int64 { return &n }

func TestRedeemHappyPath(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, i64(3600), nil)

	req := e.req(il.Key, "device-1")
	resp, err := e.svc.Redeem(e.ctx, req)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	p := e.verify(t, resp)

	if !p.Valid {
		t.Fatalf("valid = false, reason = %q", p.Reason)
	}
	if p.Nonce != req.Nonce || p.ClientTS != req.Timestamp || p.HWID != "device-1" {
		t.Fatalf("echo fields wrong: %+v", p)
	}
	if p.Tier != "pro" || p.AppID != e.app.ID.String() || p.LicenseID != il.License.ID.String() {
		t.Fatalf("identity fields wrong: %+v", p)
	}
	if want := e.now.Add(time.Hour).Unix(); p.ExpiresAt != want {
		t.Fatalf("expires_at = %d, want %d (redeemed_at + duration)", p.ExpiresAt, want)
	}
	if p.ServerTS != e.now.Unix() {
		t.Fatalf("server_ts = %d", p.ServerTS)
	}

	lic, _ := e.st.GetLicenseByID(e.ctx, il.License.ID)
	if lic.Status != store.StatusActive || lic.HWIDHash == nil || lic.RedeemedAt == nil {
		t.Fatalf("stored license not activated: %+v", lic)
	}
	if !bytes.Equal(lic.HWIDHash, service.HashHWID("device-1")) {
		t.Fatal("stored HWID hash mismatch")
	}
}

func TestRedeemIsIdempotentForSameDevice(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, i64(3600), nil)

	if _, err := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1")); err != nil {
		t.Fatal(err)
	}
	resp, err := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1"))
	if err != nil {
		t.Fatal(err)
	}
	p := e.verify(t, resp)
	if !p.Valid {
		t.Fatalf("retry redeem failed: %q", p.Reason)
	}
	if want := e.now.Add(time.Hour).Unix(); p.ExpiresAt != want {
		t.Fatalf("retry lost expiry: %d want %d", p.ExpiresAt, want)
	}
}

func TestRedeemRejectsSecondDevice(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, nil, nil)

	if _, err := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1")); err != nil {
		t.Fatal(err)
	}
	resp, _ := e.svc.Redeem(e.ctx, e.req(il.Key, "device-2"))
	if p := e.verify(t, resp); p.Valid || p.Reason != service.ReasonHWIDMismatch {
		t.Fatalf("want hwid_mismatch, got %+v", p)
	}
}

func TestValidateLifecycle(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, i64(3600), nil)

	// Before redemption.
	resp, _ := e.svc.Validate(e.ctx, e.req(il.Key, "device-1"))
	if p := e.verify(t, resp); p.Valid || p.Reason != service.ReasonNotRedeemed {
		t.Fatalf("want not_redeemed, got %+v", p)
	}

	// Redeem, then validate.
	if _, err := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1")); err != nil {
		t.Fatal(err)
	}
	resp, _ = e.svc.Validate(e.ctx, e.req(il.Key, "device-1"))
	if p := e.verify(t, resp); !p.Valid {
		t.Fatalf("want valid, got %+v", p)
	}

	// Wrong device.
	resp, _ = e.svc.Validate(e.ctx, e.req(il.Key, "device-2"))
	if p := e.verify(t, resp); p.Valid || p.Reason != service.ReasonHWIDMismatch {
		t.Fatalf("want hwid_mismatch, got %+v", p)
	}

	// Expired.
	e.advance(2 * time.Hour)
	resp, _ = e.svc.Validate(e.ctx, e.req(il.Key, "device-1"))
	if p := e.verify(t, resp); p.Valid || p.Reason != service.ReasonExpired {
		t.Fatalf("want expired, got %+v", p)
	}
}

func TestValidateBannedIsSignedFailure(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, nil, nil)
	if _, err := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.BanLicense(e.ctx, il.License.ID, "chargeback"); err != nil {
		t.Fatal(err)
	}

	resp, err := e.svc.Validate(e.ctx, e.req(il.Key, "device-1"))
	if err != nil {
		t.Fatal(err)
	}
	// The signature must verify — a denial is as authentic as an approval.
	p := e.verify(t, resp)
	if p.Valid || p.Reason != service.ReasonBanned {
		t.Fatalf("want banned, got %+v", p)
	}
}

func TestRedeemBanned(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, nil, nil)
	if _, err := e.svc.BanLicense(e.ctx, il.License.ID, ""); err != nil {
		t.Fatal(err)
	}
	resp, _ := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1"))
	if p := e.verify(t, resp); p.Valid || p.Reason != service.ReasonBanned {
		t.Fatalf("want banned, got %+v", p)
	}
}

func TestUnbanRestoresPriorState(t *testing.T) {
	e := newEnv(t)

	// Banned while active → unban → active.
	active := e.issue(t, nil, nil)
	if _, err := e.svc.Redeem(e.ctx, e.req(active.Key, "device-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.BanLicense(e.ctx, active.License.ID, "x"); err != nil {
		t.Fatal(err)
	}
	lic, err := e.svc.UnbanLicense(e.ctx, active.License.ID)
	if err != nil {
		t.Fatal(err)
	}
	if lic.Status != store.StatusActive || lic.BanReason != nil {
		t.Fatalf("want active with no reason, got %+v", lic)
	}

	// Banned while issued → unban → issued.
	fresh := e.issue(t, nil, nil)
	if _, err := e.svc.BanLicense(e.ctx, fresh.License.ID, "y"); err != nil {
		t.Fatal(err)
	}
	lic, err = e.svc.UnbanLicense(e.ctx, fresh.License.ID)
	if err != nil {
		t.Fatal(err)
	}
	if lic.Status != store.StatusIssued {
		t.Fatalf("want issued, got %s", lic.Status)
	}

	// Unban of a non-banned license is a no-op.
	lic, err = e.svc.UnbanLicense(e.ctx, fresh.License.ID)
	if err != nil || lic.Status != store.StatusIssued {
		t.Fatalf("no-op unban: %v %+v", err, lic)
	}
}

func TestResetHWIDAllowsRebind(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, nil, nil)
	if _, err := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1")); err != nil {
		t.Fatal(err)
	}

	lic, err := e.svc.ResetHWID(e.ctx, il.License.ID)
	if err != nil {
		t.Fatal(err)
	}
	if lic.HWIDHash != nil {
		t.Fatal("reset did not clear the binding")
	}

	// Next validation binds the new device...
	resp, _ := e.svc.Validate(e.ctx, e.req(il.Key, "device-2"))
	if p := e.verify(t, resp); !p.Valid {
		t.Fatalf("rebind failed: %+v", p)
	}
	// ...and the old device is now rejected.
	resp, _ = e.svc.Validate(e.ctx, e.req(il.Key, "device-1"))
	if p := e.verify(t, resp); p.Valid || p.Reason != service.ReasonHWIDMismatch {
		t.Fatalf("old device still accepted: %+v", p)
	}
}

func TestStaleTimestampRejectedBothDirections(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, nil, nil)

	for _, offset := range []time.Duration{-10 * time.Minute, 10 * time.Minute} {
		req := e.req(il.Key, "device-1")
		req.Timestamp = e.now.Add(offset).Unix()
		resp, err := e.svc.Validate(e.ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		p := e.verify(t, resp)
		if p.Valid || p.Reason != service.ReasonStaleTimestamp {
			t.Fatalf("offset %v: want stale_timestamp, got %+v", offset, p)
		}
		if p.ClientTS != req.Timestamp {
			t.Fatal("stale verdict must still echo the client timestamp")
		}
	}

	// Inside the window is fine.
	req := e.req(il.Key, "device-1")
	req.Timestamp = e.now.Add(-4 * time.Minute).Unix()
	resp, _ := e.svc.Redeem(e.ctx, req)
	if p := e.verify(t, resp); !p.Valid {
		t.Fatalf("within-skew request rejected: %+v", p)
	}
}

func TestUnknownAndMalformedKeys(t *testing.T) {
	e := newEnv(t)

	resp, err := e.svc.Validate(e.ctx, e.req(wellFormedUnknownKey, "device-1"))
	if err != nil {
		t.Fatal(err)
	}
	if p := e.verify(t, resp); p.Valid || p.Reason != service.ReasonInvalidKey {
		t.Fatalf("unknown key: want invalid_key, got %+v", p)
	}
	if p := e.verify(t, resp); p.LicenseID != "" {
		t.Fatal("unknown key must not leak a license id")
	}

	resp, err = e.svc.Validate(e.ctx, e.req("not-a-real-key", "device-1"))
	if err != nil {
		t.Fatal(err)
	}
	if p := e.verify(t, resp); p.Valid || p.Reason != service.ReasonInvalidKey {
		t.Fatalf("malformed key: want invalid_key, got %+v", p)
	}
}

func TestUnknownAppIsUnsignedError(t *testing.T) {
	e := newEnv(t)
	req := e.req(wellFormedUnknownKey, "device-1")
	req.AppID = uuid.New()
	if _, err := e.svc.Validate(e.ctx, req); !errors.Is(err, service.ErrAppNotFound) {
		t.Fatalf("want ErrAppNotFound, got %v", err)
	}
}

func TestFixedExpiryPreservedThroughRedeem(t *testing.T) {
	e := newEnv(t)
	fixed := e.now.Add(72 * time.Hour).UTC()
	il := e.issue(t, nil, &fixed)

	resp, err := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1"))
	if err != nil {
		t.Fatal(err)
	}
	if p := e.verify(t, resp); p.ExpiresAt != fixed.Unix() {
		t.Fatalf("expires_at = %d, want fixed %d", p.ExpiresAt, fixed.Unix())
	}
}

func TestRedeemExpiredFixedDate(t *testing.T) {
	e := newEnv(t)
	fixed := e.now.Add(time.Hour).UTC()
	il := e.issue(t, nil, &fixed)

	e.advance(2 * time.Hour)
	resp, _ := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1"))
	if p := e.verify(t, resp); p.Valid || p.Reason != service.ReasonExpired {
		t.Fatalf("want expired, got %+v", p)
	}
}

func TestPerpetualLicenseHasNoExpiry(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, nil, nil)
	resp, _ := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1"))
	if p := e.verify(t, resp); !p.Valid || p.ExpiresAt != 0 {
		t.Fatalf("perpetual license: %+v", p)
	}

	e.advance(24 * 365 * time.Hour)
	req := e.req(il.Key, "device-1") // re-stamp with the advanced clock
	resp, _ = e.svc.Validate(e.ctx, req)
	if p := e.verify(t, resp); !p.Valid {
		t.Fatalf("perpetual license expired: %+v", p)
	}
}

func TestTamperedEnvelopeFailsVerification(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, nil, nil)
	resp, err := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1"))
	if err != nil {
		t.Fatal(err)
	}

	raw, _ := base64.StdEncoding.DecodeString(resp.Payload)
	raw = bytes.Replace(raw, []byte(`"valid":true`), []byte(`"valid":false`), 1)
	forged := resp
	forged.Payload = base64.StdEncoding.EncodeToString(raw)

	if _, err := service.VerifyResponse(ed25519.PublicKey(e.app.PublicKey), forged); !errors.Is(err, service.ErrBadSignature) {
		t.Fatalf("forged payload verified: %v", err)
	}
}

func TestIssueLicensesInputValidation(t *testing.T) {
	e := newEnv(t)
	past := e.now.Add(-time.Hour)
	dur := i64(60)

	cases := []struct {
		name string
		fn   func() error
	}{
		{"zero count", func() error {
			_, err := e.svc.IssueLicenses(e.ctx, e.app.ID, 0, "", nil, nil)
			return err
		}},
		{"huge count", func() error {
			_, err := e.svc.IssueLicenses(e.ctx, e.app.ID, 1001, "", nil, nil)
			return err
		}},
		{"both expiry modes", func() error {
			future := e.now.Add(time.Hour)
			_, err := e.svc.IssueLicenses(e.ctx, e.app.ID, 1, "", dur, &future)
			return err
		}},
		{"negative duration", func() error {
			_, err := e.svc.IssueLicenses(e.ctx, e.app.ID, 1, "", i64(-5), nil)
			return err
		}},
		{"past expiry", func() error {
			_, err := e.svc.IssueLicenses(e.ctx, e.app.ID, 1, "", nil, &past)
			return err
		}},
	}
	for _, tc := range cases {
		if err := tc.fn(); !errors.Is(err, service.ErrInvalidInput) {
			t.Fatalf("%s: want ErrInvalidInput, got %v", tc.name, err)
		}
	}

	if _, err := e.svc.IssueLicenses(e.ctx, uuid.New(), 1, "", nil, nil); !errors.Is(err, service.ErrAppNotFound) {
		t.Fatalf("unknown app: want ErrAppNotFound, got %v", err)
	}
}

func TestAdminLoginAndTokens(t *testing.T) {
	e := newEnv(t)

	if _, err := e.svc.CreateAdminUser(e.ctx, "admin@example.com", "a-long-password"); err != nil {
		t.Fatalf("CreateAdminUser: %v", err)
	}
	if _, err := e.svc.CreateAdminUser(e.ctx, "admin@example.com", "a-long-password"); !errors.Is(err, service.ErrAlreadyExists) {
		t.Fatalf("duplicate admin: want ErrAlreadyExists, got %v", err)
	}
	if _, err := e.svc.CreateAdminUser(e.ctx, "bad-email", "a-long-password"); !errors.Is(err, service.ErrInvalidInput) {
		t.Fatalf("bad email: want ErrInvalidInput, got %v", err)
	}
	if _, err := e.svc.CreateAdminUser(e.ctx, "b@c.de", "short"); !errors.Is(err, service.ErrInvalidInput) {
		t.Fatalf("short password: want ErrInvalidInput, got %v", err)
	}

	token, expiresAt, err := e.svc.Login(e.ctx, "Admin@Example.com", "a-long-password") // case-insensitive email
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if want := e.now.Add(24 * time.Hour); !expiresAt.Equal(want) {
		t.Fatalf("token expiry = %v, want %v", expiresAt, want)
	}

	if _, _, err := e.svc.Login(e.ctx, "admin@example.com", "wrong-password"); !errors.Is(err, service.ErrInvalidCredentials) {
		t.Fatalf("wrong password: want ErrInvalidCredentials, got %v", err)
	}
	if _, _, err := e.svc.Login(e.ctx, "ghost@example.com", "whatever-long"); !errors.Is(err, service.ErrInvalidCredentials) {
		t.Fatalf("unknown email: want ErrInvalidCredentials, got %v", err)
	}

	if _, err := e.svc.AuthenticateToken(e.ctx, token); err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if _, err := e.svc.AuthenticateToken(e.ctx, "cba_bogus"); !errors.Is(err, service.ErrInvalidToken) {
		t.Fatalf("bogus token: want ErrInvalidToken, got %v", err)
	}

	e.advance(25 * time.Hour)
	if _, err := e.svc.AuthenticateToken(e.ctx, token); !errors.Is(err, service.ErrInvalidToken) {
		t.Fatalf("expired token: want ErrInvalidToken, got %v", err)
	}
}
