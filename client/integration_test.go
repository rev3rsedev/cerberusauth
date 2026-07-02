package client_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rev3rsedev/cerberusauth/client"
	"github.com/rev3rsedev/cerberusauth/internal/server"
	"github.com/rev3rsedev/cerberusauth/internal/service"
	"github.com/rev3rsedev/cerberusauth/internal/store/storetest"
)

// TestAgainstRealServer runs the SDK against the actual HTTP stack: real
// handlers, real service, in-memory store, the same wiring cmd/cerberusd
// uses minus Postgres. Protocol drift between SDK and server fails here
// first. The SDK itself must never import internal packages; only this test
// file may, and it goes with the SDK if the package ever moves to its own
// repository.
func TestAgainstRealServer(t *testing.T) {
	ctx := context.Background()
	svc := service.New(storetest.New(), service.Options{
		MasterKey: bytes.Repeat([]byte{0x42}, 32),
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ts := httptest.NewServer(server.New(svc, log).Handler())
	defer ts.Close()

	app, appKey, err := svc.CreateApplication(ctx, "sdk-e2e")
	if err != nil {
		t.Fatal(err)
	}
	dur := int64(3600)
	issued, err := svc.IssueLicenses(ctx, app.ID, 1, "pro", &dur, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := issued[0].Key
	pubB64 := base64.StdEncoding.EncodeToString(appKey.PublicKey)

	c, err := client.New(ts.URL, app.ID.String(), pubB64)
	if err != nil {
		t.Fatal(err)
	}

	// Validate before redeem: a signed denial, not an error.
	v, err := c.Validate(ctx, key, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if v.Valid || v.Reason != client.ReasonNotRedeemed {
		t.Fatalf("before redeem: want not_redeemed, got %+v", v)
	}

	// Redeem binds the device and starts the expiry clock.
	v, err = c.Redeem(ctx, key, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid || v.Tier != "pro" {
		t.Fatalf("redeem: want valid pro, got %+v", v)
	}
	if until := time.Until(v.ExpiresAt); until < 55*time.Minute || until > 65*time.Minute {
		t.Errorf("expiry %v not ~1h out", v.ExpiresAt)
	}

	// Redeeming again from the same device is a safe retry.
	if v, err = c.Redeem(ctx, key, "device-1"); err != nil || !v.Valid {
		t.Fatalf("redeem retry: %+v, %v", v, err)
	}

	// Validate from the bound device succeeds; keep the envelope for the
	// offline check below.
	v, err = c.Validate(ctx, key, "device-1")
	if err != nil || !v.Valid {
		t.Fatalf("validate bound: %+v, %v", v, err)
	}
	stored := v.Envelope

	// Another device is refused.
	if v, err = c.Validate(ctx, key, "device-2"); err != nil || v.Valid || v.Reason != client.ReasonHWIDMismatch {
		t.Fatalf("other device: want hwid_mismatch, got %+v, %v", v, err)
	}

	// A key that was never issued.
	if v, err = c.Validate(ctx, "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA", "device-1"); err != nil || v.Valid || v.Reason != client.ReasonInvalidKey {
		t.Fatalf("unknown key: want invalid_key, got %+v, %v", v, err)
	}

	// The stored envelope still verifies offline.
	if sv, err := c.VerifyStored(stored); err != nil || !sv.Valid {
		t.Fatalf("stored envelope: %+v, %v", sv, err)
	}

	// Banning flips future verdicts, all still signed.
	if _, err := svc.BanLicense(ctx, issued[0].License.ID, "e2e"); err != nil {
		t.Fatal(err)
	}
	if v, err = c.Validate(ctx, key, "device-1"); err != nil || v.Valid || v.Reason != client.ReasonBanned {
		t.Fatalf("after ban: want banned, got %+v, %v", v, err)
	}

	// A client pinning the wrong key rejects everything the server says.
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evil, err := client.New(ts.URL, app.ID.String(), base64.StdEncoding.EncodeToString(wrongPub))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evil.Validate(ctx, key, "device-1"); !errors.Is(err, client.ErrBadSignature) {
		t.Fatalf("wrong pinned key: want ErrBadSignature, got %v", err)
	}

	// An unknown app is an unsigned transport error, never a verdict.
	ghost, err := client.New(ts.URL, "00000000-0000-0000-0000-000000000000", pubB64)
	if err != nil {
		t.Fatal(err)
	}
	var apiErr *client.APIError
	if _, err := ghost.Validate(ctx, key, "device-1"); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown app: want 404 APIError, got %v", err)
	}
}

// TestKeyRotationOverlap walks the documented rotation flow against the
// real stack: a client pinning only the old key fails closed after the
// rotation; one pinning old + new keeps working before and after.
func TestKeyRotationOverlap(t *testing.T) {
	ctx := context.Background()
	svc := service.New(storetest.New(), service.Options{
		MasterKey: bytes.Repeat([]byte{0x42}, 32),
	})
	ts := httptest.NewServer(server.New(svc, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer ts.Close()

	app, oldKey, err := svc.CreateApplication(ctx, "rotation-e2e")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := svc.IssueLicenses(ctx, app.ID, 1, "pro", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	lic := issued[0].Key
	oldPub := base64.StdEncoding.EncodeToString(oldKey.PublicKey)

	oldOnly, err := client.New(ts.URL, app.ID.String(), oldPub)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := oldOnly.Redeem(ctx, lic, "device-1"); err != nil || !v.Valid {
		t.Fatalf("pre-rotation redeem: %+v, %v", v, err)
	}

	newKey, err := svc.RotateAppKey(ctx, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	newPub := base64.StdEncoding.EncodeToString(newKey.PublicKey)

	// The client that never learned the new key refuses everything now:
	// fail closed, exactly what pinning promises.
	if _, err := oldOnly.Validate(ctx, lic, "device-1"); !errors.Is(err, client.ErrBadSignature) {
		t.Fatalf("old-only client after rotation: want ErrBadSignature, got %v", err)
	}

	// The overlap client pins both and keeps working.
	both, err := client.New(ts.URL, app.ID.String(), newPub, client.WithExtraPublicKeys(oldPub))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := both.Validate(ctx, lic, "device-1"); err != nil || !v.Valid {
		t.Fatalf("dual-pinned client after rotation: %+v, %v", v, err)
	}
}
