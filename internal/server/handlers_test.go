package server_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rev3rsedev/cerberusauth/internal/server"
	"github.com/rev3rsedev/cerberusauth/internal/service"
	"github.com/rev3rsedev/cerberusauth/internal/store/storetest"
)

type env struct {
	handler http.Handler
	svc     *service.Service
	now     *time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	e := &env{now: &now}
	e.svc = service.New(storetest.New(), service.Options{
		MasterKey: bytes.Repeat([]byte{0x42}, 32),
		ClockSkew: 5 * time.Minute,
		TokenTTL:  24 * time.Hour,
		Now:       func() time.Time { return *e.now },
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e.handler = server.New(e.svc, log).Handler()
	return e
}

// do sends a JSON request through the full middleware stack.
func (e *env) do(t *testing.T, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

func decode[T any](t *testing.T, rr *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response %q: %v", rr.Body.String(), err)
	}
	return v
}

func (e *env) clientBody(appID, key, hwid string) map[string]any {
	return map[string]any{
		"app_id":      appID,
		"license_key": key,
		"hwid":        hwid,
		"nonce":       "nonce-0123456789abcdef",
		"timestamp":   e.now.Unix(),
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t)
	if rr := e.do(t, "GET", "/healthz", nil, ""); rr.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rr.Code)
	}
}

func TestAdminEndpointsRequireToken(t *testing.T) {
	e := newEnv(t)
	if rr := e.do(t, "POST", "/v1/admin/apps", map[string]string{"name": "x"}, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rr.Code)
	}
	if rr := e.do(t, "POST", "/v1/admin/apps", map[string]string{"name": "x"}, "cba_garbage"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("garbage token: %d", rr.Code)
	}
	if rr := e.do(t, "GET", "/v1/admin/stats", nil, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("stats without token: %d", rr.Code)
	}
}

func TestClientRequestValidation(t *testing.T) {
	e := newEnv(t)

	// Malformed JSON.
	req := httptest.NewRequest("POST", "/v1/client/validate", bytes.NewReader([]byte("{nope")))
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON: %d", rr.Code)
	}

	valid := e.clientBody("00000000-0000-0000-0000-000000000001", "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA", "device-1")

	mutate := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range valid {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	badRequests := map[string]map[string]any{
		"bad uuid":    mutate("app_id", "not-a-uuid"),
		"empty key":   mutate("license_key", ""),
		"empty hwid":  mutate("hwid", ""),
		"short nonce": mutate("nonce", "abc"),
		"zero ts":     mutate("timestamp", 0),
	}
	for name, body := range badRequests {
		if rr := e.do(t, "POST", "/v1/client/validate", body, ""); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", name, rr.Code)
		}
	}

	// Well-formed but unknown app: unsigned 404, not a verdict.
	if rr := e.do(t, "POST", "/v1/client/validate", valid, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown app: got %d, want 404", rr.Code)
	}
}

// TestFullLifecycleOverHTTP drives the entire MVP through the API exactly
// as an operator + client would: login, create app, issue, redeem,
// validate, ban, unban, reset HWID.
func TestFullLifecycleOverHTTP(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()

	// Bootstrap an admin (the one non-HTTP step, as in production).
	if _, err := e.svc.CreateAdminUser(ctx, "admin@example.com", "a-long-password"); err != nil {
		t.Fatal(err)
	}

	// Login.
	rr := e.do(t, "POST", "/v1/admin/login", map[string]string{
		"email": "admin@example.com", "password": "a-long-password",
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	login := decode[struct {
		Token string `json:"token"`
	}](t, rr)
	if login.Token == "" {
		t.Fatal("empty token")
	}

	// Wrong password is a 401.
	if rr := e.do(t, "POST", "/v1/admin/login", map[string]string{
		"email": "admin@example.com", "password": "wrong-password",
	}, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: %d", rr.Code)
	}

	// Create an application.
	rr = e.do(t, "POST", "/v1/admin/apps", map[string]string{"name": "My Game"}, login.Token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create app: %d %s", rr.Code, rr.Body.String())
	}
	app := decode[struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
		KeyID     string `json:"key_id"`
	}](t, rr)
	pubBytes, err := base64.StdEncoding.DecodeString(app.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("bad public key in response: %v len=%d", err, len(pubBytes))
	}
	pub := ed25519.PublicKey(pubBytes)

	// The pubkey endpoint agrees with the create response.
	rr = e.do(t, "GET", "/v1/client/apps/"+app.ID+"/pubkey", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("pubkey: %d", rr.Code)
	}
	if pk := decode[struct {
		PublicKey string `json:"public_key"`
	}](t, rr); pk.PublicKey != app.PublicKey {
		t.Fatal("pubkey endpoint disagrees with create response")
	}

	// Issue one 1-hour license.
	rr = e.do(t, "POST", "/v1/admin/apps/"+app.ID+"/licenses", map[string]any{
		"count": 1, "tier": "pro", "duration_seconds": 3600,
	}, login.Token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", rr.Code, rr.Body.String())
	}
	issued := decode[struct {
		Licenses []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"licenses"`
	}](t, rr)
	if len(issued.Licenses) != 1 || issued.Licenses[0].Key == "" {
		t.Fatalf("issue response: %+v", issued)
	}
	licID, key := issued.Licenses[0].ID, issued.Licenses[0].Key

	// The listing shows a hint, never the key.
	rr = e.do(t, "GET", "/v1/admin/apps/"+app.ID+"/licenses", nil, login.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d", rr.Code)
	}
	if bytes.Contains(rr.Body.Bytes(), []byte(key)) {
		t.Fatal("plaintext key leaked in listing")
	}
	list := decode[struct {
		Licenses []struct {
			KeyHint string `json:"key_hint"`
			Status  string `json:"status"`
		} `json:"licenses"`
	}](t, rr)
	if len(list.Licenses) != 1 || len(list.Licenses[0].KeyHint) != 5 || list.Licenses[0].Status != "issued" {
		t.Fatalf("listing: %+v", list)
	}

	// Redeem from the "client".
	verify := func(rr *httptest.ResponseRecorder) service.Payload {
		t.Helper()
		if rr.Code != http.StatusOK {
			t.Fatalf("client call: %d %s", rr.Code, rr.Body.String())
		}
		envl := decode[service.SignedResponse](t, rr)
		p, err := service.VerifyResponse(pub, envl)
		if err != nil {
			t.Fatalf("signature: %v", err)
		}
		return p
	}

	p := verify(e.do(t, "POST", "/v1/client/redeem", e.clientBody(app.ID, key, "device-1"), ""))
	if !p.Valid || p.Tier != "pro" || p.LicenseID != licID {
		t.Fatalf("redeem: %+v", p)
	}
	if want := e.now.Add(time.Hour).Unix(); p.ExpiresAt != want {
		t.Fatalf("redeem expiry: %d want %d", p.ExpiresAt, want)
	}

	// Validate on the same device: good. Other device: signed mismatch.
	if p := verify(e.do(t, "POST", "/v1/client/validate", e.clientBody(app.ID, key, "device-1"), "")); !p.Valid {
		t.Fatalf("validate: %+v", p)
	}
	if p := verify(e.do(t, "POST", "/v1/client/validate", e.clientBody(app.ID, key, "device-2"), "")); p.Valid || p.Reason != service.ReasonHWIDMismatch {
		t.Fatalf("second device: %+v", p)
	}

	// Ban → signed banned verdict.
	rr = e.do(t, "POST", "/v1/admin/licenses/"+licID+"/ban", map[string]string{"reason": "chargeback"}, login.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("ban: %d %s", rr.Code, rr.Body.String())
	}
	if p := verify(e.do(t, "POST", "/v1/client/validate", e.clientBody(app.ID, key, "device-1"), "")); p.Valid || p.Reason != service.ReasonBanned {
		t.Fatalf("banned validate: %+v", p)
	}

	// Stats reflect the current state: one app, one license, banned.
	rr = e.do(t, "GET", "/v1/admin/stats", nil, login.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats: %d %s", rr.Code, rr.Body.String())
	}
	stats := decode[struct {
		Applications   int64 `json:"applications"`
		Licenses       int64 `json:"licenses"`
		ActiveLicenses int64 `json:"active_licenses"`
		BannedLicenses int64 `json:"banned_licenses"`
	}](t, rr)
	if stats.Applications != 1 || stats.Licenses != 1 || stats.ActiveLicenses != 0 || stats.BannedLicenses != 1 {
		t.Fatalf("stats: %+v", stats)
	}

	// Unban → valid again.
	if rr := e.do(t, "POST", "/v1/admin/licenses/"+licID+"/unban", nil, login.Token); rr.Code != http.StatusOK {
		t.Fatalf("unban: %d", rr.Code)
	}
	if p := verify(e.do(t, "POST", "/v1/client/validate", e.clientBody(app.ID, key, "device-1"), "")); !p.Valid {
		t.Fatalf("post-unban validate: %+v", p)
	}

	// Reset HWID → device-2 can take over.
	rr = e.do(t, "POST", "/v1/admin/licenses/"+licID+"/reset-hwid", nil, login.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("reset-hwid: %d", rr.Code)
	}
	reset := decode[struct {
		HWIDBound bool `json:"hwid_bound"`
	}](t, rr)
	if reset.HWIDBound {
		t.Fatal("hwid still bound after reset")
	}
	if p := verify(e.do(t, "POST", "/v1/client/validate", e.clientBody(app.ID, key, "device-2"), "")); !p.Valid {
		t.Fatalf("rebind after reset: %+v", p)
	}
}

// TestLoginRateLimited exhausts one IP's login bucket through the full
// middleware stack. httptest gives every request the same RemoteAddr, which
// is exactly what an attacking IP looks like.
func TestLoginRateLimited(t *testing.T) {
	e := newEnv(t)
	body := map[string]string{"email": "nobody@example.com", "password": "wrong-password"}

	for i := 0; i < 5; i++ {
		if rr := e.do(t, "POST", "/v1/admin/login", body, ""); rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, rr.Code)
		}
	}
	rr := e.do(t, "POST", "/v1/admin/login", body, "")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt: got %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After header")
	}

	// The limiter must sit in front of the credential check: even correct
	// credentials get a 429 once the bucket is empty.
	if _, err := e.svc.CreateAdminUser(t.Context(), "admin@example.com", "a-long-password"); err != nil {
		t.Fatal(err)
	}
	good := map[string]string{"email": "admin@example.com", "password": "a-long-password"}
	if rr := e.do(t, "POST", "/v1/admin/login", good, ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("correct credentials bypassed the limiter: %d", rr.Code)
	}
}

// TestLogoutRevokesToken: a revoked token stops working immediately, and
// revoking is idempotent.
func TestLogoutRevokesToken(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.CreateAdminUser(t.Context(), "admin@example.com", "a-long-password"); err != nil {
		t.Fatal(err)
	}
	rr := e.do(t, "POST", "/v1/admin/login", map[string]string{
		"email": "admin@example.com", "password": "a-long-password",
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	token := decode[struct {
		Token string `json:"token"`
	}](t, rr).Token

	// Token works before logout.
	if rr := e.do(t, "GET", "/v1/admin/apps", nil, token); rr.Code != http.StatusOK {
		t.Fatalf("pre-logout list apps: %d", rr.Code)
	}

	if rr := e.do(t, "DELETE", "/v1/admin/token", nil, token); rr.Code != http.StatusNoContent {
		t.Fatalf("logout: got %d, want 204", rr.Code)
	}

	// Revoked token is dead for API calls and for logging out again.
	if rr := e.do(t, "GET", "/v1/admin/apps", nil, token); rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout list apps: got %d, want 401", rr.Code)
	}
	if rr := e.do(t, "DELETE", "/v1/admin/token", nil, token); rr.Code != http.StatusUnauthorized {
		t.Fatalf("double logout over HTTP: got %d, want 401", rr.Code)
	}

	// Service-level revocation stays idempotent (no row left to delete).
	if err := e.svc.Logout(t.Context(), token); err != nil {
		t.Fatalf("idempotent logout: %v", err)
	}
}
