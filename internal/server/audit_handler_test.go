package server_test

import (
	"net/http"
	"testing"
	"time"
)

// TestAuditEndpoint drives the trail through HTTP: admin actions land in
// GET /v1/admin/audit newest-first, attributed to the token's admin.
func TestAuditEndpoint(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, err := e.svc.CreateAdminUser(ctx, "admin@example.com", "a-long-password"); err != nil {
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

	if rr := e.do(t, "POST", "/v1/admin/apps", map[string]string{"name": "Audited App"}, token); rr.Code != http.StatusCreated {
		t.Fatalf("create app: %d %s", rr.Code, rr.Body.String())
	}

	// The endpoint requires auth like every admin route.
	if rr := e.do(t, "GET", "/v1/admin/audit", nil, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated audit read: %d", rr.Code)
	}

	rr = e.do(t, "GET", "/v1/admin/audit?limit=2", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("audit list: %d %s", rr.Code, rr.Body.String())
	}
	resp := decode[struct {
		Entries []struct {
			ID      int64     `json:"id"`
			At      time.Time `json:"at"`
			AdminID *string   `json:"admin_id"`
			Action  string    `json:"action"`
			Detail  string    `json:"detail"`
		} `json:"entries"`
	}](t, rr)

	if len(resp.Entries) != 2 {
		t.Fatalf("entries = %d, want 2 (app.create + admin.login)", len(resp.Entries))
	}
	if resp.Entries[0].Action != "app.create" || resp.Entries[0].Detail != "Audited App" {
		t.Errorf("newest entry: %+v", resp.Entries[0])
	}
	if resp.Entries[0].AdminID == nil {
		t.Error("app.create over HTTP must carry the acting admin")
	}
	if resp.Entries[1].Action != "admin.login" {
		t.Errorf("second entry: %+v", resp.Entries[1])
	}
}
