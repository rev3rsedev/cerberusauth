package service_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/rev3rsedev/cerberusauth/internal/service"
	"github.com/rev3rsedev/cerberusauth/internal/store"
)

// latestAudit fetches the newest trail entries via the service, which is
// also how the HTTP layer reads them.
func latestAudit(t *testing.T, e *env, n int) []store.AuditEntry {
	t.Helper()
	entries, err := e.svc.ListAudit(e.ctx, n, 0)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	return entries
}

func TestAuditTrailForAdminActions(t *testing.T) {
	e := newEnv(t) // newEnv creates an app, so the trail starts with app.create

	entries := latestAudit(t, e, 10)
	if len(entries) != 1 || entries[0].Action != service.AuditAppCreate {
		t.Fatalf("after setup: want [app.create], got %+v", entries)
	}
	if entries[0].TargetID != e.app.ID.String() || entries[0].Detail != "Test App" {
		t.Errorf("app.create entry fields: %+v", entries[0])
	}
	if entries[0].AdminID != nil {
		t.Errorf("bootstrap-style create should have nil admin, got %v", entries[0].AdminID)
	}

	// Actor attribution flows through the context.
	actor := uuid.New()
	ctx := service.WithActor(e.ctx, actor)

	issued, err := e.svc.IssueLicenses(ctx, e.app.ID, 3, "pro", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.BanLicense(ctx, issued[0].License.ID, "chargeback"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UnbanLicense(ctx, issued[0].License.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ResetHWID(ctx, issued[0].License.ID); err != nil {
		t.Fatal(err)
	}

	entries = latestAudit(t, e, 4) // newest first
	wantActions := []string{
		service.AuditLicenseResetHWID,
		service.AuditLicenseUnban,
		service.AuditLicenseBan,
		service.AuditLicenseIssue,
	}
	for i, want := range wantActions {
		if entries[i].Action != want {
			t.Errorf("entry %d action = %q, want %q", i, entries[i].Action, want)
		}
		if entries[i].AdminID == nil || *entries[i].AdminID != actor {
			t.Errorf("entry %d actor = %v, want %v", i, entries[i].AdminID, actor)
		}
	}
	if entries[2].Detail != "chargeback" {
		t.Errorf("ban detail = %q", entries[2].Detail)
	}
	if entries[3].Detail != "3 x pro" {
		t.Errorf("issue detail = %q", entries[3].Detail)
	}
}

func TestAuditTrailForLogins(t *testing.T) {
	e := newEnv(t)
	u, err := e.svc.CreateAdminUser(e.ctx, "admin@example.com", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := e.svc.Login(e.ctx, "admin@example.com", "wrong-password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, _, err := e.svc.Login(e.ctx, "ghost@example.com", "whatever-password"); err == nil {
		t.Fatal("unknown email accepted")
	}
	if _, _, err := e.svc.Login(e.ctx, "admin@example.com", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}

	entries := latestAudit(t, e, 3) // newest first
	if entries[0].Action != service.AuditLogin {
		t.Errorf("entry 0 = %q, want admin.login", entries[0].Action)
	}
	if entries[0].AdminID == nil || *entries[0].AdminID != u.ID {
		t.Errorf("login entry actor = %v, want %v", entries[0].AdminID, u.ID)
	}
	for i := 1; i <= 2; i++ {
		if entries[i].Action != service.AuditLoginFailed {
			t.Errorf("entry %d = %q, want admin.login_failed", i, entries[i].Action)
		}
		if entries[i].AdminID != nil {
			t.Errorf("failed login must not attribute an admin, got %v", entries[i].AdminID)
		}
	}
}

func TestListAuditPagination(t *testing.T) {
	e := newEnv(t)
	actor := uuid.New()
	ctx := service.WithActor(e.ctx, actor)
	for i := 0; i < 5; i++ {
		if _, err := e.svc.IssueLicenses(ctx, e.app.ID, 1, "pro", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	// 6 entries total (app.create + 5 issues).
	page, err := e.svc.ListAudit(e.ctx, 2, 0)
	if err != nil || len(page) != 2 {
		t.Fatalf("page 1: %d entries, err %v", len(page), err)
	}
	rest, err := e.svc.ListAudit(e.ctx, 100, 4)
	if err != nil || len(rest) != 2 {
		t.Fatalf("offset page: %d entries, err %v", len(rest), err)
	}
	if rest[len(rest)-1].Action != service.AuditAppCreate {
		t.Errorf("oldest entry = %q, want app.create", rest[len(rest)-1].Action)
	}
}
