package dashboard

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
	return rr
}

func TestServesShell(t *testing.T) {
	rr := get(t, "/")
	if rr.Code != 200 {
		t.Fatalf("/: HTTP %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "<title>CerberusAuth</title>") {
		t.Error("index.html not served at /")
	}
	if csp := rr.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing or weak: %q", csp)
	}

	for path, marker := range map[string]string{
		"/app.js":    "CerberusAuth dashboard",
		"/style.css": "--accent",
	} {
		rr := get(t, path)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), marker) {
			t.Errorf("%s: HTTP %d, marker %q missing", path, rr.Code, marker)
		}
	}
}

func TestUnknownPathIs404(t *testing.T) {
	// The server only mounts explicit routes, but the handler itself must
	// not invent files either.
	if rr := get(t, "/secret.txt"); rr.Code != 404 {
		t.Fatalf("unknown file: HTTP %d, want 404", rr.Code)
	}
	if rr := get(t, "/static/index.html"); rr.Code != 404 {
		t.Fatalf("double-prefixed path: HTTP %d, want 404", rr.Code)
	}
}
