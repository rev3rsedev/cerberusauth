package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposition(t *testing.T) {
	m := NewMetrics("1.0.0-test")
	m.ObserveRequest("/v1/client/validate", 200, 30*time.Millisecond)
	m.ObserveRequest("/v1/client/validate", 200, 10*time.Millisecond)
	m.ObserveRequest("/v1/admin/apps", 401, time.Millisecond)
	m.ObserveRequest("/v1/client/apps/xyz/pubkey", 200, time.Millisecond)
	m.ObserveVerdict("validate", "valid")
	m.ObserveVerdict("validate", "banned")
	m.ObserveVerdict("redeem", "valid")

	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

	body := rr.Body.String()
	for _, want := range []string{
		`cerberus_http_requests_total{endpoint="client_validate",code="200"} 2`,
		`cerberus_http_requests_total{endpoint="admin",code="401"} 1`,
		`cerberus_http_requests_total{endpoint="client_pubkey",code="200"} 1`,
		`cerberus_http_request_duration_seconds_sum{endpoint="client_validate"} 0.040000`,
		`cerberus_http_request_duration_seconds_count{endpoint="client_validate"} 2`,
		`cerberus_verdicts_total{endpoint="validate",result="valid"} 1`,
		`cerberus_verdicts_total{endpoint="validate",result="banned"} 1`,
		`cerberus_verdicts_total{endpoint="redeem",result="valid"} 1`,
		`cerberus_build_info{version="1.0.0-test"} 1`,
		`cerberus_uptime_seconds`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q\n%s", want, body)
		}
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain; version=0.0.4") {
		t.Errorf("content type = %q", got)
	}
}

// TestMetricsNilSafe: a Server without WithMetrics must observe into nil
// without panicking; the middleware calls unconditionally.
func TestMetricsNilSafe(t *testing.T) {
	var m *Metrics
	m.ObserveRequest("/v1/client/validate", 200, time.Millisecond)
	m.ObserveVerdict("validate", "valid")
}

func TestEndpointLabelCardinality(t *testing.T) {
	cases := map[string]string{
		"/v1/client/validate":                   "client_validate",
		"/v1/client/redeem":                     "client_redeem",
		"/v1/client/apps/123/pubkey":            "client_pubkey",
		"/v1/admin/apps":                        "admin",
		"/v1/admin/licenses/xyz/ban":            "admin",
		"/healthz":                              "healthz",
		"/":                                     "other",
		"/anything/../weird/path/whatsoever/42": "other",
	}
	for path, want := range cases {
		if got := endpointLabel(path); got != want {
			t.Errorf("endpointLabel(%q) = %q, want %q", path, got, want)
		}
	}
}
