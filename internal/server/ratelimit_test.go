package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPLimiterBurstThenRefill(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	l := newIPLimiter(5, 10*time.Second, func() time.Time { return now })

	for i := 0; i < 5; i++ {
		if ok, _ := l.allow("1.2.3.4"); !ok {
			t.Fatalf("attempt %d within burst denied", i+1)
		}
	}
	ok, retryAfter := l.allow("1.2.3.4")
	if ok {
		t.Fatal("6th immediate attempt allowed")
	}
	if retryAfter <= 0 || retryAfter > 10*time.Second {
		t.Fatalf("retryAfter = %v, want in (0, 10s]", retryAfter)
	}

	// Another key is an independent bucket.
	if ok, _ := l.allow("5.6.7.8"); !ok {
		t.Fatal("distinct IP shares the exhausted bucket")
	}

	// One refill interval later exactly one attempt exists again.
	now = now.Add(10 * time.Second)
	if ok, _ := l.allow("1.2.3.4"); !ok {
		t.Fatal("attempt after a full refill interval denied")
	}
	if ok, _ := l.allow("1.2.3.4"); ok {
		t.Fatal("second attempt after a single refill interval allowed")
	}
}

func TestIPLimiterRefillCapsAtBurst(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	l := newIPLimiter(5, 10*time.Second, func() time.Time { return now })

	l.allow("1.2.3.4")
	now = now.Add(time.Hour) // far more than 5 tokens' worth
	for i := 0; i < 5; i++ {
		if ok, _ := l.allow("1.2.3.4"); !ok {
			t.Fatalf("attempt %d after long idle denied", i+1)
		}
	}
	if ok, _ := l.allow("1.2.3.4"); ok {
		t.Fatal("bucket refilled beyond burst")
	}
}

func TestIPLimiterSweepDropsIdleBuckets(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	l := newIPLimiter(5, 10*time.Second, func() time.Time { return now })

	l.allow("1.2.3.4")
	l.allow("5.6.7.8")
	if len(l.buckets) != 2 {
		t.Fatalf("bucket count = %d, want 2", len(l.buckets))
	}

	// Past the sweep interval and past full refill for both entries.
	now = now.Add(limiterSweepEvery + time.Minute)
	l.allow("9.9.9.9")
	if len(l.buckets) != 1 {
		t.Fatalf("bucket count after sweep = %d, want 1 (only the fresh key)", len(l.buckets))
	}
	if l.buckets["9.9.9.9"] == nil {
		t.Fatal("sweep evicted the fresh bucket")
	}
}

func TestClientRateLimitMiddleware(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(nil, log, WithClientRateLimit(2, time.Minute))

	called := 0
	h := s.withClientRateLimit(func(w http.ResponseWriter, r *http.Request) { called++ })
	post := func(ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/client/validate", nil)
		req.RemoteAddr = ip + ":4444"
		rr := httptest.NewRecorder()
		h(rr, req)
		return rr
	}

	for i := 0; i < 2; i++ {
		if rr := post("10.0.0.1"); rr.Code != http.StatusOK {
			t.Fatalf("request %d within burst: HTTP %d", i+1, rr.Code)
		}
	}
	rr := post("10.0.0.1")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("over burst: HTTP %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	if called != 2 {
		t.Errorf("handler ran %d times, want 2", called)
	}

	// Another IP has its own bucket.
	if rr := post("10.0.0.2"); rr.Code != http.StatusOK {
		t.Fatalf("distinct IP limited: HTTP %d", rr.Code)
	}
}

func TestClientRateLimitDisabled(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for name, s := range map[string]*Server{
		"no option":  New(nil, log),
		"burst zero": New(nil, log, WithClientRateLimit(0, time.Second)),
	} {
		if s.clientLimiter != nil {
			t.Fatalf("%s: limiter unexpectedly enabled", name)
		}
		h := s.withClientRateLimit(func(w http.ResponseWriter, r *http.Request) {})
		req := httptest.NewRequest(http.MethodPost, "/v1/client/validate", nil)
		req.RemoteAddr = "10.0.0.1:4444"
		for i := 0; i < 100; i++ {
			rr := httptest.NewRecorder()
			h(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("%s: request %d: HTTP %d", name, i+1, rr.Code)
			}
		}
	}
}

func TestClientIP(t *testing.T) {
	r := &http.Request{RemoteAddr: "10.0.0.7:5555"}
	if got := clientIP(r); got != "10.0.0.7" {
		t.Fatalf("clientIP = %q, want 10.0.0.7", got)
	}
	r.RemoteAddr = "[::1]:5555"
	if got := clientIP(r); got != "::1" {
		t.Fatalf("clientIP v6 = %q, want ::1", got)
	}
	r.RemoteAddr = "no-port"
	if got := clientIP(r); got != "no-port" {
		t.Fatalf("clientIP fallback = %q, want no-port", got)
	}
}
