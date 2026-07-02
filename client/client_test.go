package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testAppID = "6c9028f8-11a1-4e5e-9f30-1d2c3b4a5968"

func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signEnvelope(t *testing.T, priv ed25519.PrivateKey, p payload) envelope {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return envelope{
		Alg:       "ed25519",
		KeyID:     "testkey",
		Payload:   base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)),
	}
}

// capture records what the fake server saw, for asserting on paths and
// request contents.
type capture struct {
	mu    sync.Mutex
	reqs  []request
	paths []string
}

func (c *capture) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reqs)
}

// verdictServer decodes each request, records it, and answers with a signed
// payload built by f.
func verdictServer(t *testing.T, cap *capture, priv ed25519.PrivateKey, f func(request) payload) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if cap != nil {
			cap.mu.Lock()
			cap.reqs = append(cap.reqs, req)
			cap.paths = append(cap.paths, r.URL.Path)
			cap.mu.Unlock()
		}
		if err := json.NewEncoder(w).Encode(signEnvelope(t, priv, f(req))); err != nil {
			t.Errorf("encode envelope: %v", err)
		}
	}))
}

// okPayload echoes a request back as a valid verdict, the way the real
// server does.
func okPayload(req request) payload {
	return payload{
		V:         1,
		Valid:     true,
		AppID:     req.AppID,
		LicenseID: "lic-1",
		Tier:      "pro",
		HWID:      req.HWID,
		Nonce:     req.Nonce,
		ClientTS:  req.Timestamp,
		ServerTS:  time.Now().Unix(),
	}
}

func newTestClient(t *testing.T, url string, pub ed25519.PublicKey, opts ...Option) *Client {
	t.Helper()
	c, err := New(url, testAppID, base64.StdEncoding.EncodeToString(pub), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidateHappyPath(t *testing.T) {
	pub, priv := testKeypair(t)
	expiry := time.Now().Add(time.Hour).Unix()
	cap := &capture{}
	ts := verdictServer(t, cap, priv, func(req request) payload {
		p := okPayload(req)
		p.ExpiresAt = expiry
		return p
	})
	defer ts.Close()

	// Trailing slash on the base URL must not produce a double-slash path.
	c := newTestClient(t, ts.URL+"/", pub)
	v, err := c.Validate(context.Background(), "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid || v.Reason != "" {
		t.Fatalf("want valid verdict, got %+v", v)
	}
	if v.LicenseID != "lic-1" || v.Tier != "pro" || v.KeyID != "testkey" {
		t.Errorf("verdict fields wrong: %+v", v)
	}
	if v.ExpiresAt.Unix() != expiry {
		t.Errorf("expiry = %v, want unix %d", v.ExpiresAt, expiry)
	}
	if len(v.Envelope) == 0 {
		t.Error("envelope not retained")
	}
	if got := cap.paths[0]; got != "/v1/client/validate" {
		t.Errorf("path = %q", got)
	}
	req := cap.reqs[0]
	if req.AppID != testAppID || req.LicenseKey != "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE" || req.HWID != "device-1" {
		t.Errorf("request fields wrong: %+v", req)
	}
	if len(req.Nonce) != 32 {
		t.Errorf("nonce length = %d, want 32 hex chars", len(req.Nonce))
	}
	if drift := time.Now().Unix() - req.Timestamp; drift < -2 || drift > 2 {
		t.Errorf("timestamp drift %d s", drift)
	}
}

func TestRedeemUsesRedeemPath(t *testing.T) {
	pub, priv := testKeypair(t)
	cap := &capture{}
	ts := verdictServer(t, cap, priv, okPayload)
	defer ts.Close()

	c := newTestClient(t, ts.URL, pub)
	if _, err := c.Redeem(context.Background(), "KEY", "device-1"); err != nil {
		t.Fatal(err)
	}
	if got := cap.paths[0]; got != "/v1/client/redeem" {
		t.Errorf("path = %q", got)
	}
}

func TestSignedDenialIsNotAnError(t *testing.T) {
	pub, priv := testKeypair(t)
	ts := verdictServer(t, nil, priv, func(req request) payload {
		p := okPayload(req)
		p.Valid = false
		p.Reason = string(ReasonBanned)
		return p
	})
	defer ts.Close()

	v, err := newTestClient(t, ts.URL, pub).Validate(context.Background(), "KEY", "device-1")
	if err != nil {
		t.Fatalf("signed denial must not be an error, got %v", err)
	}
	if v.Valid || v.Reason != ReasonBanned {
		t.Fatalf("want banned denial, got %+v", v)
	}
}

func TestForgedSignatureRejected(t *testing.T) {
	pub, _ := testKeypair(t)
	_, otherPriv := testKeypair(t)
	ts := verdictServer(t, nil, otherPriv, okPayload)
	defer ts.Close()

	_, err := newTestClient(t, ts.URL, pub).Validate(context.Background(), "KEY", "device-1")
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	pub, priv := testKeypair(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		_ = json.NewDecoder(r.Body).Decode(&req)
		env := signEnvelope(t, priv, okPayload(req))
		// Flip the verdict after signing; the signature no longer matches.
		raw, _ := base64.StdEncoding.DecodeString(env.Payload)
		tampered := strings.Replace(string(raw), `"valid":true`, `"valid":false`, 1)
		env.Payload = base64.StdEncoding.EncodeToString([]byte(tampered))
		_ = json.NewEncoder(w).Encode(env)
	}))
	defer ts.Close()

	_, err := newTestClient(t, ts.URL, pub).Validate(context.Background(), "KEY", "device-1")
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestReplayedResponseRejected(t *testing.T) {
	pub, priv := testKeypair(t)
	ts := verdictServer(t, nil, priv, func(req request) payload {
		p := okPayload(req)
		p.Nonce = "aaaaaaaaaaaaaaaa" // signed fine, but not the nonce we sent
		return p
	})
	defer ts.Close()

	_, err := newTestClient(t, ts.URL, pub).Validate(context.Background(), "KEY", "device-1")
	if !errors.Is(err, ErrReplayedResponse) {
		t.Fatalf("want ErrReplayedResponse, got %v", err)
	}
}

func TestWrongAppRejected(t *testing.T) {
	pub, priv := testKeypair(t)
	ts := verdictServer(t, nil, priv, func(req request) payload {
		p := okPayload(req)
		p.AppID = "someone-elses-app"
		return p
	})
	defer ts.Close()

	_, err := newTestClient(t, ts.URL, pub).Validate(context.Background(), "KEY", "device-1")
	if err == nil || !strings.Contains(err.Error(), "about app") {
		t.Fatalf("want app mismatch error, got %v", err)
	}
}

func TestTransportErrorFailsClosed(t *testing.T) {
	pub, _ := testKeypair(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"application not found"}`))
	}))
	defer ts.Close()

	_, err := newTestClient(t, ts.URL, pub).Validate(context.Background(), "KEY", "device-1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %v", err)
	}
	if apiErr.StatusCode != http.StatusNotFound || apiErr.Message != "application not found" {
		t.Errorf("apiErr = %+v", apiErr)
	}
}

func TestSkewCorrectionRetriesOnce(t *testing.T) {
	pub, priv := testKeypair(t)
	base := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	serverNow := base.Add(time.Hour) // server is an hour ahead of us
	const skew = 5 * time.Minute

	cap := &capture{}
	ts := verdictServer(t, cap, priv, func(req request) payload {
		p := okPayload(req)
		p.ServerTS = serverNow.Unix()
		drift := serverNow.Unix() - req.Timestamp
		if drift < 0 {
			drift = -drift
		}
		if time.Duration(drift)*time.Second > skew {
			p.Valid = false
			p.Reason = string(ReasonStaleTimestamp)
		}
		return p
	})
	defer ts.Close()

	c := newTestClient(t, ts.URL, pub)
	c.now = func() time.Time { return base }

	v, err := c.Validate(context.Background(), "KEY", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid {
		t.Fatalf("want valid after skew retry, got %+v", v)
	}
	if cap.len() != 2 {
		t.Fatalf("want 2 requests (original + retry), got %d", cap.len())
	}
	if got := cap.reqs[1].Timestamp; got != serverNow.Unix() {
		t.Errorf("retry timestamp = %d, want server clock %d", got, serverNow.Unix())
	}

	// The learned offset sticks: the next call is right on the first try.
	if _, err := c.Validate(context.Background(), "KEY", "device-1"); err != nil {
		t.Fatal(err)
	}
	if cap.len() != 3 {
		t.Fatalf("want 3 requests total, got %d", cap.len())
	}
}

func TestStaleAfterRetryReturnsVerdict(t *testing.T) {
	pub, priv := testKeypair(t)
	cap := &capture{}
	ts := verdictServer(t, cap, priv, func(req request) payload {
		p := okPayload(req)
		p.Valid = false
		p.Reason = string(ReasonStaleTimestamp)
		return p
	})
	defer ts.Close()

	v, err := newTestClient(t, ts.URL, pub).Validate(context.Background(), "KEY", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if v.Valid || v.Reason != ReasonStaleTimestamp {
		t.Fatalf("want stale verdict, got %+v", v)
	}
	if cap.len() != 2 {
		t.Fatalf("want exactly one retry, got %d requests", cap.len())
	}
}

func TestUnsupportedVersionRejected(t *testing.T) {
	pub, priv := testKeypair(t)
	ts := verdictServer(t, nil, priv, func(req request) payload {
		p := okPayload(req)
		p.V = 2
		return p
	})
	defer ts.Close()

	_, err := newTestClient(t, ts.URL, pub).Validate(context.Background(), "KEY", "device-1")
	if err == nil || !strings.Contains(err.Error(), "unsupported payload version") {
		t.Fatalf("want version error, got %v", err)
	}
}

func TestUnsupportedAlgorithmRejected(t *testing.T) {
	pub, priv := testKeypair(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		_ = json.NewDecoder(r.Body).Decode(&req)
		env := signEnvelope(t, priv, okPayload(req))
		env.Alg = "rsa-pss"
		_ = json.NewEncoder(w).Encode(env)
	}))
	defer ts.Close()

	_, err := newTestClient(t, ts.URL, pub).Validate(context.Background(), "KEY", "device-1")
	if err == nil || !strings.Contains(err.Error(), "unsupported signature algorithm") {
		t.Fatalf("want algorithm error, got %v", err)
	}
}

func TestVerifyStored(t *testing.T) {
	pub, priv := testKeypair(t)
	ts := verdictServer(t, nil, priv, okPayload)
	defer ts.Close()

	c := newTestClient(t, ts.URL, pub)
	live, err := c.Validate(context.Background(), "KEY", "device-1")
	if err != nil {
		t.Fatal(err)
	}

	// A stored envelope verifies again, without the nonce echo check.
	stored, err := c.VerifyStored(live.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Valid || stored.LicenseID != live.LicenseID {
		t.Fatalf("stored verdict differs: %+v", stored)
	}

	// A tampered stored envelope fails closed.
	var env envelope
	if err := json.Unmarshal(live.Envelope, &env); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(env.Payload)
	raw[0] ^= 0xFF
	env.Payload = base64.StdEncoding.EncodeToString(raw)
	tampered, _ := json.Marshal(env)
	if _, err := c.VerifyStored(tampered); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature for tampered cache, got %v", err)
	}
}

func TestPerpetualLicenseHasZeroExpiry(t *testing.T) {
	pub, priv := testKeypair(t)
	ts := verdictServer(t, nil, priv, okPayload) // okPayload sets no expiry
	defer ts.Close()

	v, err := newTestClient(t, ts.URL, pub).Validate(context.Background(), "KEY", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if !v.ExpiresAt.IsZero() {
		t.Fatalf("perpetual license must have zero ExpiresAt, got %v", v.ExpiresAt)
	}
}

func TestNewRejectsBadInputs(t *testing.T) {
	pub, _ := testKeypair(t)
	goodKey := base64.StdEncoding.EncodeToString(pub)
	cases := []struct {
		name               string
		url, appID, pubkey string
	}{
		{"not base64", "http://localhost:8080", testAppID, "not-base64!!"},
		{"wrong key size", "http://localhost:8080", testAppID, base64.StdEncoding.EncodeToString([]byte("short"))},
		{"empty app id", "http://localhost:8080", "", goodKey},
		{"relative url", "localhost:8080", testAppID, goodKey},
		{"empty url", "", testAppID, goodKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.url, tc.appID, tc.pubkey); err == nil {
				t.Fatal("want constructor error")
			}
		})
	}
}

func TestEmptyArgumentsRejectedLocally(t *testing.T) {
	pub, _ := testKeypair(t)
	c := newTestClient(t, "http://127.0.0.1:1", pub) // nothing listens; must not be reached
	if _, err := c.Validate(context.Background(), "", "device-1"); err == nil {
		t.Error("want error for empty license key")
	}
	if _, err := c.Validate(context.Background(), "KEY", ""); err == nil {
		t.Error("want error for empty hwid")
	}
}
