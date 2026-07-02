// Package client is the Go SDK for the CerberusAuth client protocol. It
// wraps the redeem and validate endpoints and performs the verification
// steps every client must do before trusting an answer:
//
//  1. generate a random nonce and stamp the current time
//  2. POST the request
//  3. verify the Ed25519 signature over the exact payload bytes
//  4. only then parse the JSON
//  5. check the echoed nonce equals the one just sent
//  6. hand the verdict to the caller
//
// The public key is pinned at construction time, from your app's creation
// response or GET /v1/client/apps/{id}/pubkey. Ship it inside your binary;
// fetching it at runtime over the connection you are trying to distrust
// would defeat the point.
//
// # Errors versus denials
//
// A signed "no" is a real answer: Validate and Redeem return a Verdict with
// Valid == false and a nil error when the server rejects the license. An
// error return means no trustworthy answer exists at all (network failure,
// non-200 status, bad signature, replayed nonce), and the caller must fail
// closed: keep the app locked, retry later.
//
// # Clock skew
//
// The server rejects requests whose timestamp drifts past its accepted
// skew, with a signed stale_timestamp verdict that carries the server
// clock. Since that response is signed and bound to our nonce, the Client
// trusts it, learns the offset, and retries once. Machines with a wildly
// wrong clock therefore still validate; callers see ReasonStaleTimestamp
// only when the corrected retry is rejected too.
//
// # Offline grace period
//
// The SDK stays stateless on purpose; caching policy belongs to the app.
// The supported pattern: after a Valid verdict, persist Verdict.Envelope.
// When the server is unreachable (an error, never a signed denial), load
// the stored envelope, re-verify it with VerifyStored, and accept it if
// ServerTime is recent enough for your taste. A signed denial always
// overrides the cache: delete the stored envelope on any Valid == false
// verdict. See the package example.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// envelope is the wire shape of a signed response. It carries no plaintext
// copy of the payload: verify first, then decode.
type envelope struct {
	Alg       string `json:"alg"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// payload mirrors the server's signed unit. Only fields the SDK consumes
// are listed; unknown fields in future minor versions are ignored.
type payload struct {
	V         int    `json:"v"`
	Valid     bool   `json:"valid"`
	Reason    string `json:"reason"`
	AppID     string `json:"app_id"`
	LicenseID string `json:"license_id"`
	Tier      string `json:"tier"`
	ExpiresAt int64  `json:"expires_at"`
	HWID      string `json:"hwid"`
	Nonce     string `json:"nonce"`
	ClientTS  int64  `json:"client_ts"`
	ServerTS  int64  `json:"server_ts"`
}

type request struct {
	AppID      string `json:"app_id"`
	LicenseKey string `json:"license_key"`
	HWID       string `json:"hwid"`
	Nonce      string `json:"nonce"`
	Timestamp  int64  `json:"timestamp"`
}

// Client talks to one CerberusAuth server about one application, verifying
// every response against the pinned public key. It is safe for concurrent
// use. Use it by pointer; the zero value is not functional.
type Client struct {
	baseURL string
	appID   string
	pub     ed25519.PublicKey
	httpc   *http.Client
	now     func() time.Time

	// offset is added to the local clock when stamping requests, learned
	// from signed stale_timestamp verdicts. See the package doc.
	offset atomic.Int64
}

// Option adjusts a Client at construction time.
type Option func(*Client)

// WithHTTPClient replaces the default HTTP client (15 second timeout).
// Bring your own for proxies, custom TLS or different timeouts.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpc = h }
}

// New builds a Client for one application. baseURL is the server root,
// like "https://auth.example.com"; appID is the application UUID; publicKey
// is the app's base64 Ed25519 verification key, pinned from app creation.
func New(baseURL, appID, publicKey string, opts ...Option) (*Client, error) {
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("client: public key must be a base64 32-byte Ed25519 key")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("client: base URL must be absolute, like https://auth.example.com")
	}
	if appID == "" {
		return nil, errors.New("client: app ID is required")
	}
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		appID:   appID,
		pub:     ed25519.PublicKey(pub),
		httpc:   &http.Client{Timeout: 15 * time.Second},
		now:     time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Validate asks whether the license is good for this device right now.
// hwid is any stable device identifier you choose; the server only ever
// sees and stores its hash.
func (c *Client) Validate(ctx context.Context, licenseKey, hwid string) (*Verdict, error) {
	return c.call(ctx, "/v1/client/validate", licenseKey, hwid)
}

// Redeem activates an issued license on this device: binds the hwid and
// starts the expiry clock. Redeeming an already-active license with the
// same hwid succeeds, so retrying after a lost response is safe.
func (c *Client) Redeem(ctx context.Context, licenseKey, hwid string) (*Verdict, error) {
	return c.call(ctx, "/v1/client/redeem", licenseKey, hwid)
}

// VerifyStored re-verifies a previously persisted Verdict.Envelope: same
// signature and version checks as a live call, minus the nonce echo, which
// only makes sense for a response just requested. The caller owns
// freshness: check ServerTime against the grace period the app allows.
// Never feed this anything but envelopes this program stored itself.
func (c *Client) VerifyStored(envelopeJSON []byte) (*Verdict, error) {
	return c.verify(envelopeJSON, "")
}

func (c *Client) call(ctx context.Context, path, licenseKey, hwid string) (*Verdict, error) {
	if licenseKey == "" {
		return nil, errors.New("client: license key is required")
	}
	if hwid == "" {
		return nil, errors.New("client: hwid is required")
	}
	v, err := c.once(ctx, path, licenseKey, hwid)
	if err != nil || v.Valid || v.Reason != ReasonStaleTimestamp {
		return v, err
	}
	// Our clock is off by more than the server tolerates. The rejection is
	// signed and bound to our nonce, so its server time is trustworthy:
	// learn the offset and retry once. Safe for redeem too, the server's
	// skew check runs before any state change.
	c.offset.Store(v.ServerTime.Unix() - c.now().Unix())
	return c.once(ctx, path, licenseKey, hwid)
}

func (c *Client) once(ctx context.Context, path, licenseKey, hwid string) (*Verdict, error) {
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(request{
		AppID:      c.appID,
		LicenseKey: licenseKey,
		HWID:       hwid,
		Nonce:      nonce,
		Timestamp:  c.now().Unix() + c.offset.Load(),
	})
	if err != nil {
		return nil, fmt.Errorf("client: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("client: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{StatusCode: resp.StatusCode, Message: apiMessage(raw)}
	}
	return c.verify(raw, nonce)
}

// verify runs the mandatory sequence on a signed envelope: signature over
// the exact payload bytes first, JSON second, then the echo checks. An
// empty wantNonce skips the echo check (stored envelopes only).
func (c *Client) verify(envelopeJSON []byte, wantNonce string) (*Verdict, error) {
	var env envelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("client: malformed envelope: %w", err)
	}
	if env.Alg != "ed25519" {
		return nil, fmt.Errorf("client: unsupported signature algorithm %q", env.Alg)
	}
	rawPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, ErrBadSignature
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, ErrBadSignature
	}
	if !ed25519.Verify(c.pub, rawPayload, sig) {
		return nil, ErrBadSignature
	}

	var p payload
	if err := json.Unmarshal(rawPayload, &p); err != nil {
		return nil, fmt.Errorf("client: parse verified payload: %w", err)
	}
	if p.V != 1 {
		return nil, fmt.Errorf("client: unsupported payload version %d, update the SDK", p.V)
	}
	if p.AppID != c.appID {
		return nil, fmt.Errorf("client: response is about app %s, expected %s", p.AppID, c.appID)
	}
	if wantNonce != "" && p.Nonce != wantNonce {
		return nil, ErrReplayedResponse
	}

	v := &Verdict{
		Valid:      p.Valid,
		Reason:     Reason(p.Reason),
		LicenseID:  p.LicenseID,
		Tier:       p.Tier,
		ServerTime: time.Unix(p.ServerTS, 0).UTC(),
		KeyID:      env.KeyID,
		Envelope:   envelopeJSON,
	}
	if p.ExpiresAt > 0 {
		v.ExpiresAt = time.Unix(p.ExpiresAt, 0).UTC()
	}
	return v, nil
}

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("client: generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// apiMessage extracts the server's {"error": "..."} body, falling back to
// the raw text, truncated so a misconfigured proxy cannot flood the error.
func apiMessage(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return e.Error
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
