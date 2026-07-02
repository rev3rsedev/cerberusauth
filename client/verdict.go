package client

import (
	"errors"
	"fmt"
	"time"
)

// Reason classifies why a verdict came back invalid. The strings are part
// of the server's API contract and stable across versions; switch on the
// constants, not on prose.
type Reason string

const (
	// ReasonInvalidKey: the key does not exist for this app or is not a
	// well-formed license key.
	ReasonInvalidKey Reason = "invalid_key"
	// ReasonNotRedeemed: the key exists but was never activated. Call
	// Redeem first.
	ReasonNotRedeemed Reason = "not_redeemed"
	// ReasonBanned: the license was banned by an admin.
	ReasonBanned Reason = "banned"
	// ReasonExpired: the license was valid once and has run out.
	ReasonExpired Reason = "expired"
	// ReasonHWIDMismatch: the license is bound to a different device.
	ReasonHWIDMismatch Reason = "hwid_mismatch"
	// ReasonStaleTimestamp: the request timestamp fell outside the server's
	// accepted clock skew. The Client corrects its clock offset from the
	// signed response and retries once on its own, so callers only see this
	// when the retry was rejected too.
	ReasonStaleTimestamp Reason = "stale_timestamp"
)

// Verdict is a verified license decision: the signature checked out and,
// for online calls, the nonce echo matched. A Verdict with Valid == false
// is an authoritative, server-signed denial, not an error.
type Verdict struct {
	Valid  bool
	Reason Reason // set when Valid is false

	LicenseID string
	Tier      string
	// ExpiresAt is the UTC expiry instant; the zero time means the license
	// is perpetual.
	ExpiresAt time.Time

	// ServerTime is the server clock at signing time, useful for judging
	// the age of stored verdicts.
	ServerTime time.Time
	// KeyID fingerprints the signing key (relevant once keys rotate).
	KeyID string

	// Envelope is the raw signed response exactly as received. Persist it
	// if you want an offline grace period: VerifyStored re-checks the
	// signature at load time, so a tampered cache file fails closed.
	Envelope []byte
}

var (
	// ErrBadSignature means the response failed Ed25519 verification: it is
	// forged, tampered with, or signed by a key other than the pinned one.
	// Treat the license as invalid; do not retry with relaxed checks.
	ErrBadSignature = errors.New("client: signature verification failed")

	// ErrReplayedResponse means the signature was fine but the echoed nonce
	// is not the one just sent: a recorded response is being replayed, or a
	// proxy answered with someone else's verdict. Treat as invalid.
	ErrReplayedResponse = errors.New("client: nonce mismatch, response replayed or answers a different request")
)

// APIError is an unsigned transport-level failure, any HTTP status other
// than 200. It is never a license verdict: verdicts, including denials,
// arrive signed with status 200. Fail closed and retry later.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("client: server returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("client: server returned HTTP %d: %s", e.StatusCode, e.Message)
}
