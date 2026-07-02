package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"crypto/ed25519"

	"github.com/rev3rsedev/cerberusauth/internal/signing"
)

// Failure reasons carried in signed payloads. Stable strings: clients
// switch on them, so changing one is a breaking API change.
const (
	ReasonInvalidKey     = "invalid_key"
	ReasonNotRedeemed    = "not_redeemed"
	ReasonBanned         = "banned"
	ReasonExpired        = "expired"
	ReasonHWIDMismatch   = "hwid_mismatch"
	ReasonStaleTimestamp = "stale_timestamp"
)

// Payload is the unit that gets signed. The exact bytes produced by
// json.Marshal on this struct are signed and transported verbatim
// (base64); clients verify those bytes, then parse them. Field order is
// fixed by the struct; there is no canonicalization step.
type Payload struct {
	V     int  `json:"v"`
	Valid bool `json:"valid"`
	// Reason is set when Valid is false; see the Reason* constants.
	Reason string `json:"reason,omitempty"`

	AppID     string `json:"app_id"`
	LicenseID string `json:"license_id,omitempty"`
	Tier      string `json:"tier,omitempty"`
	// ExpiresAt is unix seconds; absent means perpetual.
	ExpiresAt int64 `json:"expires_at,omitempty"`

	// HWID, Nonce and ClientTS echo the request so the client can bind
	// this response to the exact call it made (replay protection lives
	// client-side: check the nonce matches the one you just sent).
	HWID     string `json:"hwid,omitempty"`
	Nonce    string `json:"nonce"`
	ClientTS int64  `json:"client_ts"`
	ServerTS int64  `json:"server_ts"`
}

// SignedResponse is the wire envelope for client endpoints. It carries no
// plaintext copy of the payload on purpose: verify first, then decode.
type SignedResponse struct {
	Alg       string `json:"alg"`       // always "ed25519" in v0.1
	KeyID     string `json:"key_id"`    // fingerprint of the signing key
	Payload   string `json:"payload"`   // base64(signed JSON bytes)
	Signature string `json:"signature"` // base64(Ed25519 signature)
}

var ErrBadSignature = errors.New("service: signature verification failed")

// VerifyResponse is the client-side half of the protocol: it checks the
// signature over the raw payload bytes and only then parses them. Reference
// behavior for SDKs (TODO v0.2); used by our own tests.
func VerifyResponse(pub ed25519.PublicKey, resp SignedResponse) (Payload, error) {
	raw, err := base64.StdEncoding.DecodeString(resp.Payload)
	if err != nil {
		return Payload{}, ErrBadSignature
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return Payload{}, ErrBadSignature
	}
	if !signing.Verify(pub, raw, sig) {
		return Payload{}, ErrBadSignature
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Payload{}, err
	}
	return p, nil
}
