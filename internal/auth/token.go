package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// tokenPrefix makes admin tokens greppable in leaked logs and secret
// scanners ("cba" = CerberusAuth bearer admin).
const tokenPrefix = "cba_"

// NewToken returns a fresh admin bearer token: prefix + 256 bits of
// crypto/rand, URL-safe base64. Only its SHA-256 is stored.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: token: %w", err)
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken maps a bearer token to its storage/lookup form.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// HashEmail maps an email to its storage/lookup form: HMAC-SHA-256 keyed
// with a pepper (derived from the master key via signing.DeriveKeys) over
// the trimmed, lowercased address. A plain unsalted hash would let anyone
// with a database dump enumerate addresses offline; the HMAC requires the
// pepper, which never leaves the process. Trade-off: emails can be matched
// at login but never displayed.
func HashEmail(pepper []byte, email string) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	return mac.Sum(nil)
}
