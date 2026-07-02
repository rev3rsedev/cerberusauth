// Package license generates and canonicalizes license keys.
//
// Keys are 25 characters drawn from the Crockford base32 alphabet (no
// I/L/O/U to avoid transcription errors), grouped for humans as
// XXXXX-XXXXX-XXXXX-XXXXX-XXXXX. That is 125 bits from crypto/rand:
// unguessable, so the database stores only an unsalted SHA-256 of the
// canonical form and the plaintext is shown once, at issuance.
package license

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// alphabet is Crockford base32: 32 symbols, so a random byte masked to five
// bits indexes it without modulo bias.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

const (
	rawLen   = 25
	groupLen = 5
)

var ErrMalformedKey = errors.New("license: malformed key")

// Generate returns a fresh formatted key, e.g. "P4X7Q-9K2MN-TR8VW-3EZ5H-BC6DF".
func Generate() (string, error) {
	buf := make([]byte, rawLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("license: generate key: %w", err)
	}
	var b strings.Builder
	b.Grow(rawLen + rawLen/groupLen - 1)
	for i, c := range buf {
		if i > 0 && i%groupLen == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(alphabet[c&31])
	}
	return b.String(), nil
}

// Canonicalize uppercases the input and strips separators (dashes, spaces),
// returning the 25-character canonical form used for hashing. It rejects
// anything that is not exactly 25 alphabet characters after cleanup.
func Canonicalize(input string) (string, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ':
			return -1
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(input)))

	if len(cleaned) != rawLen {
		return "", ErrMalformedKey
	}
	for i := 0; i < len(cleaned); i++ {
		if !strings.ContainsRune(alphabet, rune(cleaned[i])) {
			return "", ErrMalformedKey
		}
	}
	return cleaned, nil
}

// Hash returns the SHA-256 of a canonical key, the only form stored.
func Hash(canonical string) []byte {
	sum := sha256.Sum256([]byte(canonical))
	return sum[:]
}

// Hint returns the last group of a formatted key (e.g. "BC6DF"), stored in
// plaintext so admins can tell licenses apart in listings. Five of 25
// characters is not enough to reconstruct or meaningfully brute the rest.
func Hint(formatted string) string {
	if i := strings.LastIndexByte(formatted, '-'); i >= 0 && i+1 < len(formatted) {
		return formatted[i+1:]
	}
	return ""
}
