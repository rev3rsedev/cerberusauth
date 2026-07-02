// Package auth covers admin credentials: argon2id password hashing, opaque
// bearer tokens, and peppered email hashing for lookups.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters, per the OWASP baseline (2024): 19 MiB
// memory, 2 iterations, 1 lane. Parameters are encoded into each hash, so
// raising them later only affects new hashes and old ones keep verifying.
const (
	argonMemoryKiB = 19 * 1024
	argonTime      = 2
	argonThreads   = 1
	argonKeyLen    = 32
	saltLen        = 16
)

// HashPassword returns a PHC-formatted argon2id hash, e.g.
// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a PHC argon2id string, using the
// parameters stored in the hash itself.
func VerifyPassword(password, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	if m == 0 || t == 0 || p == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// fakePHC is a syntactically valid hash of nothing in particular (zero salt,
// zero digest). Verifying against it always fails, but costs the same as a
// real verification.
var fakePHC = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
	argon2.Version, argonMemoryKiB, argonTime, argonThreads,
	base64.RawStdEncoding.EncodeToString(make([]byte, saltLen)),
	base64.RawStdEncoding.EncodeToString(make([]byte, argonKeyLen)))

// FakeVerify burns the same CPU as a real password check. Called when a
// login names an unknown email, so response timing does not reveal whether
// an account exists.
func FakeVerify(password string) {
	VerifyPassword(password, fakePHC)
}
