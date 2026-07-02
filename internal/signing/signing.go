// Package signing implements the Ed25519 core: per-application keypairs,
// detached signatures over raw payload bytes, and AES-256-GCM encryption of
// private keys at rest. The master key supplied via the environment is never
// used directly; DeriveKeys expands it into independent subkeys per purpose.
//
// The signed unit is always an exact byte sequence. Callers transport those
// bytes verbatim (base64) and clients verify before parsing; there is no
// canonicalization step anywhere.
package signing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// MasterKeySize is the required master key length in bytes (AES-256).
const MasterKeySize = 32

const gcmNonceSize = 12

var (
	ErrBadMasterKey  = errors.New("signing: master key must be 32 bytes, base64-encoded")
	ErrDecryptFailed = errors.New("signing: private key decryption failed (wrong master key or corrupted data)")
)

// Keypair is an application's Ed25519 signing keypair.
type Keypair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// Generate creates a new Ed25519 keypair from crypto/rand.
func Generate() (Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, fmt.Errorf("signing: generate keypair: %w", err)
	}
	return Keypair{Public: pub, Private: priv}, nil
}

// KeyID is a short fingerprint of a public key: the first 8 bytes of its
// SHA-256, hex-encoded. It identifies which key signed a response (useful
// once key rotation exists); it is not a secret.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Sign produces a detached Ed25519 signature over payload.
func Sign(priv ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(priv, payload)
}

// Verify reports whether sig is a valid signature over payload by pub.
func Verify(pub ed25519.PublicKey, payload, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, payload, sig)
}

// ParseMasterKey decodes a base64 master key and enforces its length.
func ParseMasterKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(key) != MasterKeySize {
		return nil, ErrBadMasterKey
	}
	return key, nil
}

// DeriveKeys expands the master key into its two subkeys via HKDF-SHA256:
// the AES-256 key for private keys at rest and the HMAC pepper for email
// hashing. The master key itself must never be used as a cipher or MAC key;
// deriving per-purpose keys keeps the primitives independent. The info
// strings are versioned so a future rotation scheme can add "-v2" without
// ambiguity; changing them (or the nil salt) changes every derived key and
// orphans existing stored data.
func DeriveKeys(master []byte) (encKey, emailPepper []byte, err error) {
	if len(master) != MasterKeySize {
		return nil, nil, ErrBadMasterKey
	}
	encKey, err = hkdf.Key(sha256.New, master, nil, "cerberus/enc-v1", 32)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: derive enc key: %w", err)
	}
	emailPepper, err = hkdf.Key(sha256.New, master, nil, "cerberus/email-v1", 32)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: derive email pepper: %w", err)
	}
	return encKey, emailPepper, nil
}

// NewMasterKey generates a fresh master key, base64-encoded for the env var.
func NewMasterKey() (string, error) {
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("signing: generate master key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// EncryptPrivateKey seals an Ed25519 private key with AES-256-GCM under the
// encryption key from DeriveKeys. Output layout: 12-byte nonce || ciphertext+tag.
func EncryptPrivateKey(encKey []byte, priv ed25519.PrivateKey) ([]byte, error) {
	if len(encKey) != MasterKeySize {
		return nil, ErrBadMasterKey
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing: private key must be %d bytes", ed25519.PrivateKeySize)
	}
	gcm, err := newGCM(encKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("signing: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, priv, nil), nil
}

// DecryptPrivateKey reverses EncryptPrivateKey. A wrong key or a
// tampered blob yields ErrDecryptFailed, never a garbage key.
func DecryptPrivateKey(encKey, blob []byte) (ed25519.PrivateKey, error) {
	if len(encKey) != MasterKeySize {
		return nil, ErrBadMasterKey
	}
	if len(blob) < gcmNonceSize+1 {
		return nil, ErrDecryptFailed
	}
	gcm, err := newGCM(encKey)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, blob[:gcmNonceSize], blob[gcmNonceSize:], nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	if len(plain) != ed25519.PrivateKeySize {
		return nil, ErrDecryptFailed
	}
	return ed25519.PrivateKey(plain), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("signing: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("signing: gcm: %w", err)
	}
	return gcm, nil
}
