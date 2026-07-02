package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"testing"
)

func testMaster(t *testing.T) []byte {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, MasterKeySize)
	return key
}

func TestGenerateSignVerify(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	payload := []byte(`{"valid":true,"nonce":"abc"}`)
	sig := Sign(kp.Private, payload)
	if !Verify(kp.Public, payload, sig) {
		t.Fatal("signature did not verify")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	kp, _ := Generate()
	payload := []byte(`{"valid":false,"reason":"banned"}`)
	sig := Sign(kp.Private, payload)

	tampered := bytes.Clone(payload)
	tampered[10] ^= 0x01 // flip one bit: "banned" verdict must not be forgeable either
	if Verify(kp.Public, tampered, sig) {
		t.Fatal("tampered payload verified")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	kp1, _ := Generate()
	kp2, _ := Generate()
	payload := []byte("payload")
	sig := Sign(kp1.Private, payload)
	if Verify(kp2.Public, payload, sig) {
		t.Fatal("signature verified under the wrong key")
	}
}

func TestVerifyRejectsBadKeyLength(t *testing.T) {
	if Verify(ed25519.PublicKey([]byte("short")), []byte("p"), []byte("s")) {
		t.Fatal("verified with malformed public key")
	}
}

func TestKeyID(t *testing.T) {
	kp, _ := Generate()
	id := KeyID(kp.Public)
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(id) {
		t.Fatalf("KeyID format: %q", id)
	}
	if id != KeyID(kp.Public) {
		t.Fatal("KeyID not deterministic")
	}
	kp2, _ := Generate()
	if id == KeyID(kp2.Public) {
		t.Fatal("distinct keys share a KeyID")
	}
}

func TestPrivateKeyEncryptionRoundtrip(t *testing.T) {
	master := testMaster(t)
	kp, _ := Generate()

	blob, err := EncryptPrivateKey(master, kp.Private)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}
	if bytes.Contains(blob, kp.Private) {
		t.Fatal("ciphertext contains the plaintext key")
	}

	got, err := DecryptPrivateKey(master, blob)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}
	if !got.Equal(kp.Private) {
		t.Fatal("roundtrip lost the key")
	}
}

func TestDecryptWithWrongMasterKeyFails(t *testing.T) {
	kp, _ := Generate()
	blob, _ := EncryptPrivateKey(testMaster(t), kp.Private)

	wrong := bytes.Repeat([]byte{0x43}, MasterKeySize)
	if _, err := DecryptPrivateKey(wrong, blob); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("want ErrDecryptFailed, got %v", err)
	}
}

func TestDecryptRejectsTamperedBlob(t *testing.T) {
	master := testMaster(t)
	kp, _ := Generate()
	blob, _ := EncryptPrivateKey(master, kp.Private)

	blob[len(blob)-1] ^= 0x01
	if _, err := DecryptPrivateKey(master, blob); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("want ErrDecryptFailed, got %v", err)
	}
}

func TestDecryptRejectsTruncatedBlob(t *testing.T) {
	if _, err := DecryptPrivateKey(testMaster(t), []byte{1, 2, 3}); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("want ErrDecryptFailed, got %v", err)
	}
}

func TestEncryptRejectsBadInputs(t *testing.T) {
	kp, _ := Generate()
	if _, err := EncryptPrivateKey([]byte("short"), kp.Private); !errors.Is(err, ErrBadMasterKey) {
		t.Fatalf("short master key: want ErrBadMasterKey, got %v", err)
	}
	if _, err := EncryptPrivateKey(testMaster(t), ed25519.PrivateKey([]byte("short"))); err == nil {
		t.Fatal("short private key accepted")
	}
}

func TestParseMasterKey(t *testing.T) {
	ok := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, MasterKeySize))
	if _, err := ParseMasterKey(ok); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	for _, bad := range []string{"", "not-base64!!!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParseMasterKey(bad); !errors.Is(err, ErrBadMasterKey) {
			t.Fatalf("ParseMasterKey(%q): want ErrBadMasterKey, got %v", bad, err)
		}
	}
}

func TestNewMasterKeyParses(t *testing.T) {
	s, err := NewMasterKey()
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	if _, err := ParseMasterKey(s); err != nil {
		t.Fatalf("generated master key does not parse: %v", err)
	}
}

// TestDeriveKeysKnownAnswer pins the exact derivation. If this test breaks,
// the change orphans every private key and email hash in existing databases —
// that must be a deliberate, versioned decision, never a refactoring accident.
func TestDeriveKeysKnownAnswer(t *testing.T) {
	encKey, emailPepper, err := DeriveKeys(testMaster(t))
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	wantEnc := "83325b2e67acc2dd852d862d414fa8dab80bb3cbb403ef708e0c9427a0fdc460"
	wantPepper := "fc50c0b2f7d8c9c5cbbaf71b54c237d79c8b61447a25f913d9630c02a2977e69"
	if got := hex.EncodeToString(encKey); got != wantEnc {
		t.Fatalf("enc key derivation changed:\n got %s\nwant %s", got, wantEnc)
	}
	if got := hex.EncodeToString(emailPepper); got != wantPepper {
		t.Fatalf("email pepper derivation changed:\n got %s\nwant %s", got, wantPepper)
	}
}

func TestDeriveKeysSubkeysIndependent(t *testing.T) {
	master := testMaster(t)
	encKey, emailPepper, err := DeriveKeys(master)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	if len(encKey) != 32 || len(emailPepper) != 32 {
		t.Fatalf("subkey lengths: enc=%d pepper=%d, want 32/32", len(encKey), len(emailPepper))
	}
	if bytes.Equal(encKey, emailPepper) {
		t.Fatal("enc key and email pepper are identical")
	}
	if bytes.Equal(encKey, master) || bytes.Equal(emailPepper, master) {
		t.Fatal("a subkey equals the master key — derivation is not happening")
	}
}

func TestDeriveKeysRejectsBadMaster(t *testing.T) {
	for _, bad := range [][]byte{nil, {}, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{1}, 33)} {
		if _, _, err := DeriveKeys(bad); !errors.Is(err, ErrBadMasterKey) {
			t.Fatalf("DeriveKeys(len %d): want ErrBadMasterKey, got %v", len(bad), err)
		}
	}
}
