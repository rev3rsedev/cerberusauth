package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestHashPasswordFormatAndVerify(t *testing.T) {
	phc, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected PHC prefix: %q", phc)
	}
	if !VerifyPassword("correct horse battery staple", phc) {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword("wrong password", phc) {
		t.Fatal("wrong password accepted")
	}
}

func TestHashPasswordSaltsDiffer(t *testing.T) {
	a, _ := HashPassword("same password")
	b, _ := HashPassword("same password")
	if a == b {
		t.Fatal("two hashes of the same password are identical (salt reuse)")
	}
}

func TestVerifyPasswordGarbageHashes(t *testing.T) {
	garbage := []string{
		"",
		"x",
		"$argon2id$",
		"$argon2i$v=19$m=19456,t=2,p=1$AAAA$AAAA",      // wrong variant
		"$argon2id$v=18$m=19456,t=2,p=1$AAAA$AAAA",     // wrong version
		"$argon2id$v=19$m=0,t=0,p=0$AAAA$AAAA",         // zero params
		"$argon2id$v=19$m=19456,t=2,p=1$!notb64!$AAAA", // bad salt
		"$argon2id$v=19$m=19456,t=2,p=1$AAAA$!notb64!", // bad digest
	}
	for _, phc := range garbage {
		if VerifyPassword("anything", phc) {
			t.Fatalf("garbage hash verified: %q", phc)
		}
	}
}

func TestFakeVerifyDoesNotPanic(t *testing.T) {
	FakeVerify("any password") // must burn argon2 CPU and return quietly
}

func TestNewToken(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	b, _ := NewToken()
	if !strings.HasPrefix(a, "cba_") {
		t.Fatalf("token prefix: %q", a)
	}
	if len(a) < 40 {
		t.Fatalf("token too short: %d", len(a))
	}
	if a == b {
		t.Fatal("two tokens identical")
	}
	if len(HashToken(a)) != 32 {
		t.Fatal("token hash is not 32 bytes")
	}
}

func TestHashEmailNormalizes(t *testing.T) {
	pepper := bytes.Repeat([]byte{9}, 32)
	a := HashEmail(pepper, "Admin@Example.COM ")
	b := HashEmail(pepper, "admin@example.com")
	if !bytes.Equal(a, b) {
		t.Fatal("email hash is case/whitespace sensitive")
	}
	otherPepper := bytes.Repeat([]byte{8}, 32)
	if bytes.Equal(a, HashEmail(otherPepper, "admin@example.com")) {
		t.Fatal("pepper does not affect the hash")
	}
	if bytes.Equal(a, HashEmail(pepper, "other@example.com")) {
		t.Fatal("distinct emails share a hash")
	}
}
