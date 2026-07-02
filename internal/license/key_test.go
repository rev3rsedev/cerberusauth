package license

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// Alphabet is Crockford base32: I, L, O, U excluded.
var formatRe = regexp.MustCompile(`^[0-9A-HJ-KM-NP-TV-Z]{5}(-[0-9A-HJ-KM-NP-TV-Z]{5}){4}$`)

func TestGenerateFormat(t *testing.T) {
	for i := 0; i < 100; i++ {
		key, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !formatRe.MatchString(key) {
			t.Fatalf("bad format: %q", key)
		}
	}
}

func TestGenerateUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		key, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[key] {
			t.Fatalf("duplicate key generated: %q", key)
		}
		seen[key] = true
	}
}

func TestCanonicalizeAcceptsMangledInput(t *testing.T) {
	key, _ := Generate()
	want, err := Canonicalize(key)
	if err != nil {
		t.Fatalf("Canonicalize(generated): %v", err)
	}
	if len(want) != 25 {
		t.Fatalf("canonical length = %d, want 25", len(want))
	}

	// Users paste keys lowercased, with spaces, without dashes...
	variants := []string{
		strings.ToLower(key),
		strings.ReplaceAll(key, "-", ""),
		strings.ReplaceAll(key, "-", " "),
		"  " + key + "  ",
	}
	for _, v := range variants {
		got, err := Canonicalize(v)
		if err != nil {
			t.Fatalf("Canonicalize(%q): %v", v, err)
		}
		if got != want {
			t.Fatalf("Canonicalize(%q) = %q, want %q", v, got, want)
		}
	}
}

func TestCanonicalizeRejectsGarbage(t *testing.T) {
	bad := []string{
		"",
		"short",
		strings.Repeat("A", 24),
		strings.Repeat("A", 26),
		strings.Repeat("A", 20) + "AAAAI", // I not in alphabet
		strings.Repeat("A", 20) + "AAAA!",
	}
	for _, in := range bad {
		if _, err := Canonicalize(in); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("Canonicalize(%q): want ErrMalformedKey, got %v", in, err)
		}
	}
}

func TestHash(t *testing.T) {
	a := Hash("AAAAAAAAAAAAAAAAAAAAAAAAA")
	b := Hash("AAAAAAAAAAAAAAAAAAAAAAAAA")
	c := Hash("BAAAAAAAAAAAAAAAAAAAAAAAA")
	if len(a) != 32 {
		t.Fatalf("hash length = %d, want 32", len(a))
	}
	if !bytes.Equal(a, b) {
		t.Fatal("hash not deterministic")
	}
	if bytes.Equal(a, c) {
		t.Fatal("distinct keys share a hash")
	}
}

func TestHint(t *testing.T) {
	if h := Hint("AB12C-DE34F-GH56J-KM78N-PQ90R"); h != "PQ90R" {
		t.Fatalf("Hint = %q, want PQ90R", h)
	}
	if h := Hint("nodashes"); h != "" {
		t.Fatalf("Hint(no dashes) = %q, want empty", h)
	}
}
