// client-verify is a reference client for the CerberusAuth validation
// protocol, the exact sequence every real client must implement:
//
//  1. generate a random nonce, stamp the current time
//  2. POST /v1/client/validate (or /redeem with -redeem)
//  3. decode the payload bytes, verify the Ed25519 signature over them
//  4. only then parse the JSON
//  5. check the echoed nonce equals the one just sent (replay protection)
//  6. read the verdict
//
// The public key is pinned via -pubkey (base64, from app creation or
// GET /v1/client/apps/{id}/pubkey). Fetching it at runtime over the same
// connection you distrust would defeat the point.
//
// The Go SDK (package client, at the repository root) implements this same
// sequence with skew correction and offline verification on top; this file
// stays as the minimal spell-it-out reference for SDK authors.
//
// Usage:
//
//	go run ./examples/client-verify \
//	  -server http://localhost:8080 \
//	  -app    <app uuid> \
//	  -pubkey <base64 ed25519 public key> \
//	  -key    XXXXX-XXXXX-XXXXX-XXXXX-XXXXX \
//	  -hwid   my-device-1 \
//	  [-redeem]
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

type envelope struct {
	Alg       string `json:"alg"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

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

func main() {
	server := flag.String("server", "http://localhost:8080", "CerberusAuth base URL")
	appID := flag.String("app", "", "application UUID")
	pubkeyB64 := flag.String("pubkey", "", "pinned Ed25519 public key, base64")
	key := flag.String("key", "", "license key")
	hwid := flag.String("hwid", "example-device", "device identifier")
	redeem := flag.Bool("redeem", false, "redeem (first activation) instead of validate")
	flag.Parse()

	if *appID == "" || *pubkeyB64 == "" || *key == "" {
		flag.Usage()
		os.Exit(2)
	}

	pub, err := base64.StdEncoding.DecodeString(*pubkeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fatal("-pubkey must be a base64 32-byte Ed25519 key")
	}

	// Step 1: fresh nonce + timestamp. The nonce makes the response
	// single-use; the timestamp bounds how old a request the server accepts.
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		fatal("nonce: %v", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	reqBody, _ := json.Marshal(map[string]any{
		"app_id":      *appID,
		"license_key": *key,
		"hwid":        *hwid,
		"nonce":       nonce,
		"timestamp":   time.Now().Unix(),
	})

	endpoint := *server + "/v1/client/validate"
	if *redeem {
		endpoint = *server + "/v1/client/redeem"
	}

	// Step 2: call the server.
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		fatal("request: %v", err)
	}
	defer resp.Body.Close()

	var env envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		fatal("decode envelope (HTTP %d): %v", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		// Unsigned transport error, NOT a license verdict. Fail closed,
		// retry later; do not unlock anything.
		fatal("transport error: HTTP %d", resp.StatusCode)
	}

	// Steps 3-4: verify the signature over the raw bytes, then parse.
	rawPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		fatal("payload not base64: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		fatal("signature not base64: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), rawPayload, sig) {
		fatal("SIGNATURE INVALID: response is forged, tampered, or signed by a different key. Treat as invalid license.")
	}
	var p payload
	if err := json.Unmarshal(rawPayload, &p); err != nil {
		fatal("parse verified payload: %v", err)
	}

	// Step 5: the echoed nonce must be ours, or this is a replayed response.
	if p.Nonce != nonce {
		fatal("NONCE MISMATCH: response replayed or answered for a different request. Treat as invalid license.")
	}

	// Step 6: the verdict is now trustworthy.
	fmt.Println("signature      : OK (ed25519, key_id " + env.KeyID + ")")
	fmt.Println("nonce echo     : OK")
	fmt.Printf("valid          : %v\n", p.Valid)
	if p.Reason != "" {
		fmt.Printf("reason         : %s\n", p.Reason)
	}
	if p.Tier != "" {
		fmt.Printf("tier           : %s\n", p.Tier)
	}
	if p.ExpiresAt > 0 {
		fmt.Printf("expires        : %s\n", time.Unix(p.ExpiresAt, 0).UTC().Format(time.RFC3339))
	} else if p.Valid {
		fmt.Println("expires        : never (perpetual)")
	}
	fmt.Printf("server time    : %s\n", time.Unix(p.ServerTS, 0).UTC().Format(time.RFC3339))

	if !p.Valid {
		os.Exit(1)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
