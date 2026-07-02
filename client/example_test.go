package client_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/rev3rsedev/cerberusauth/client"
)

// Basic usage: pin the key, redeem once, validate on every start.
func Example() {
	c, err := client.New(
		"https://auth.example.com",
		"6c9028f8-11a1-4e5e-9f30-1d2c3b4a5968",         // your app's UUID
		"vGm0Hgu3v1n0Ka7SwzW9DlFOMFY2M3lQxN4mB2kQzUM=", // pinned at build time
	)
	if err != nil {
		log.Fatal(err)
	}

	v, err := c.Validate(context.Background(), "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", "device-1234")
	if err != nil {
		// No trustworthy answer (offline, forged response, ...). Fail
		// closed: keep the app locked and try again later.
		log.Fatal(err)
	}
	if !v.Valid {
		// A signed, authoritative denial.
		switch v.Reason {
		case client.ReasonNotRedeemed:
			fmt.Println("license not activated yet, call Redeem first")
		case client.ReasonExpired:
			fmt.Println("license expired")
		default:
			fmt.Println("license refused:", v.Reason)
		}
		return
	}
	fmt.Println("licensed, tier:", v.Tier)
}

// The offline grace-period pattern: cache the last good signed envelope and
// fall back to it when the server is unreachable. The cache is re-verified
// at load time, so editing the file breaks it, and a signed denial always
// deletes it.
func Example_offlineGrace() {
	const cachePath = "license-cache.json"
	const grace = 72 * time.Hour

	c, _ := client.New(
		"https://auth.example.com",
		"6c9028f8-11a1-4e5e-9f30-1d2c3b4a5968",
		"vGm0Hgu3v1n0Ka7SwzW9DlFOMFY2M3lQxN4mB2kQzUM=",
	)

	v, err := c.Validate(context.Background(), "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", "device-1234")
	switch {
	case err == nil && v.Valid:
		// Fresh signed approval: refresh the cache.
		_ = os.WriteFile(cachePath, v.Envelope, 0o600)

	case err == nil:
		// Signed denial: authoritative, the grace period does not apply.
		_ = os.Remove(cachePath)

	case errors.Is(err, client.ErrBadSignature), errors.Is(err, client.ErrReplayedResponse):
		// Someone is interfering with the connection. Fail closed, keep the
		// cache for when the real server is reachable again.
		log.Fatal(err)

	default:
		// Offline or server trouble: fall back to the cached verdict.
		stored, rerr := os.ReadFile(cachePath)
		if rerr != nil {
			log.Fatal("no license and no cache: staying locked")
		}
		sv, verr := c.VerifyStored(stored)
		if verr != nil || !sv.Valid || time.Since(sv.ServerTime) > grace {
			log.Fatal("cache invalid or older than the grace period: staying locked")
		}
		v = sv // trusted for up to `grace` since the server last said yes
	}

	fmt.Println("licensed, tier:", v.Tier)
}
