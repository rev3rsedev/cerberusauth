// Package config loads server configuration from environment variables,
// 12-factor style. Nothing is read from files or flags.
package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/rev3rsedev/cerberusauth/internal/signing"
)

type Config struct {
	DatabaseURL string
	ListenAddr  string

	// MasterKey is the root secret. It is never used directly:
	// signing.DeriveKeys expands it into the key that encrypts per-app
	// signing keys at rest and the pepper for email hashes. Nil when
	// CERBERUS_MASTER_KEY is unset; commands that need it must check and
	// refuse to run.
	MasterKey []byte

	ClockSkew   time.Duration
	TokenTTL    time.Duration
	AutoMigrate bool

	// DevMode acknowledges a disposable sandbox: it is the only way the
	// server will run with the published dev master key.
	DevMode bool

	BootstrapAdminEmail    string
	BootstrapAdminPassword string
}

// devMasterKeyB64 is the well-known dev key shipped in docker-compose.yml
// ("0123456789abcdef0123456789abcdef"). Anyone on the internet has it, so a
// deployment using it has effectively unencrypted signing keys and a public
// email pepper. The server refuses it unless CERBERUS_DEV_MODE=true.
const devMasterKeyB64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

// MasterKeyIsDevKey reports whether the configured master key is the
// published dev key. The dev key is public, so this needs no constant-time
// ceremony.
func (c Config) MasterKeyIsDevKey() bool {
	dev, err := base64.StdEncoding.DecodeString(devMasterKeyB64)
	if err != nil {
		panic("config: dev master key constant is not valid base64")
	}
	return bytes.Equal(c.MasterKey, dev)
}

func Load() (Config, error) {
	cfg := Config{
		DatabaseURL:            os.Getenv("CERBERUS_DATABASE_URL"),
		ListenAddr:             envOr("CERBERUS_LISTEN_ADDR", ":8080"),
		BootstrapAdminEmail:    os.Getenv("CERBERUS_BOOTSTRAP_ADMIN_EMAIL"),
		BootstrapAdminPassword: os.Getenv("CERBERUS_BOOTSTRAP_ADMIN_PASSWORD"),
	}

	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("config: CERBERUS_DATABASE_URL is required")
	}

	if raw := os.Getenv("CERBERUS_MASTER_KEY"); raw != "" {
		key, err := signing.ParseMasterKey(raw)
		if err != nil {
			return Config{}, fmt.Errorf("config: CERBERUS_MASTER_KEY: %w", err)
		}
		cfg.MasterKey = key
	}

	var err error
	if cfg.ClockSkew, err = envDuration("CERBERUS_CLOCK_SKEW", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.TokenTTL, err = envDuration("CERBERUS_ADMIN_TOKEN_TTL", 24*time.Hour); err != nil {
		return Config{}, err
	}
	if cfg.AutoMigrate, err = envBool("CERBERUS_AUTO_MIGRATE", true); err != nil {
		return Config{}, err
	}
	if cfg.DevMode, err = envBool("CERBERUS_DEV_MODE", false); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// RequireMasterKey returns an error suitable for commands that cannot
// operate without the master key.
func (c Config) RequireMasterKey() error {
	if len(c.MasterKey) == 0 {
		return fmt.Errorf("config: CERBERUS_MASTER_KEY is required (generate one with `cerberusd genkey`)")
	}
	return nil
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("config: %s must be positive", name)
	}
	return d, nil
}

func envBool(name string, def bool) (bool, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("config: %s: %w", name, err)
	}
	return b, nil
}
