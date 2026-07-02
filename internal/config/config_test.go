package config

import (
	"testing"

	"github.com/cerberusauth/cerberusauth/internal/signing"
)

func TestMasterKeyIsDevKey(t *testing.T) {
	t.Setenv("CERBERUS_DATABASE_URL", "postgres://localhost/test")

	t.Setenv("CERBERUS_MASTER_KEY", devMasterKeyB64)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with dev key: %v", err)
	}
	if !cfg.MasterKeyIsDevKey() {
		t.Fatal("published dev key not detected")
	}
	if cfg.DevMode {
		t.Fatal("DevMode defaulted to true")
	}

	fresh, err := signing.NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CERBERUS_MASTER_KEY", fresh)
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load with fresh key: %v", err)
	}
	if cfg.MasterKeyIsDevKey() {
		t.Fatal("fresh key flagged as the dev key")
	}

	// No key at all is not the dev key either.
	if (Config{}).MasterKeyIsDevKey() {
		t.Fatal("nil key flagged as the dev key")
	}
}

func TestDevModeParses(t *testing.T) {
	t.Setenv("CERBERUS_DATABASE_URL", "postgres://localhost/test")
	t.Setenv("CERBERUS_DEV_MODE", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DevMode {
		t.Fatal("CERBERUS_DEV_MODE=true not honored")
	}

	t.Setenv("CERBERUS_DEV_MODE", "not-a-bool")
	if _, err := Load(); err == nil {
		t.Fatal("malformed CERBERUS_DEV_MODE accepted")
	}
}
