package service_test

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/rev3rsedev/cerberusauth/internal/service"
)

func TestRotateAppKey(t *testing.T) {
	e := newEnv(t)
	il := e.issue(t, nil, nil)
	if _, err := e.svc.Redeem(e.ctx, e.req(il.Key, "device-1")); err != nil {
		t.Fatal(err)
	}

	// Before rotation: responses verify under the original key.
	resp, err := e.svc.Validate(e.ctx, e.req(il.Key, "device-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyResponse(ed25519.PublicKey(e.key.PublicKey), resp); err != nil {
		t.Fatalf("pre-rotation verify: %v", err)
	}

	actor := uuid.New()
	newKey, err := e.svc.RotateAppKey(service.WithActor(e.ctx, actor), e.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !newKey.Active || newKey.AppID != e.app.ID {
		t.Fatalf("rotated key: %+v", newKey)
	}

	// After rotation: signed by the new key, not the old one.
	resp, err = e.svc.Validate(e.ctx, e.req(il.Key, "device-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyResponse(ed25519.PublicKey(newKey.PublicKey), resp); err != nil {
		t.Fatalf("post-rotation verify with new key: %v", err)
	}
	if _, err := service.VerifyResponse(ed25519.PublicKey(e.key.PublicKey), resp); !errors.Is(err, service.ErrBadSignature) {
		t.Fatalf("old key still verifies new responses: %v", err)
	}

	// Both keys stay listed; the old one is retired.
	keys, err := e.svc.ListAppKeys(e.ctx, e.app.ID)
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys: %v, len %d", err, len(keys))
	}
	var oldListed, newListed bool
	for _, k := range keys {
		switch string(k.PublicKey) {
		case string(e.key.PublicKey):
			oldListed = true
			if k.Active || k.RetiredAt == nil {
				t.Errorf("old key not retired: %+v", k)
			}
		case string(newKey.PublicKey):
			newListed = true
			if !k.Active {
				t.Error("new key not active")
			}
		}
	}
	if !oldListed || !newListed {
		t.Fatalf("key listing incomplete: %+v", keys)
	}

	// The rotation landed in the audit trail with its actor.
	entries, err := e.svc.ListAudit(e.ctx, 1, 0)
	if err != nil || len(entries) != 1 {
		t.Fatal(err)
	}
	if entries[0].Action != service.AuditAppRotateKey || entries[0].AdminID == nil || *entries[0].AdminID != actor {
		t.Fatalf("audit entry: %+v", entries[0])
	}

	// Rotating an unknown app is a clean not-found.
	if _, err := e.svc.RotateAppKey(e.ctx, uuid.New()); !errors.Is(err, service.ErrAppNotFound) {
		t.Fatalf("unknown app: %v", err)
	}
}
