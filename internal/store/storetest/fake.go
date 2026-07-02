// Package storetest provides an in-memory store.Store for unit tests, so
// the service and HTTP layers are testable without PostgreSQL. Conditional
// mutations (RedeemLicense, BindHWID) mirror the SQL semantics exactly;
// that is the part worth faking faithfully.
package storetest

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/rev3rsedev/cerberusauth/internal/store"
)

type FakeStore struct {
	mu       sync.Mutex
	apps     map[uuid.UUID]store.Application
	licenses map[uuid.UUID]store.License
	admins   map[uuid.UUID]store.AdminUser
	tokens   map[uuid.UUID]store.AdminToken
}

var _ store.Store = (*FakeStore)(nil)

func New() *FakeStore {
	return &FakeStore{
		apps:     make(map[uuid.UUID]store.Application),
		licenses: make(map[uuid.UUID]store.License),
		admins:   make(map[uuid.UUID]store.AdminUser),
		tokens:   make(map[uuid.UUID]store.AdminToken),
	}
}

func (f *FakeStore) CreateApplication(_ context.Context, app store.Application) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.apps[app.ID] = app
	return nil
}

func (f *FakeStore) GetApplication(_ context.Context, id uuid.UUID) (store.Application, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	app, ok := f.apps[id]
	if !ok {
		return store.Application{}, store.ErrNotFound
	}
	return app, nil
}

func (f *FakeStore) ListApplications(_ context.Context) ([]store.Application, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]store.Application, 0, len(f.apps))
	for _, a := range f.apps {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out, nil
}

func (f *FakeStore) CreateLicenses(_ context.Context, lics []store.License) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range lics {
		f.licenses[l.ID] = l
	}
	return nil
}

func (f *FakeStore) GetLicenseByID(_ context.Context, id uuid.UUID) (store.License, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	lic, ok := f.licenses[id]
	if !ok {
		return store.License{}, store.ErrNotFound
	}
	return lic, nil
}

func (f *FakeStore) GetLicenseByKeyHash(_ context.Context, appID uuid.UUID, keyHash []byte) (store.License, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.licenses {
		if l.AppID == appID && bytes.Equal(l.KeyHash, keyHash) {
			return l, nil
		}
	}
	return store.License{}, store.ErrNotFound
}

func (f *FakeStore) ListLicenses(_ context.Context, appID uuid.UUID, limit, offset int) ([]store.License, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	all := make([]store.License, 0)
	for _, l := range f.licenses {
		if l.AppID == appID {
			all = append(all, l)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.After(all[j].CreatedAt)
		}
		return all[i].ID.String() < all[j].ID.String()
	})
	if offset >= len(all) {
		return []store.License{}, nil
	}
	all = all[offset:]
	if limit < len(all) {
		all = all[:limit]
	}
	return all, nil
}

func (f *FakeStore) RedeemLicense(_ context.Context, id uuid.UUID, hwidHash []byte, redeemedAt time.Time, expiresAt *time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	lic, ok := f.licenses[id]
	if !ok || lic.Status != store.StatusIssued {
		return false, nil
	}
	lic.Status = store.StatusActive
	lic.HWIDHash = hwidHash
	lic.RedeemedAt = &redeemedAt
	lic.ExpiresAt = expiresAt
	lic.UpdatedAt = redeemedAt
	f.licenses[id] = lic
	return true, nil
}

func (f *FakeStore) BindHWID(_ context.Context, id uuid.UUID, hwidHash []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	lic, ok := f.licenses[id]
	if !ok || lic.HWIDHash != nil {
		return false, nil
	}
	lic.HWIDHash = hwidHash
	f.licenses[id] = lic
	return true, nil
}

func (f *FakeStore) ResetHWID(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	lic, ok := f.licenses[id]
	if !ok {
		return store.ErrNotFound
	}
	lic.HWIDHash = nil
	f.licenses[id] = lic
	return nil
}

func (f *FakeStore) SetLicenseStatus(_ context.Context, id uuid.UUID, status store.LicenseStatus, banReason *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	lic, ok := f.licenses[id]
	if !ok {
		return store.ErrNotFound
	}
	lic.Status = status
	lic.BanReason = banReason
	f.licenses[id] = lic
	return nil
}

func (f *FakeStore) CreateAdminUser(_ context.Context, u store.AdminUser) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.admins[u.ID] = u
	return nil
}

func (f *FakeStore) GetAdminUserByEmailHash(_ context.Context, emailHash []byte) (store.AdminUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.admins {
		if bytes.Equal(u.EmailHash, emailHash) {
			return u, nil
		}
	}
	return store.AdminUser{}, store.ErrNotFound
}

func (f *FakeStore) CreateAdminToken(_ context.Context, t store.AdminToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[t.ID] = t
	return nil
}

func (f *FakeStore) GetAdminTokenByHash(_ context.Context, tokenHash []byte) (store.AdminToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if bytes.Equal(t.TokenHash, tokenHash) {
			return t, nil
		}
	}
	return store.AdminToken{}, store.ErrNotFound
}

// DeleteAdminToken removes by hash only. The postgres implementation also
// sweeps expired rows opportunistically; that is a storage housekeeping
// detail, not semantics worth faking.
func (f *FakeStore) DeleteAdminToken(_ context.Context, tokenHash []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, t := range f.tokens {
		if bytes.Equal(t.TokenHash, tokenHash) {
			delete(f.tokens, id)
			return nil
		}
	}
	return nil
}
