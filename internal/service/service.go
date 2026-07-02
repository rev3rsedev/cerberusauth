// Package service holds the business logic: license validation and
// redemption (the signed path) plus admin operations. It talks to storage
// through store.Store and never sees SQL or HTTP.
package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/cerberusauth/cerberusauth/internal/license"
	"github.com/cerberusauth/cerberusauth/internal/signing"
	"github.com/cerberusauth/cerberusauth/internal/store"
)

var (
	ErrAppNotFound        = errors.New("application not found")
	ErrLicenseNotFound    = errors.New("license not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrAlreadyExists      = errors.New("already exists")
	ErrInvalidInput       = errors.New("invalid input")
)

type Service struct {
	store       store.Store
	encKey      []byte // encrypts signing keys at rest; derived from the master key
	emailPepper []byte // peppers email hashes; derived from the master key
	now         func() time.Time
	clockSkew   time.Duration
	tokenTTL    time.Duration
}

type Options struct {
	MasterKey []byte
	ClockSkew time.Duration // default 5m
	TokenTTL  time.Duration // default 24h
	Now       func() time.Time
}

func New(st store.Store, opts Options) *Service {
	s := &Service{
		store:     st,
		now:       opts.Now,
		clockSkew: opts.ClockSkew,
		tokenTTL:  opts.TokenTTL,
	}
	// An absent or malformed master key leaves the derived keys nil, and
	// key-touching operations fail at call time — same laziness as before
	// the HKDF split. config.Load already rejects malformed keys upfront.
	if encKey, emailPepper, err := signing.DeriveKeys(opts.MasterKey); err == nil {
		s.encKey, s.emailPepper = encKey, emailPepper
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.clockSkew <= 0 {
		s.clockSkew = 5 * time.Minute
	}
	if s.tokenTTL <= 0 {
		s.tokenTTL = 24 * time.Hour
	}
	return s
}

// ValidationRequest is a client's redeem/validate call.
type ValidationRequest struct {
	AppID      uuid.UUID
	LicenseKey string
	HWID       string
	Nonce      string
	Timestamp  int64 // unix seconds, client clock
}

// HashHWID maps a device identifier to its storage form.
func HashHWID(hwid string) []byte {
	sum := sha256.Sum256([]byte(hwid))
	return sum[:]
}

// Validate answers "is this license good for this device, right now" with a
// signed verdict. Every license-related outcome — including failures — is
// signed, so a network attacker can forge neither approval nor denial.
func (s *Service) Validate(ctx context.Context, req ValidationRequest) (SignedResponse, error) {
	app, p, lic, early, err := s.resolve(ctx, req)
	if err != nil {
		return SignedResponse{}, err
	}
	if early != nil {
		return *early, nil
	}

	switch {
	case lic.Status == store.StatusBanned:
		p.Reason = ReasonBanned
	case lic.Status == store.StatusIssued:
		p.Reason = ReasonNotRedeemed
	case s.expired(lic):
		p.Reason = ReasonExpired
	default:
		ok, err := s.checkAndBindHWID(ctx, lic, HashHWID(req.HWID))
		if err != nil {
			return SignedResponse{}, err
		}
		if ok {
			p.Valid = true
		} else {
			p.Reason = ReasonHWIDMismatch
		}
	}
	return s.signPayload(app, p)
}

// Redeem activates an issued license: binds the device and starts the
// expiry clock (redeemed_at + duration). Redeeming an already-active
// license with the same HWID is a success (safe client retry); with a
// different HWID it is hwid_mismatch.
func (s *Service) Redeem(ctx context.Context, req ValidationRequest) (SignedResponse, error) {
	app, p, lic, early, err := s.resolve(ctx, req)
	if err != nil {
		return SignedResponse{}, err
	}
	if early != nil {
		return *early, nil
	}

	hwidHash := HashHWID(req.HWID)
	now := s.now()

	for attempt := 0; ; attempt++ {
		if lic.Status == store.StatusBanned {
			p.Reason = ReasonBanned
			break
		}
		if lic.Status == store.StatusActive {
			switch {
			case s.expired(lic):
				p.Reason = ReasonExpired
			case lic.HWIDHash != nil && bytes.Equal(lic.HWIDHash, hwidHash):
				p.Valid = true
				if lic.ExpiresAt != nil {
					p.ExpiresAt = lic.ExpiresAt.Unix()
				}
			default:
				p.Reason = ReasonHWIDMismatch
			}
			break
		}
		// Status issued. A fixed expiry set at issuance may already be past.
		if s.expired(lic) {
			p.Reason = ReasonExpired
			break
		}
		expiresAt := computeExpiry(lic, now)
		won, err := s.store.RedeemLicense(ctx, lic.ID, hwidHash, now, expiresAt)
		if err != nil {
			return SignedResponse{}, err
		}
		if won {
			p.Valid = true
			if expiresAt != nil {
				p.ExpiresAt = expiresAt.Unix()
			}
			break
		}
		// Lost a race: someone redeemed (or banned) it between our read and
		// write. Re-read once and re-evaluate.
		if attempt > 0 {
			return SignedResponse{}, fmt.Errorf("service: redeem did not settle for license %s", lic.ID)
		}
		lic, err = s.store.GetLicenseByID(ctx, lic.ID)
		if err != nil {
			return SignedResponse{}, err
		}
	}
	return s.signPayload(app, p)
}

// resolve performs the steps shared by Validate and Redeem: app lookup,
// timestamp skew check, key canonicalization and license fetch. When the
// request can be answered without a license evaluation (stale timestamp,
// unknown key) it returns the signed verdict as early.
func (s *Service) resolve(ctx context.Context, req ValidationRequest) (app store.Application, p Payload, lic store.License, early *SignedResponse, err error) {
	app, err = s.store.GetApplication(ctx, req.AppID)
	if errors.Is(err, store.ErrNotFound) {
		return app, p, lic, nil, ErrAppNotFound
	}
	if err != nil {
		return app, p, lic, nil, err
	}

	now := s.now()
	p = Payload{
		V:        1,
		AppID:    app.ID.String(),
		HWID:     req.HWID,
		Nonce:    req.Nonce,
		ClientTS: req.Timestamp,
		ServerTS: now.Unix(),
	}

	signEarly := func(reason string) (store.Application, Payload, store.License, *SignedResponse, error) {
		p.Reason = reason
		resp, serr := s.signPayload(app, p)
		if serr != nil {
			return app, p, lic, nil, serr
		}
		return app, p, lic, &resp, nil
	}

	drift := now.Unix() - req.Timestamp
	if drift < 0 {
		drift = -drift
	}
	if time.Duration(drift)*time.Second > s.clockSkew {
		return signEarly(ReasonStaleTimestamp)
	}

	canonical, cerr := license.Canonicalize(req.LicenseKey)
	if cerr != nil {
		return signEarly(ReasonInvalidKey)
	}

	lic, err = s.store.GetLicenseByKeyHash(ctx, app.ID, license.Hash(canonical))
	if errors.Is(err, store.ErrNotFound) {
		return signEarly(ReasonInvalidKey)
	}
	if err != nil {
		return app, p, lic, nil, err
	}

	p.LicenseID = lic.ID.String()
	p.Tier = lic.Tier
	if lic.ExpiresAt != nil {
		p.ExpiresAt = lic.ExpiresAt.Unix()
	}
	return app, p, lic, nil, nil
}

// checkAndBindHWID enforces device binding: bind on first use, exact match
// afterwards. The conditional store update means two devices racing for the
// first bind cannot both win; the loser is re-checked against what actually
// got bound.
func (s *Service) checkAndBindHWID(ctx context.Context, lic store.License, hwidHash []byte) (bool, error) {
	if lic.HWIDHash != nil {
		return bytes.Equal(lic.HWIDHash, hwidHash), nil
	}
	bound, err := s.store.BindHWID(ctx, lic.ID, hwidHash)
	if err != nil {
		return false, err
	}
	if bound {
		return true, nil
	}
	fresh, err := s.store.GetLicenseByID(ctx, lic.ID)
	if err != nil {
		return false, err
	}
	return fresh.HWIDHash != nil && bytes.Equal(fresh.HWIDHash, hwidHash), nil
}

func (s *Service) expired(lic store.License) bool {
	return lic.ExpiresAt != nil && s.now().After(*lic.ExpiresAt)
}

// computeExpiry decides a license's expiry at redemption time: a fixed date
// set at issuance wins; otherwise a relative duration starts now; neither
// means perpetual.
func computeExpiry(lic store.License, now time.Time) *time.Time {
	if lic.ExpiresAt != nil {
		return lic.ExpiresAt
	}
	if lic.DurationSeconds != nil {
		t := now.Add(time.Duration(*lic.DurationSeconds) * time.Second)
		return &t
	}
	return nil
}

func (s *Service) signPayload(app store.Application, p Payload) (SignedResponse, error) {
	priv, err := signing.DecryptPrivateKey(s.encKey, app.PrivateKeyEnc)
	if err != nil {
		return SignedResponse{}, fmt.Errorf("service: app %s: %w", app.ID, err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return SignedResponse{}, fmt.Errorf("service: marshal payload: %w", err)
	}
	sig := signing.Sign(priv, raw)
	return SignedResponse{
		Alg:       "ed25519",
		KeyID:     signing.KeyID(app.PublicKey),
		Payload:   base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}
