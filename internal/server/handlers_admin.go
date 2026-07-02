package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/rev3rsedev/cerberusauth/internal/signing"
	"github.com/rev3rsedev/cerberusauth/internal/store"
)

// --- wire shapes (no key hashes, no private keys, no plaintext emails) ---

type appJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"` // base64, raw Ed25519
	KeyID     string    `json:"key_id"`
	CreatedAt time.Time `json:"created_at"`
}

func toAppJSON(a store.Application) appJSON {
	return appJSON{
		ID:        a.ID.String(),
		Name:      a.Name,
		PublicKey: base64.StdEncoding.EncodeToString(a.PublicKey),
		KeyID:     signing.KeyID(a.PublicKey),
		CreatedAt: a.CreatedAt,
	}
}

type licenseJSON struct {
	ID              string     `json:"id"`
	AppID           string     `json:"app_id"`
	KeyHint         string     `json:"key_hint"`
	Tier            string     `json:"tier"`
	Status          string     `json:"status"`
	BanReason       *string    `json:"ban_reason,omitempty"`
	DurationSeconds *int64     `json:"duration_seconds,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	HWIDBound       bool       `json:"hwid_bound"`
	RedeemedAt      *time.Time `json:"redeemed_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

func toLicenseJSON(l store.License) licenseJSON {
	return licenseJSON{
		ID:              l.ID.String(),
		AppID:           l.AppID.String(),
		KeyHint:         l.KeyHint,
		Tier:            l.Tier,
		Status:          string(l.Status),
		BanReason:       l.BanReason,
		DurationSeconds: l.DurationSeconds,
		ExpiresAt:       l.ExpiresAt,
		HWIDBound:       l.HWIDHash != nil,
		RedeemedAt:      l.RedeemedAt,
		CreatedAt:       l.CreatedAt,
	}
}

// --- auth ---

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "malformed JSON body")
		return
	}
	token, expiresAt, err := s.svc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": expiresAt,
	})
}

// handleLogout revokes the token that authenticated this very request.
// requireAdmin has already validated it; here it is only re-read from the
// header to know which row to delete.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if err := s.svc.Logout(r.Context(), token); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- applications ---

func (s *Server) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "malformed JSON body")
		return
	}
	app, err := s.svc.CreateApplication(r.Context(), req.Name)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, toAppJSON(app))
}

func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.svc.ListApplications(r.Context())
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	out := make([]appJSON, 0, len(apps))
	for _, a := range apps {
		out = append(out, toAppJSON(a))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"applications": out})
}

func (s *Server) handleGetApp(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "id must be a UUID")
		return
	}
	app, err := s.svc.GetApplication(r.Context(), id)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, toAppJSON(app))
}

// --- licenses ---

func (s *Server) handleIssueLicenses(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "id must be a UUID")
		return
	}
	var req struct {
		Count           int        `json:"count"`
		Tier            string     `json:"tier"`
		DurationSeconds *int64     `json:"duration_seconds"`
		ExpiresAt       *time.Time `json:"expires_at"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "malformed JSON body")
		return
	}
	if req.Count == 0 {
		req.Count = 1
	}
	issued, err := s.svc.IssueLicenses(r.Context(), appID, req.Count, req.Tier, req.DurationSeconds, req.ExpiresAt)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}

	type issuedJSON struct {
		ID              string     `json:"id"`
		Key             string     `json:"key"` // plaintext — returned once, never again
		Tier            string     `json:"tier"`
		DurationSeconds *int64     `json:"duration_seconds,omitempty"`
		ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	}
	out := make([]issuedJSON, 0, len(issued))
	for _, il := range issued {
		out = append(out, issuedJSON{
			ID:              il.License.ID.String(),
			Key:             il.Key,
			Tier:            il.License.Tier,
			DurationSeconds: il.License.DurationSeconds,
			ExpiresAt:       il.License.ExpiresAt,
		})
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"licenses": out})
}

func (s *Server) handleListLicenses(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "id must be a UUID")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	lics, err := s.svc.ListLicenses(r.Context(), appID, limit, offset)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	out := make([]licenseJSON, 0, len(lics))
	for _, l := range lics {
		out = append(out, toLicenseJSON(l))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"licenses": out})
}

func (s *Server) handleGetLicense(w http.ResponseWriter, r *http.Request) {
	s.licenseAction(w, r, s.svc.GetLicense)
}

func (s *Server) handleBanLicense(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "id must be a UUID")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	// Body is optional for bans; ignore decode errors from an empty body.
	_ = decodeJSON(w, r, &req)

	lic, err := s.svc.BanLicense(r.Context(), id, req.Reason)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, toLicenseJSON(lic))
}

func (s *Server) handleUnbanLicense(w http.ResponseWriter, r *http.Request) {
	s.licenseAction(w, r, s.svc.UnbanLicense)
}

func (s *Server) handleResetHWID(w http.ResponseWriter, r *http.Request) {
	s.licenseAction(w, r, s.svc.ResetHWID)
}

// licenseAction factors the shared shape of {id}-scoped license operations.
func (s *Server) licenseAction(w http.ResponseWriter, r *http.Request, fn func(context.Context, uuid.UUID) (store.License, error)) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "id must be a UUID")
		return
	}
	lic, err := fn(r.Context(), id)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, toLicenseJSON(lic))
}
