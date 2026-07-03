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
	PublicKey string    `json:"public_key"` // base64, raw Ed25519; the active key
	KeyID     string    `json:"key_id"`
	CreatedAt time.Time `json:"created_at"`
}

func toAppJSON(a store.Application, activeKey store.AppKey) appJSON {
	return appJSON{
		ID:        a.ID.String(),
		Name:      a.Name,
		PublicKey: base64.StdEncoding.EncodeToString(activeKey.PublicKey),
		KeyID:     signing.KeyID(activeKey.PublicKey),
		CreatedAt: a.CreatedAt,
	}
}

type appKeyJSON struct {
	KeyID     string     `json:"key_id"`
	PublicKey string     `json:"public_key"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

func toAppKeyJSON(k store.AppKey) appKeyJSON {
	return appKeyJSON{
		KeyID:     signing.KeyID(k.PublicKey),
		PublicKey: base64.StdEncoding.EncodeToString(k.PublicKey),
		Active:    k.Active,
		CreatedAt: k.CreatedAt,
		RetiredAt: k.RetiredAt,
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
	app, key, err := s.svc.CreateApplication(r.Context(), req.Name)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, toAppJSON(app, key))
}

func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.svc.ListApplications(r.Context())
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	// One key lookup per app. Fine at the scale of "my products"; revisit
	// with a join if someone runs thousands of apps.
	out := make([]appJSON, 0, len(apps))
	for _, a := range apps {
		key, err := s.svc.GetActiveKey(r.Context(), a.ID)
		if err != nil {
			s.writeServiceError(w, r, err)
			return
		}
		out = append(out, toAppJSON(a, key))
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
	key, err := s.svc.GetActiveKey(r.Context(), id)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, toAppJSON(app, key))
}

func (s *Server) handleListAppKeys(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "id must be a UUID")
		return
	}
	keys, err := s.svc.ListAppKeys(r.Context(), id)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	out := make([]appKeyJSON, 0, len(keys))
	for _, k := range keys {
		out = append(out, toAppKeyJSON(k))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// handleRotateAppKey mints and activates a fresh signing key. The old key
// is retired but stays on the pubkey endpoint so already-shipped clients
// that pin it keep working while they migrate.
func (s *Server) handleRotateAppKey(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "id must be a UUID")
		return
	}
	key, err := s.svc.RotateAppKey(r.Context(), id)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, toAppKeyJSON(key))
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
		Key             string     `json:"key"` // plaintext; returned once, never again
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

// --- audit ---

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	entries, err := s.svc.ListAudit(r.Context(), limit, offset)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}

	type auditJSON struct {
		ID       int64     `json:"id"`
		At       time.Time `json:"at"`
		AdminID  *string   `json:"admin_id,omitempty"`
		Action   string    `json:"action"`
		TargetID string    `json:"target_id,omitempty"`
		Detail   string    `json:"detail,omitempty"`
	}
	out := make([]auditJSON, 0, len(entries))
	for _, e := range entries {
		j := auditJSON{ID: e.ID, At: e.At, Action: e.Action, TargetID: e.TargetID, Detail: e.Detail}
		if e.AdminID != nil {
			id := e.AdminID.String()
			j.AdminID = &id
		}
		out = append(out, j)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// --- stats ---

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.svc.Stats(r.Context())
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"applications":    st.Applications,
		"licenses":        st.Licenses,
		"active_licenses": st.ActiveLicenses,
		"banned_licenses": st.BannedLicenses,
	})
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
