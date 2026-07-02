package server

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/google/uuid"

	"github.com/cerberusauth/cerberusauth/internal/service"
	"github.com/cerberusauth/cerberusauth/internal/signing"
)

type clientRequest struct {
	AppID      string `json:"app_id"`
	LicenseKey string `json:"license_key"`
	HWID       string `json:"hwid"`
	Nonce      string `json:"nonce"`
	Timestamp  int64  `json:"timestamp"` // unix seconds, client clock
}

// handleClientCall adapts Redeem and Validate — same request shape, same
// envelope, different service call.
func (s *Server) handleClientCall(call func(context.Context, service.ValidationRequest) (service.SignedResponse, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req clientRequest
		if err := decodeJSON(w, r, &req); err != nil {
			s.writeError(w, http.StatusBadRequest, "malformed JSON body")
			return
		}

		appID, err := uuid.Parse(req.AppID)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "app_id must be a UUID")
			return
		}
		if n := len(req.LicenseKey); n < 1 || n > 64 {
			s.writeError(w, http.StatusBadRequest, "license_key must be 1-64 characters")
			return
		}
		if n := len(req.HWID); n < 1 || n > 256 {
			s.writeError(w, http.StatusBadRequest, "hwid must be 1-256 characters")
			return
		}
		// A short nonce weakens the client's own replay check; refuse it.
		if n := len(req.Nonce); n < 8 || n > 128 {
			s.writeError(w, http.StatusBadRequest, "nonce must be 8-128 characters")
			return
		}
		if req.Timestamp <= 0 {
			s.writeError(w, http.StatusBadRequest, "timestamp must be unix seconds")
			return
		}

		resp, err := call(r.Context(), service.ValidationRequest{
			AppID:      appID,
			LicenseKey: req.LicenseKey,
			HWID:       req.HWID,
			Nonce:      req.Nonce,
			Timestamp:  req.Timestamp,
		})
		if err != nil {
			s.writeServiceError(w, r, err)
			return
		}
		s.writeJSON(w, http.StatusOK, resp)
	}
}

// handlePubkey serves an app's verification key. Convenience for tooling —
// production clients should pin the key at build time; fetching it over the
// same channel you are trying to distrust defeats the purpose.
func (s *Server) handlePubkey(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(r.PathValue("app_id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "app_id must be a UUID")
		return
	}
	app, err := s.svc.GetApplication(r.Context(), appID)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{
		"app_id":     app.ID.String(),
		"alg":        "ed25519",
		"public_key": base64.StdEncoding.EncodeToString(app.PublicKey),
		"key_id":     signing.KeyID(app.PublicKey),
	})
}
