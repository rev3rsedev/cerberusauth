package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rev3rsedev/cerberusauth/internal/service"
)

func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Error("write response", "err", err)
	}
}

// writeError is the unsigned error shape: {"error": "..."}. Clients must
// never treat these as license verdicts — verdicts are signed payloads.
func (s *Server) writeError(w http.ResponseWriter, code int, msg string) {
	s.writeJSON(w, code, map[string]string{"error": msg})
}

// writeServiceError maps service sentinels onto HTTP statuses. Anything
// unrecognized is a 500 with a generic body; details go to the log only.
func (s *Server) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, service.ErrAppNotFound):
		s.writeError(w, http.StatusNotFound, "application not found")
	case errors.Is(err, service.ErrLicenseNotFound):
		s.writeError(w, http.StatusNotFound, "license not found")
	case errors.Is(err, service.ErrInvalidInput):
		s.writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, service.ErrAlreadyExists):
		s.writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, service.ErrInvalidCredentials):
		s.writeError(w, http.StatusUnauthorized, "invalid credentials")
	case errors.Is(err, service.ErrInvalidToken):
		s.writeError(w, http.StatusUnauthorized, "invalid or expired token")
	default:
		s.log.Error("internal error", "method", r.Method, "path", r.URL.Path, "err", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// decodeJSON reads a request body (capped at 64 KiB) into dst.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	return json.NewDecoder(r.Body).Decode(dst)
}
