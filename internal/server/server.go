// Package server is the HTTP boundary: routing, request decoding, response
// envelopes, middleware. All decisions live in internal/service; handlers
// only translate.
package server

import (
	"log/slog"
	"net/http"

	"github.com/rev3rsedev/cerberusauth/internal/service"
)

type Server struct {
	svc          *service.Service
	log          *slog.Logger
	mux          *http.ServeMux
	loginLimiter *ipLimiter
}

func New(svc *service.Service, log *slog.Logger) *Server {
	s := &Server{
		svc:          svc,
		log:          log,
		mux:          http.NewServeMux(),
		loginLimiter: newIPLimiter(loginBurst, loginRefillEvery, nil),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Client endpoints: the license key is the credential; outcomes about
	// the license are always HTTP 200 with a signed payload.
	s.mux.HandleFunc("POST /v1/client/redeem", s.handleClientCall(s.svc.Redeem))
	s.mux.HandleFunc("POST /v1/client/validate", s.handleClientCall(s.svc.Validate))
	s.mux.HandleFunc("GET /v1/client/apps/{app_id}/pubkey", s.handlePubkey)

	// Admin endpoints: bearer token except login, which is rate-limited
	// per IP instead (it is the only unauthenticated guessing surface).
	s.mux.HandleFunc("POST /v1/admin/login", s.withLoginRateLimit(s.handleLogin))
	s.mux.HandleFunc("DELETE /v1/admin/token", s.requireAdmin(s.handleLogout))
	s.mux.HandleFunc("POST /v1/admin/apps", s.requireAdmin(s.handleCreateApp))
	s.mux.HandleFunc("GET /v1/admin/apps", s.requireAdmin(s.handleListApps))
	s.mux.HandleFunc("GET /v1/admin/apps/{id}", s.requireAdmin(s.handleGetApp))
	s.mux.HandleFunc("POST /v1/admin/apps/{id}/licenses", s.requireAdmin(s.handleIssueLicenses))
	s.mux.HandleFunc("GET /v1/admin/apps/{id}/licenses", s.requireAdmin(s.handleListLicenses))
	s.mux.HandleFunc("GET /v1/admin/licenses/{id}", s.requireAdmin(s.handleGetLicense))
	s.mux.HandleFunc("POST /v1/admin/licenses/{id}/ban", s.requireAdmin(s.handleBanLicense))
	s.mux.HandleFunc("POST /v1/admin/licenses/{id}/unban", s.requireAdmin(s.handleUnbanLicense))
	s.mux.HandleFunc("POST /v1/admin/licenses/{id}/reset-hwid", s.requireAdmin(s.handleResetHWID))
}

// Handler returns the fully wrapped root handler.
func (s *Server) Handler() http.Handler {
	// TODO(v0.2): global rate limiting slots in here, before logging.
	// Login already has its own per-IP limiter (ratelimit.go).
	return s.withRecover(s.withLogging(s.mux))
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
