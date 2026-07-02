// Package server is the HTTP boundary: routing, request decoding, response
// envelopes, middleware. All decisions live in internal/service; handlers
// only translate.
package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/rev3rsedev/cerberusauth/internal/service"
)

type Server struct {
	svc          *service.Service
	log          *slog.Logger
	mux          *http.ServeMux
	loginLimiter *ipLimiter
	// clientLimiter guards the client endpoints; nil disables the gate
	// (rate-limit at the proxy in that topology).
	clientLimiter *ipLimiter
}

// Option adjusts a Server at construction time.
type Option func(*Server)

// WithClientRateLimit enables the per-IP limiter on the client endpoints.
// A burst of 0 disables it.
func WithClientRateLimit(burst int, refillEvery time.Duration) Option {
	return func(s *Server) {
		if burst > 0 && refillEvery > 0 {
			s.clientLimiter = newIPLimiter(burst, refillEvery, nil)
		}
	}
}

func New(svc *service.Service, log *slog.Logger, opts ...Option) *Server {
	s := &Server{
		svc:          svc,
		log:          log,
		mux:          http.NewServeMux(),
		loginLimiter: newIPLimiter(loginBurst, loginRefillEvery, nil),
	}
	for _, o := range opts {
		o(s)
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Client endpoints: the license key is the credential; outcomes about
	// the license are always HTTP 200 with a signed payload. The per-IP
	// limiter caps flooding; a 429 is a transport error, never a verdict.
	s.mux.HandleFunc("POST /v1/client/redeem", s.withClientRateLimit(s.handleClientCall(s.svc.Redeem)))
	s.mux.HandleFunc("POST /v1/client/validate", s.withClientRateLimit(s.handleClientCall(s.svc.Validate)))
	s.mux.HandleFunc("GET /v1/client/apps/{app_id}/pubkey", s.withClientRateLimit(s.handlePubkey))

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
	s.mux.HandleFunc("GET /v1/admin/audit", s.requireAdmin(s.handleListAudit))
}

// Handler returns the fully wrapped root handler.
func (s *Server) Handler() http.Handler {
	return s.withRecover(s.withLogging(s.mux))
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
