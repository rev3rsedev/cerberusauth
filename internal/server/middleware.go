package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cerberusauth/cerberusauth/internal/service"
)

// withRecover turns panics into 500s instead of dropped connections.
func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "method", r.Method, "path", r.URL.Path, "panic", rec)
				s.writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withLogging logs one line per request. Never bodies and never query
// strings: request bodies carry license keys and credentials.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"dur_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// requireAdmin gates a handler behind a valid admin bearer token.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			s.writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		if _, err := s.svc.AuthenticateToken(r.Context(), token); err != nil {
			if errors.Is(err, service.ErrInvalidToken) {
				s.writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}
			s.writeServiceError(w, r, err)
			return
		}
		next(w, r)
	}
}
