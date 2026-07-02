// Package dashboard embeds the admin UI: three static files, no build
// step, no CDN, no third-party JavaScript. The UI is a thin shell over the
// admin API; it holds no state the API does not enforce, so disabling it
// (CERBERUS_DASHBOARD=false) removes nothing but convenience.
package dashboard

import (
	"embed"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// pages is the complete list of what this handler will ever serve. An
// allowlist, not a file server: nothing else in the binary is reachable
// through it, whatever the path says.
var pages = map[string]struct {
	file        string
	contentType string
}{
	"/":          {"static/index.html", "text/html; charset=utf-8"},
	"/app.js":    {"static/app.js", "text/javascript; charset=utf-8"},
	"/style.css": {"static/style.css", "text/css; charset=utf-8"},
}

// Handler serves the dashboard files. Callers mount it on explicit routes
// (/, /app.js, /style.css); it never sees API paths.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, err := staticFS.ReadFile(p.file)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Same-origin only: the app talks to its own API and loads nothing
		// external. Inline script and style stay blocked.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Type", p.contentType)
		_, _ = w.Write(body)
	})
}
