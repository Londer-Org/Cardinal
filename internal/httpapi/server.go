package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/arthur-lonfils/cardinal/internal/auth"
	"github.com/arthur-lonfils/cardinal/internal/config"
	"github.com/arthur-lonfils/cardinal/internal/store"
)

// Server holds the HTTP surface.
type Server struct {
	store *store.Store
	auth  *auth.Service
	cfg   *config.Config
	log   *slog.Logger

	// secureCookies is false only in development over plain HTTP. In any
	// deployment reachable over a network it must be true, or session cookies
	// travel in the clear.
	secureCookies bool
	devMode       bool

	// ui is the embedded admin interface. Nil serves API only, which is useful
	// while the frontend is being rebuilt.
	ui fs.FS

	clientIP *clientIPResolver
}

type Options struct {
	DevMode bool
	UI      fs.FS
	Logger  *slog.Logger
}

func New(s *store.Store, a *auth.Service, cfg *config.Config, opts Options) (*Server, error) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	// Validated at startup rather than per request: a malformed trusted_proxies
	// entry must stop the server, not silently degrade to trusting nothing.
	resolver, err := newClientIPResolver(cfg.Server.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("httpapi: server.trusted_proxies: %w", err)
	}
	if len(cfg.Server.TrustedProxies) > 0 {
		log.Info("trusting forwarded client addresses from configured proxies",
			"proxies", cfg.Server.TrustedProxies)
	}

	return &Server{
		store: s, auth: a, cfg: cfg, log: log,
		// Secure cookies are the default; dev mode is the only way to opt out,
		// so forgetting to configure something cannot silently downgrade them.
		secureCookies: !opts.DevMode,
		devMode:       opts.DevMode,
		ui:            opts.UI,
		clientIP:      resolver,
	}, nil
}

// Handler builds the routing tree.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// ── Authentication, anonymous but rate limited ──────────────────────────
	mux.Handle("POST /api/auth/login/begin",
		s.rateLimit(store.LimitLoginBegin)(http.HandlerFunc(s.handleLoginBegin)))
	mux.Handle("POST /api/auth/login/finish",
		s.rateLimit(store.LimitLoginFinish)(http.HandlerFunc(s.handleLoginFinish)))

	// ── Session ────────────────────────────────────────────────────────────
	mux.Handle("GET /api/auth/me", s.requireAuth(http.HandlerFunc(s.handleMe)))
	mux.Handle("POST /api/auth/logout", s.requireAuth(http.HandlerFunc(s.handleLogout)))

	// ── Credential self-service ────────────────────────────────────────────
	mux.Handle("POST /api/credentials/register/begin",
		s.requireAuth(http.HandlerFunc(s.handleRegisterBegin)))
	mux.Handle("POST /api/credentials/register/finish",
		s.requireAuth(http.HandlerFunc(s.handleRegisterFinish)))
	mux.Handle("GET /api/credentials",
		s.requireAuth(http.HandlerFunc(s.handleListCredentials)))
	mux.Handle("DELETE /api/credentials/{id}",
		s.requireAuth(http.HandlerFunc(s.handleRevokeCredential)))

	// ── Recovery codes ─────────────────────────────────────────────────────
	mux.Handle("POST /api/recovery/codes",
		s.requireAuth(http.HandlerFunc(s.handleGenerateRecoveryCodes)))
	mux.Handle("GET /api/recovery/codes/remaining",
		s.requireAuth(http.HandlerFunc(s.handleRemainingRecoveryCodes)))

	mux.HandleFunc("GET /api/health", s.handleHealth)

	if s.ui != nil {
		mux.Handle("/", s.spaHandler())
	}

	// Order matters: security headers outermost so they apply even to
	// responses produced by the layers below, then session resolution, then
	// CSRF, which needs to know whether a session exists.
	var h http.Handler = mux
	h = s.csrfProtect(h)
	h = s.authenticate(h)
	h = securityHeaders(s.devMode)(h)
	h = requestLogger(s.log)(h)
	return h
}

// spaHandler serves the embedded single-page app.
//
// Unknown paths fall back to index.html so client-side routing works on a hard
// refresh — but only for paths that are not API routes and do not look like a
// missing asset, so a genuine 404 for a stale bundle is not disguised as a
// working page.
func (s *Server) spaHandler() http.Handler {
	files := http.FileServer(http.FS(s.ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(s.ui, path); err == nil {
			files.ServeHTTP(w, r)
			return
		}
		if strings.Contains(path, ".") {
			// Looks like an asset that genuinely is not there.
			http.NotFound(w, r)
			return
		}

		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		files.ServeHTTP(w, r2)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unreachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── helpers ────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

type errorBody struct {
	Error string `json:"error"`
}

// writeError sends a deliberately unhelpful message.
//
// Authentication failures must not distinguish "no such user" from "wrong
// credential" from "account disabled": each distinction is a username
// enumeration oracle. Detail goes to the log, not the response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorBody{Error: message})
}

// decodeJSON reads a request body with a size cap, so a malicious client cannot
// exhaust memory by streaming an unbounded document.
func decodeJSON(r *http.Request, dst any) error {
	const maxBody = 1 << 20 // 1 MiB; WebAuthn responses are a few KiB at most
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("malformed request body")
	}
	return nil
}
