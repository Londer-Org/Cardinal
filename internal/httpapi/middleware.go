// Package httpapi serves Cardinal's HTTP surface.
//
// The admin UI is the highest-value target in the system, so the defaults here
// are deliberately strict: session cookies are HttpOnly and SameSite=Lax, every
// mutation requires a CSRF token, and the CSP forbids inline script.
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/store"
)

const (
	sessionCookie = "cardinal_session"
	csrfCookie    = "cardinal_csrf"
	csrfHeader    = "X-Cardinal-CSRF"
)

type ctxKey int

const (
	ctxSession ctxKey = iota
)

// SessionFrom returns the authenticated session, if any.
func SessionFrom(ctx context.Context) (*store.Session, bool) {
	s, ok := ctx.Value(ctxSession).(*store.Session)
	return s, ok
}

// securityHeaders applies defence-in-depth headers to every response.
func securityHeaders(devMode bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()

			// No inline script: the admin UI is built by Vite into real files,
			// so it never needs 'unsafe-inline', and forbidding it removes the
			// most common XSS payload sink outright.
			csp := "default-src 'self'; " +
				"script-src 'self'; " +
				"style-src 'self'; " +
				"img-src 'self' data:; " +
				"connect-src 'self'; " +
				"frame-ancestors 'none'; " +
				"base-uri 'none'; " +
				"form-action 'self'; " +
				"object-src 'none'"
			if devMode {
				// Vite's dev server needs inline styles and a websocket. This
				// relaxation exists only when the operator explicitly asked for
				// dev mode, and never in a release build's default path.
				csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
					"style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
					"connect-src 'self' ws: wss:; frame-ancestors 'none'"
			}
			h.Set("Content-Security-Policy", csp)

			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			// WebAuthn must remain available to this origin; everything else is
			// switched off because Cardinal has no use for it.
			h.Set("Permissions-Policy",
				"publickey-credentials-get=(self), publickey-credentials-create=(self), "+
					"camera=(), microphone=(), geolocation=(), payment=()")

			if !devMode {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}

			// Authentication responses must never be cached: a shared or proxy
			// cache holding a session response would hand it to the next user.
			if strings.HasPrefix(r.URL.Path, "/api/") {
				h.Set("Cache-Control", "no-store")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// authenticate resolves the session cookie, if present.
//
// It does not reject unauthenticated requests — that is requireAuth's job — so
// that endpoints which are legitimately anonymous (beginning a login) still see
// a session when one exists.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Validity is checked in SQL on every request. Revocation is enforced
		// here, at read time, never by cache invalidation (ADR 0004).
		sess, err := s.store.LookupSession(r.Context(), cookie.Value)
		if err != nil {
			if !errors.Is(err, store.ErrSessionInvalid) {
				s.log.ErrorContext(r.Context(), "session lookup failed", "error", err)
			}
			// Clear the dead cookie so the browser stops sending it.
			clearCookie(w, sessionCookie, s.secureCookies)
			next.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), ctxSession, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAuth rejects unauthenticated requests.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := SessionFrom(r.Context()); !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfProtect guards state-changing requests.
//
// Double-submit: the token is in both a cookie and a header, and they must
// match. An attacker's page can cause the browser to send the cookie but cannot
// read it to set the header, because it is same-origin.
//
// SameSite=Lax on the session cookie already blocks most cross-site posts. This
// is the second layer, because SameSite is a browser behaviour rather than a
// guarantee, and older or unusual clients vary.
func (s *Server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// Safe methods must not mutate, so no token is needed. Ensure one
			// exists for the client to use on its next mutation.
			if _, err := r.Cookie(csrfCookie); err != nil {
				if token, err := newToken(); err == nil {
					// Readable by JavaScript on purpose: the SPA must copy it
					// into the header. It is not a credential — it is only
					// useful in combination with the session cookie, which
					// stays HttpOnly.
					http.SetCookie(w, &http.Cookie{
						Name:     csrfCookie,
						Value:    token,
						Path:     "/",
						Secure:   s.secureCookies,
						SameSite: http.SameSiteLaxMode,
						HttpOnly: false,
					})
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(csrfCookie)
		header := r.Header.Get(csrfHeader)
		if err != nil || header == "" ||
			subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			writeError(w, http.StatusForbidden, "CSRF token missing or invalid")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimit bounds attempts per client for an endpoint.
func (s *Server) rateLimit(limit store.RateLimit) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := clientIP(r)

			allowed, err := s.store.Allow(r.Context(), limit, subject)
			if err != nil {
				// Fail closed. If the limiter cannot be consulted, the safe
				// answer for an authentication endpoint is to refuse: a broken
				// limiter must not become an open door.
				s.log.ErrorContext(r.Context(), "rate limiter unavailable",
					"error", err, "scope", limit.Scope)
				writeError(w, http.StatusServiceUnavailable, "temporarily unavailable")
				return
			}
			if !allowed {
				w.Header().Set("Retry-After",
					strconv.Itoa(int(limit.Window.Seconds())))
				writeError(w, http.StatusTooManyRequests, "too many attempts")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requestLogger records outcomes without recording personal data.
func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			// No query string, no user agent, no client IP: request logs are
			// shipped and retained widely, and personal data in them is subject
			// to the same erasure obligations as anything else (ADR 0010).
			log.InfoContext(r.Context(), "request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds())
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func setSessionCookie(w http.ResponseWriter, token string, expires time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookie,
		Value: token,
		Path:  "/",
		// HttpOnly: script must never be able to read the session token, so an
		// XSS bug cannot become credential theft.
		HttpOnly: true,
		Secure:   secure,
		// Lax rather than Strict: Strict would break returning to Cardinal from
		// an external link, and Lax already blocks cross-site POSTs.
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
}

func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: name == sessionCookie,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// clientIP extracts the address used for rate limiting.
//
// X-Forwarded-For is deliberately NOT trusted. It is attacker-controlled unless
// a proxy is known to overwrite it, so honouring it here would let anyone evade
// rate limiting by varying a header. Deployments behind a trusted proxy should
// have it set the connection address, or this needs an explicit allowlist of
// proxy addresses — which is a decision for whoever runs it, not a default.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
