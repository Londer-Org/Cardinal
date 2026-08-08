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
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.londer.be/cardinal/internal/store"
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

// authenticate resolves the session cookie or a bearer token, if either is
// present.
//
// It does not reject unauthenticated requests — that is requireAuth's job — so
// that endpoints which are legitimately anonymous (beginning a login) still see
// a session when one exists.
//
// The cookie is tried first. A browser that also happens to carry an
// Authorization header is still a browser, and its cookie is the credential it
// is entitled to use; preferring the header would let a page that can set one
// choose which identity Cardinal sees.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(sessionCookie); err == nil && cookie.Value != "" {
			// Validity is checked in SQL on every request. Revocation is
			// enforced here, at read time, never by cache invalidation
			// (ADR 0004).
			sess, err := s.store.LookupSession(r.Context(), cookie.Value)
			if err != nil {
				if !errors.Is(err, store.ErrSessionInvalid) {
					s.log.ErrorContext(r.Context(), "session lookup failed", "error", err)
				}
				// Clear the dead cookie so the browser stops sending it.
				clearCookie(w, sessionCookie, s.secureCookies, s.cfg.Server.CookieDomain)
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), ctxSession, sess)))
			return
		}

		presented := bearerToken(r)
		if presented == "" {
			next.ServeHTTP(w, r)
			return
		}

		token, err := s.store.LookupAccessToken(r.Context(), presented)
		if err != nil {
			if !errors.Is(err, store.ErrTokenInvalid) {
				s.log.ErrorContext(r.Context(), "access token lookup failed", "error", err)
			}
			next.ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), ctxSession, sessionForToken(token))))
	})
}

// bearerToken reads an RFC 6750 Authorization header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// sessionForToken presents an access token as the principal it authenticates.
//
// Deliberately a Session, so that every claim projection, policy evaluation and
// decision log entry downstream works unchanged rather than growing a second
// code path for machines — a second path is where the two drift and one of them
// stops being checked.
//
// Two fields carry the whole security argument, and neither is incidental:
//
//   - DeviceBound is false. `admin-requires-fresh-device-bound-auth` and
//     `ssh-requires-device-bound` are both written `unless { principal.deviceBound
//     && … }`, so a token is refused every administrative action and every SSH
//     certificate by policy that already exists. Setting this true would hand a
//     string in a CI variable the authority of a hardware key.
//
//   - AuthAt is when the token was issued, not when it was used. A token typed
//     into a pipeline months ago has not authenticated anyone recently, and
//     reporting otherwise would make authAgeSeconds — which freshness rules are
//     built on — a fiction.
func sessionForToken(token *store.AccessToken) *store.Session {
	return &store.Session{
		ID:          token.ID,
		SubjectID:   token.SubjectID,
		AuthMethod:  store.AuthMethodAccessToken,
		AuthAt:      token.CreatedAt,
		DeviceBound: false,
		ValidFrom:   token.ValidFrom,
		ValidUntil:  token.ValidUntil,
	}
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

// requireDeviceBound refuses anything that is not a passkey session.
//
// Guards the credential self-service surface: passkeys, recovery codes, and
// access tokens. Changing what can authenticate as you is not an ordinary
// action a weaker credential may take on your behalf.
//
// ## Why this is code and not a Cedar policy
//
// ADR 0018 argued a token is safe because `admin-requires-fresh-device-bound-auth`
// forbids it every dangerous action, and that this holds "for rules nobody has
// written yet". The reasoning had a hole: it holds only for routes that ask
// Cedar. Credential self-service never did — there is no resource to authorize
// against, only the caller's own account — so the entire surface sat behind bare
// requireAuth, and a token reached all of it.
//
// What that allowed, measured against a running stack rather than reasoned
// about: a token could POST /api/recovery/codes and read a fresh set of
// account-recovery credentials, which in the same statement invalidated the
// owner's. It could begin registering a passkey of the holder's choosing. It
// could revoke the owner's existing passkeys. And once /api/tokens existed it
// could mint its own successor, so revoking the leaked token accomplished
// nothing. A string in a CI variable was one request away from owning the
// account it was scoped to serve.
//
// Two reasons it stays in code:
//
//   - There is nothing to decide. Cedar answers "may this principal do this to
//     that resource"; here the answer does not vary by principal or resource. A
//     universal precondition on the credential belongs with requireAuth and CSRF,
//     which are the same category of check.
//
//   - A policy set is editable, and this must not be. An administrator who
//     publishes a policy set that drops this rule would hand every leaked token
//     in the fleet an account takeover, with the mistake looking like an ordinary
//     policy change in review.
func (s *Server) requireDeviceBound(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := SessionFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !session.DeviceBound {
			// Says what to do, not just no. Somebody hitting this from a script
			// has hit a wall the design put there on purpose, and the useful
			// information is that no token will ever work.
			writeError(w, http.StatusForbidden,
				"credentials can only be managed with a passkey — an access token "+
					"cannot change what authenticates as you, however privileged "+
					"its owner")
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
		// CSRF defends cookie-authenticated requests. The OIDC protocol
		// endpoints do not use cookies: the token, revocation and
		// introspection endpoints authenticate with client credentials or
		// PKCE, and are called server-to-server by relying parties that have
		// no cookie jar and no way to obtain a token from us.
		//
		// Requiring one there does not add protection — there is no ambient
		// authority to abuse — and breaks every client. The browser-facing
		// /oidc/authorize is a GET, which is exempt below anyway.
		if isOIDCProtocolPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Machines, for the same reason. A host has no cookie jar: it either
		// holds an enrollment token it was handed at a console, or it signs the
		// request with a key it generated itself. Neither is ambient authority a
		// browser could be tricked into replaying, and neither client can be
		// made to read a cookie it never received.
		if isHostProtocolPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// ACME, for the third time and the same reason. Every request is a JWS
		// signed by an account key; there is no cookie, no ambient authority,
		// and a client is a machine with no browser to be tricked.
		if strings.HasPrefix(r.URL.Path, "/acme/") {
			next.ServeHTTP(w, r)
			return
		}

		// A request authenticated by a bearer token has no ambient authority to
		// abuse: nothing attaches an Authorization header on a browser's behalf
		// the way it attaches a cookie, which is the entire premise of CSRF.
		//
		// The test is what actually authenticated this request, not whether a
		// header happens to be present. Skipping on the mere presence of one
		// would be a hole: a page that can add a header to a cookie-carrying
		// request could switch the protection off. authenticate() prefers the
		// cookie for the same reason, so a request holding both is
		// cookie-authenticated and still lands here.
		if session, ok := SessionFrom(r.Context()); ok &&
			session.AuthMethod == store.AuthMethodAccessToken {
			next.ServeHTTP(w, r)
			return
		}

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
						Name:  csrfCookie,
						Value: token,
						Path:  "/",
						// Same scope as the session cookie: the SPA runs on the
						// Cardinal host but the token must survive alongside a
						// parent-domain session.
						Domain:   s.cfg.Server.CookieDomain,
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

// isOIDCProtocolPath reports whether a path belongs to the OIDC provider.
//
// A closed list rather than a prefix-with-exceptions, so adding a
// cookie-authenticated endpoint under /oidc/ later does not silently inherit
// the exemption.
func isOIDCProtocolPath(path string) bool {
	switch path {
	case "/oidc/token", "/oidc/revoke", "/oidc/introspect",
		"/oidc/userinfo", "/oidc/keys", "/.well-known/openid-configuration":
		return true
	}
	return false
}

// isHostProtocolPath reports whether a path is spoken by a machine.
//
// A closed list, like the OIDC one and for a sharper reason: /api/hosts/ will
// also hold the administrator-facing endpoints for managing hosts, and those are
// cookie-authenticated and must keep their CSRF protection. Adding a path here
// is a decision to make, never something to inherit from a prefix.
func isHostProtocolPath(path string) bool {
	switch path {
	case "/api/hosts/enroll", "/api/hosts/me", "/api/hosts/assignment",
		"/api/hosts/certificate":
		return true
	}
	return false
}

// rateLimit bounds attempts per client for an endpoint.
func (s *Server) rateLimit(limit store.RateLimit) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := s.clientIP.resolve(r)

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

func setSessionCookie(w http.ResponseWriter, token string, expires time.Time, secure bool, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookie,
		Value: token,
		Path:  "/",
		// Empty Domain means host-only, which is the safe default. Setting it
		// is what makes one sign-in cover every application behind the proxy.
		Domain: domain,
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

func clearCookie(w http.ResponseWriter, name string, secure bool, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:  name,
		Value: "",
		Path:  "/",
		// Must match how it was set, or the browser keeps the original and
		// signing out appears to do nothing.
		Domain:   domain,
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

// sessionOrigin describes where a request came from, for the session it opens.
//
// The address comes from the resolver rather than RemoteAddr, so a deployment
// behind Traefik records the browser's address and not the proxy's — and one
// that is *not* behind a trusted proxy ignores a forwarded header a client made
// up. Getting that backwards would fill the column with whatever an attacker
// wanted somebody to see when they checked their sessions.
func (s *Server) sessionOrigin(r *http.Request) store.SessionOrigin {
	return store.SessionOrigin{
		ClientIP:  s.clientIP.resolve(r),
		UserAgent: r.UserAgent(),
	}
}
