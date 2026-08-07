package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/arthur-lonfils/cardinal/internal/auth"
	"github.com/arthur-lonfils/cardinal/internal/claims"
	"github.com/arthur-lonfils/cardinal/internal/config"
	"github.com/arthur-lonfils/cardinal/internal/oidcprovider"
	"github.com/arthur-lonfils/cardinal/internal/policy"
	"github.com/arthur-lonfils/cardinal/internal/sshca"
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
	claims   *claims.Resolver

	// sshCA is nil unless host access is configured. A certificate authority
	// nobody has enrolled hosts against is a signing key sitting in a database
	// for no reason, so it stays off until asked for.
	sshCA *sshca.CA

	// oidc is nil when the provider is disabled, which is the default: an
	// identity provider nobody has registered clients for is attack surface
	// without a purpose.
	oidc *oidcprovider.Provider

	// policy holds the live engine behind an atomic pointer.
	//
	// Reloading swaps the whole engine rather than mutating one, so an
	// in-flight request can never observe a half-applied policy change — it
	// evaluates entirely against the old set or entirely against the new.
	policy atomic.Pointer[policy.Engine]
}

// ReloadPolicy swaps in a new policy version.
func (s *Server) ReloadPolicy(engine *policy.Engine) {
	s.policy.Store(engine)
	if engine != nil {
		s.log.Info("policy set loaded",
			"version", engine.Version(), "policies", len(engine.PolicyIDs()))

		// Cedar is default-deny, so an action this set never mentions is one
		// that will be refused every time — correct, and indistinguishable from
		// a bug to whoever hits it.
		//
		// The case worth catching is an upgrade: Cardinal gains an action, the
		// deployment keeps running its existing policy set, and an
		// administrator is told they are not a member of a group they are a
		// member of. Warning rather than refusing to start, because a
		// deliberately narrow policy set is a legitimate thing to run.
		if missing := engine.UngovernedActions(); len(missing) > 0 {
			s.log.Warn("the active policy set never mentions some actions, "+
				"so they will be refused for everyone — republish "+
				"policies/cardinal.cedar if this deployment was upgraded",
				"actions", missing, "version", engine.Version())
		}
	}
}

type Options struct {
	DevMode bool
	UI      fs.FS
	Logger  *slog.Logger

	// OIDC enables the OpenID Connect provider. Nil leaves it off.
	OIDC *oidcprovider.Provider

	// SSHCA enables host access by certificate. Nil leaves it off, which is
	// the default: a certificate authority nobody has enrolled hosts against
	// is a signing key in a database for no reason.
	SSHCA *sshca.CA
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

	srv := &Server{
		store: s, auth: a, cfg: cfg, log: log,
		// Secure cookies are the default; dev mode is the only way to opt out,
		// so forgetting to configure something cannot silently downgrade them.
		secureCookies: !opts.DevMode,
		devMode:       opts.DevMode,
		ui:            opts.UI,
		clientIP:      resolver,
		claims:        claims.NewResolver(s),
		oidc:          opts.OIDC,
		sshCA:         opts.SSHCA,
	}
	return srv, nil
}

// Handler builds the routing tree.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// ── Authentication, anonymous but rate limited ──────────────────────────
	mux.Handle("POST /api/auth/login/begin",
		s.rateLimit(store.LimitLoginBegin)(http.HandlerFunc(s.handleLoginBegin)))
	mux.Handle("POST /api/auth/login/finish",
		s.rateLimit(store.LimitLoginFinish)(http.HandlerFunc(s.handleLoginFinish)))

	mux.Handle("GET /api/auth/me", s.requireAuth(http.HandlerFunc(s.handleMe)))

	// Tiered: people go to user-admins, applications to security-admins, and
	// directory-admins holds both. An endpoint added without a tier in mind
	// falls to requireAdmin, which is the strictest of the three.
	people := func(h http.HandlerFunc) http.Handler {
		return s.requireAuth(s.requirePermission(policy.ActionManageUsers, h))
	}
	apps := func(h http.HandlerFunc) http.Handler {
		return s.requireAuth(s.requirePermission(policy.ActionManageApplications, h))
	}
	mux.Handle("POST /api/auth/logout", s.requireAuth(http.HandlerFunc(s.handleLogout)))

	// Editing your own name and email. Not behind requireAdmin: correcting a
	// typo in your own display name is not administering the directory, and
	// demanding a fresh security key for it would make the step-up rule
	// something people resent rather than respect.
	mux.Handle("PATCH /api/auth/me", s.requireAuth(http.HandlerFunc(s.handleUpdateProfile)))

	// Step-up. Rate-limited like login, because it is a login in everything but
	// the session it does not create.
	mux.Handle("POST /api/auth/reauth/begin",
		s.requireAuth(s.rateLimit(store.LimitLoginBegin)(http.HandlerFunc(s.handleReAuthBegin))))
	mux.Handle("POST /api/auth/reauth/finish",
		s.requireAuth(s.rateLimit(store.LimitLoginFinish)(http.HandlerFunc(s.handleReAuthFinish))))

	// Enrollment. Unauthenticated by necessity — the whole point is that the
	// account has no credential yet — so each of these carries its own rate
	// limit and the invitation token is the only thing that authorises them.
	mux.HandleFunc("GET /api/enroll", s.handleInvitationDetails)
	mux.HandleFunc("POST /api/enroll/begin", s.handleEnrollBegin)
	mux.HandleFunc("POST /api/enroll/finish", s.handleEnrollFinish)

	// Issuing them is administration.
	mux.Handle("POST /api/invitations", people(s.handleIssueInvitation))

	// Recovery restores an account that can already sign in, so it can mint a
	// credential on an administrator's account. That needs the broad tier, and
	// two of them.
	recovery := func(h http.HandlerFunc) http.Handler {
		return s.requireAuth(s.requirePermission(policy.ActionAdministerData, h))
	}
	mux.Handle("GET /api/recoveries", recovery(s.handleListRecoveries))
	mux.Handle("POST /api/recoveries", recovery(s.handleRequestRecovery))
	mux.Handle("POST /api/recoveries/{login}/approve", recovery(s.handleApproveRecovery))
	mux.Handle("DELETE /api/recoveries/{login}", recovery(s.handleCancelRecovery))
	mux.Handle("GET /api/invitations", people(s.handleListInvitations))
	mux.Handle("DELETE /api/invitations/{login}", people(s.handleRevokeInvitation))

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

	// ── Host enrollment ────────────────────────────────────────────────────
	//
	// Enrolling is unauthenticated by necessity — a machine with no credential
	// is exactly what this exists to fix — so the token carries the whole
	// authorization, and it is rate limited like every other unauthenticated
	// credential path.
	mux.Handle("POST /api/hosts/enroll",
		s.rateLimit(store.LimitHostEnroll)(http.HandlerFunc(s.handleHostEnroll)))
	mux.Handle("GET /api/hosts/me", s.requireHost(http.HandlerFunc(s.handleHostSelf)))
	mux.Handle("GET /api/hosts/assignment",
		s.requireHost(http.HandlerFunc(s.handleHostAssignment)))

	// ── Host access ────────────────────────────────────────────────────────
	//
	// The only place SSH access is decided. sshd does no thinking at login, so
	// whatever this returns is what a host will believe for the certificate's
	// lifetime.
	if s.sshCA != nil {
		mux.Handle("POST /api/ssh/certificate",
			s.requireAuth(http.HandlerFunc(s.handleIssueSSHCertificate)))
	}

	// ── Traefik forwardAuth ────────────────────────────────────────────────
	// Any method: Traefik mirrors the original request's method here, and a
	// POST to a protected route must be authorized the same as a GET.
	mux.HandleFunc("/api/auth/verify", s.handleForwardAuth)

	// ── Decision explorer ──────────────────────────────────────────────────
	mux.Handle("GET /api/decisions", s.requireAuth(http.HandlerFunc(s.handleDecisions)))

	// Application management. Behind requireAdmin, which evaluates
	// Cardinal::Action::"AdministerDirectory" — anyone who can register a client
	// chooses its redirect URIs and whether it asks for consent, which is enough
	// to build a phishing surface inside the organisation's own IdP.
	// People and groups. Membership is what every policy reads, so granting one
	// is administration in the fullest sense.
	mux.Handle("GET /api/directory/users", people(s.handleListUsers))
	mux.Handle("POST /api/directory/users", people(s.handleCreateUser))
	mux.Handle("GET /api/directory/users/{login}", people(s.handleGetUser))
	mux.Handle("DELETE /api/directory/users/{login}", people(s.handleDisableUser))

	mux.Handle("GET /api/directory/groups", people(s.handleListGroups))
	mux.Handle("GET /api/directory/applications", people(s.handleListApplicationNames))
	mux.Handle("POST /api/directory/groups", people(s.handleCreateGroup))
	mux.Handle("GET /api/directory/groups/{name}", people(s.handleGetGroup))
	mux.Handle("POST /api/directory/groups/{name}/members", people(s.handleGrantMembership))
	mux.Handle("DELETE /api/directory/groups/{name}/members/{member}", people(s.handleRevokeMembership))

	mux.Handle("GET /api/applications", apps(s.handleListApplications))
	mux.Handle("POST /api/applications", apps(s.handleRegisterApplication))
	mux.Handle("GET /api/applications/{clientID}", apps(s.handleGetApplication))
	mux.Handle("DELETE /api/applications/{clientID}", apps(s.handleDisableApplication))
	mux.Handle("GET /api/policy", s.requireAuth(http.HandlerFunc(s.handlePolicy)))

	// ── OpenID Connect ─────────────────────────────────────────────────────
	if s.oidc != nil {
		// The library serves discovery, /authorize, /token, /userinfo and JWKS
		// on its own paths. Mounted directly rather than proxied, so its
		// well-known URLs are where every client expects them.
		// Everything the library owns lives under /oidc/, except discovery,
		// whose path is fixed by the specification. Cardinal's own bridge
		// handlers are registered after, and the more specific pattern wins in
		// Go's ServeMux.
		oidcHandler := s.oidc.Handler()

		// Cardinal's own discovery document, not the library's: the library
		// hardcodes response and grant types that no client here can use.
		mux.Handle("/.well-known/openid-configuration", s.oidc.DiscoveryHandler())
		mux.Handle("/oidc/", oidcHandler)

		// The hand-off between the library and Cardinal's own authentication.
		// More specific than "/oidc/", so it takes precedence.
		mux.HandleFunc("GET /oidc/login", s.handleOIDCLogin)
		mux.Handle("GET /api/oidc/pending",
			s.requireAuth(http.HandlerFunc(s.handlePendingAuthorization)))
		mux.Handle("POST /api/oidc/consent",
			s.requireAuth(http.HandlerFunc(s.handleConsentDecision)))
		mux.Handle("GET /api/oidc/resume",
			s.requireAuth(http.HandlerFunc(s.handleOIDCResume)))

		// Standing consents, and withdrawing them. Available whether or not any
		// client currently requires consent: a client's setting can change
		// after agreement was given, and the user must still be able to see and
		// undo what they agreed to.
		mux.Handle("GET /api/consents",
			s.requireAuth(http.HandlerFunc(s.handleListConsents)))
		mux.Handle("DELETE /api/consents/{clientID}",
			s.requireAuth(http.HandlerFunc(s.handleRevokeConsent)))
	}

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
