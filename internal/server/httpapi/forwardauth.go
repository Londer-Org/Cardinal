package httpapi

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
	"go.londer.be/cardinal/internal/server/claims"
	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/internal/store"
)

// Traefik forwardAuth.
//
// Traefik makes a sub-request here for every request to a protected route. A
// 2xx lets the original request through, carrying whatever headers are listed
// in the middleware's authResponseHeaders; anything else is returned to the
// client instead.
//
// This replaces oauth2-proxy plus Keycloak role mappers with one Cedar
// evaluation that also governs SSH and sudo, so "who can reach this" is
// answered by the same reviewable policy set as everything else (ADR 0005).

// Headers describing the authenticated subject.
//
// Named to match what oauth2-proxy emits, so existing backends that already
// read these keep working — the migration should not require touching every
// application.
const (
	headerUser   = "X-Auth-Request-User"
	headerLogin  = "X-Auth-Request-Preferred-Username"
	headerName   = "X-Auth-Request-Name"
	headerGroups = "X-Auth-Request-Groups"
	// Stable identifiers for the same memberships. An application deciding what
	// somebody may do should read these; the names above are for showing a
	// person, and Cardinal reserves the right to rename a group (ADR 0002).
	headerGroupIDs    = "X-Auth-Request-Group-Ids"
	headerAuthMethod  = "X-Auth-Request-Auth-Method"
	headerDeviceBound = "X-Auth-Request-Device-Bound"

	// Cardinal-specific: lets a backend log the decision that admitted a
	// request, so an application's own logs can be correlated with the
	// directory's decision log.
	headerPolicy = "X-Cardinal-Policy"
)

// handleForwardAuth answers Traefik's authorization sub-request.
func (s *Server) handleForwardAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Traefik describes the original request in these headers. They are only
	// trustworthy because Traefik itself is the immediate peer — the same
	// reasoning as X-Forwarded-For, and the same trusted_proxies setting
	// governs it.
	original := originalRequest(r)

	session, authenticated := SessionFrom(ctx)
	if !authenticated {
		// Unauthenticated is not a policy decision, so it is not logged as one.
		// Sending the browser to the login page and remembering where it was
		// going is ordinary flow control.
		s.redirectToLogin(w, r, original)
		return
	}

	// An access token reaches applications only if it was issued for that. The
	// check is here rather than in middleware because this endpoint is not
	// behind requireAuth — an unauthenticated request is a redirect to sign in,
	// not a refusal — so there is no wrapper to hang it on.
	if session.AuthMethod == store.AuthMethodAccessToken &&
		!slices.Contains(session.Scopes, ScopeApplications) {
		s.log.InfoContext(ctx, "forwardAuth: token has no applications scope",
			"host", original.Host, "path", original.Path)
		writeError(w, http.StatusForbidden,
			"this access token was not issued with the applications scope, so it "+
				"cannot reach sites through the proxy")
		return
	}

	subject, err := s.claims.Resolve(ctx, session)
	if err != nil {
		// A disabled account with a live session token lands here. Refusing is
		// what makes disabling take effect immediately.
		s.log.InfoContext(ctx, "forwardAuth: subject could not be resolved", "error", err)
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	// Which application this hostname belongs to.
	//
	// An unregistered hostname is refused here rather than described to policy,
	// the same way an unenrolled machine is refused an SSH certificate: Cardinal
	// decides about things the directory knows, and a rule matching on
	// `resource == Cardinal::Application::"grafana"` must not also match a
	// request whose Host header happens to say grafana.
	app, err := s.store.ApplicationForHostname(ctx, original.Host)
	if err != nil {
		s.unregisteredHost(w, r, subject, original, err)
		return
	}

	// The application's own group memberships, which are what a policy matches
	// on. Resolved through the same path as a person's and a host's, because an
	// application is an entity like any other and "which applications" should
	// not be a third mechanism.
	appSubject, err := s.claims.ResolveByID(ctx, app.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "forwardAuth: resolving application memberships failed",
			"application", app.Name, "error", err)
		writeError(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}

	engine := s.policy.Load()
	if engine == nil {
		// No policy loaded means no basis for allowing anything. Failing closed
		// is the only safe answer, and it is loud rather than silent.
		s.log.ErrorContext(ctx, "forwardAuth: no policy is active — denying all access")
		writeError(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}

	decision := engine.Evaluate(policy.Request{
		Subject:        subject,
		Action:         policy.ActionAccessURL,
		Resource:       types.NewEntityUID(policy.TypeApplication, types.String(app.Name)),
		ResourceGroups: appSubject.Groups,
		Context: map[string]types.Value{
			"host":   types.String(original.Host),
			"path":   types.String(original.Path),
			"method": types.String(original.Method),
		},
	})

	// Logged asynchronously in effect: the write is best-effort, because
	// refusing access when the decision log is unavailable would turn an
	// observability outage into an availability one.
	principalID := subject.ID
	if err := s.store.LogDecision(ctx, store.DecisionRecord{
		DecisionPoint: "forwardAuth",
		PrincipalID:   &principalID,
		Action:        "AccessURL",
		Resource:      original.Host + original.Path,
		Allowed:       decision.Allowed,
		Reasons:       decision.Reasons,
		Errors:        decision.Errors,
		PolicyVersion: decision.Version,
		Context: map[string]any{
			"method":       original.Method,
			"application":  app.Name,
			"auth_method":  subject.Auth.Method,
			"device_bound": subject.Auth.DeviceBound,
			"groups":       subject.GroupNames(),
		},
		Duration: decision.Duration,
	}); err != nil {
		s.log.ErrorContext(ctx, "forwardAuth: decision log write failed", "error", err)
	}

	if len(decision.Errors) > 0 {
		// A policy that failed to evaluate never grants access, but it is a
		// defect in the policy set and must not pass silently.
		s.log.ErrorContext(ctx, "forwardAuth: policy evaluation errors",
			"errors", decision.Errors)
	}

	if !decision.Allowed {
		s.log.InfoContext(ctx, "forwardAuth: denied",
			"subject", subject.Login, "host", original.Host, "path", original.Path,
			"explanation", decision.Explain())

		// 403 rather than a redirect: they are signed in, so sending them back
		// to the login page would loop. The explanation goes in a header the
		// error page can surface, which is how "why was I denied?" reaches the
		// person who asked.
		w.Header().Set(headerPolicy, strings.Join(decision.Reasons, ","))
		writeError(w, http.StatusForbidden, decision.Explain())
		return
	}

	h := w.Header()
	h.Set(headerUser, subject.ID.String())
	h.Set(headerLogin, subject.Login)
	h.Set(headerName, subject.DisplayName)
	h.Set(headerGroups, strings.Join(subject.GroupNames(), ","))
	h.Set(headerGroupIDs, strings.Join(subject.GroupIDs(), ","))
	h.Set(headerAuthMethod, subject.Auth.Method)
	h.Set(headerDeviceBound, boolHeader(subject.Auth.DeviceBound))
	h.Set(headerPolicy, strings.Join(decision.Reasons, ","))

	w.WriteHeader(http.StatusNoContent)
}

// originalRequest describes the request Traefik is asking about.
type forwardedRequest struct {
	Method string
	Host   string
	Path   string
	URI    string
}

func originalRequest(r *http.Request) forwardedRequest {
	get := func(name, fallback string) string {
		if v := r.Header.Get(name); v != "" {
			return v
		}
		return fallback
	}

	proto := get("X-Forwarded-Proto", "https")
	host := get("X-Forwarded-Host", r.Host)
	uri := get("X-Forwarded-Uri", "/")

	path := uri
	if idx := strings.IndexByte(uri, '?'); idx >= 0 {
		path = uri[:idx]
	}

	return forwardedRequest{
		Method: get("X-Forwarded-Method", http.MethodGet),
		Host:   host,
		Path:   path,
		URI:    proto + "://" + host + uri,
	}
}

// redirectToLogin sends an unauthenticated browser to sign in, remembering
// where it was going.
//
// The return URL is validated against the configured origins rather than echoed
// back. An unchecked redirect parameter is an open-redirect, and on a login page
// that is a phishing primitive: an attacker sends a victim to a genuine
// Cardinal URL that bounces them somewhere else after signing in.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request, original forwardedRequest) {
	// Non-browser clients get a 401 rather than a redirect; an API client
	// following a redirect to an HTML login page produces a confusing error far
	// from its cause.
	if !acceptsHTML(r) {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	target := s.cfg.Server.PublicURL
	if target == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	loginURL, err := url.Parse(target)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if s.isAllowedReturnTarget(original.URI) {
		q := loginURL.Query()
		q.Set("return_to", original.URI)
		loginURL.RawQuery = q.Encode()
	}

	http.Redirect(w, r, loginURL.String(), http.StatusFound)
}

// isAllowedReturnTarget reports whether a URL may be redirected to after login.
//
// Only hosts within the configured WebAuthn origins, or subdomains of the
// relying party. Everything else is dropped silently: the user still reaches
// the login page, they simply land on the dashboard afterwards instead of being
// bounced to an attacker's site.
func (s *Server) isAllowedReturnTarget(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}

	host := strings.ToLower(u.Hostname())
	rpID := strings.ToLower(s.cfg.WebAuthn.RPID)
	if host == rpID || strings.HasSuffix(host, "."+rpID) {
		return true
	}

	for _, origin := range s.cfg.WebAuthn.Origins {
		if o, err := url.Parse(origin); err == nil &&
			strings.EqualFold(o.Hostname(), host) {
			return true
		}
	}
	return false
}

// unregisteredHost refuses a hostname no application claims.
//
// This is the one deny here that policy did not produce, and it replaces a
// function that classified every hostname as "staff" — which made the shipped
// rule permitting staff applications permit everything, while reading as though
// it distinguished between them. Refusing is the same choice the SSH decision
// point already makes for a machine nobody enrolled.
//
// Logged as a decision even though no policy was consulted, because "why was I
// denied?" is answered from the decision log and an answer that is simply
// missing sends whoever is asking to the wrong place. The reasons list is empty,
// which the explorer already renders as default-deny, and the context says which
// kind of default-deny this was.
func (s *Server) unregisteredHost(
	w http.ResponseWriter, r *http.Request,
	subject *claims.Subject, original forwardedRequest, cause error,
) {
	ctx := r.Context()

	s.log.WarnContext(ctx, "forwardAuth: no application is registered for this hostname",
		"host", original.Host, "path", original.Path,
		"subject", subject.Login, "error", cause)

	principalID := subject.ID
	if err := s.store.LogDecision(ctx, store.DecisionRecord{
		DecisionPoint: "forwardAuth",
		PrincipalID:   &principalID,
		Action:        "AccessURL",
		Resource:      original.Host + original.Path,
		Allowed:       false,
		Context: map[string]any{
			"method":            original.Method,
			"unregistered_host": true,
			"auth_method":       subject.Auth.Method,
			"device_bound":      subject.Auth.DeviceBound,
		},
	}); err != nil {
		s.log.ErrorContext(ctx, "forwardAuth: decision log write failed", "error", err)
	}

	// The remedy is in the message because the alternative is an administrator
	// reading a generic 403 and going looking for a policy bug that is not
	// there. The person seeing it is signed in, so this tells them nothing about
	// the deployment they could not learn by visiting the URL.
	writeError(w, http.StatusForbidden,
		"This address is not registered with Cardinal, so no policy governs it. "+
			"An administrator can register it with "+
			"`cardinal app hostname add <application> "+original.Host+"`.")
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func boolHeader(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
