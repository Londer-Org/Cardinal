package httpapi

import (
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/store"
)

// The bridge between the OIDC library and Cardinal's own authentication.
//
// zitadel/oidc handles the protocol and hands off when it needs a user: an
// unauthenticated /authorize redirects to the client's LoginURL, and the
// library expects to be told when that user comes back. These two handlers are
// that hand-off.

// handleOIDCLogin receives an authorization request needing a signed-in user.
//
// If there is already a session, the flow continues immediately — which is what
// makes it single sign-on rather than sign-in-again-per-application. Otherwise
// the browser goes to the login page carrying the request ID, and returns here.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	requestID, err := uuid.Parse(r.URL.Query().Get("auth"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid authorization request")
		return
	}

	// Confirm the request exists and is live before sending anyone anywhere. An
	// expired request would otherwise send the user through a full sign-in only
	// to fail at the end.
	authReq, err := s.store.AuthRequestByID(ctx, requestID)
	if err != nil {
		writeError(w, http.StatusBadRequest,
			"this authorization request has expired — start again from the application")
		return
	}

	session, authenticated := SessionFrom(ctx)

	// What the client asked for about authentication itself.
	//
	// `prompt=login` and `max_age` are requests for a ceremony, not opinions
	// about whether one looks necessary — a client asking for either is usually
	// about to do something that matters, and answering from an hours-old
	// session tells it something untrue. Evaluated before consent and before
	// access, because if the answer is "authenticate again" then nothing else
	// on this request has been established yet.
	needsFresh := !authenticated ||
		authReq.RequiresFreshAuthentication(session.AuthAt)

	// `prompt=none` forbids showing the user anything at all. So a request that
	// would need an interaction cannot be satisfied, and the specification is
	// explicit about the answer: fail back to the client rather than render a
	// page it told us not to render.
	if needsFresh && authReq.PromptedFor("none") {
		s.log.InfoContext(ctx, "OIDC authorization refused",
			"reason", "prompt=none but authentication is required",
			"client", authReq.ClientID)
		redirectAuthError(w, r, authReq, "login_required",
			"authentication is required, and prompt=none forbids asking for it")
		return
	}

	// Access first, then consent. Asking someone to agree to release claims to
	// an application they may not use would be a strange question, and agreeing
	// would leave a consent record for access that never happened.
	if authenticated {
		client, oIDCClientByIDErr := s.store.OIDCClientByID(ctx, authReq.ClientID)
		if oIDCClientByIDErr != nil {
			writeError(w, http.StatusBadRequest, "unknown application")
			return
		}
		access, oIDCClientByIDErr := s.canAccessApplication(ctx, session, client)
		if oIDCClientByIDErr != nil {
			s.log.ErrorContext(ctx, "application access check failed", "error", oIDCClientByIDErr)
			writeError(w, http.StatusServiceUnavailable, "authorization unavailable")
			return
		}
		if !access.Allowed {
			s.denyApplicationAccess(w, client, access)
			return
		}
	}

	// A signed-in user still stops here if the application requires consent.
	// This is the single-sign-on path — the common one — so completing it
	// silently would have meant consent applied only to people who happened not
	// to have a session yet.
	askFirst := false
	if authenticated {
		askFirst, err = s.needsConsent(ctx, session.SubjectID, authReq)
		if err != nil {
			s.log.ErrorContext(ctx, "reading consent failed", "error", err)
			writeError(w, http.StatusInternalServerError, "could not check consent")
			return
		}
	}

	if needsFresh || askFirst {
		// Send them to the UI, remembering what is waiting. The target is
		// Cardinal's own path, so there is no open-redirect surface here. The
		// SPA works out whether that means signing in, agreeing, or both.
		//
		// `reauth` is what tells it that an existing session is not enough. The
		// SPA would otherwise see a signed-in user with a pending request and
		// resume it, which is exactly the silent completion the client asked us
		// not to perform.
		query := url.Values{"oidc_auth": {requestID.String()}}
		if authenticated && needsFresh {
			query.Set("reauth", "1")
		}
		target := url.URL{Path: "/", RawQuery: query.Encode()}
		http.Redirect(w, r, target.String(), http.StatusFound)
		return
	}

	if err := s.oidc.Storage().CompleteAuthentication(
		ctx, requestID, session.SubjectID, session); err != nil {
		s.log.ErrorContext(ctx, "completing OIDC authentication failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not complete sign-in")
		return
	}

	s.log.InfoContext(ctx, "OIDC authorization completed",
		"subject", session.SubjectID, "auth_method", session.AuthMethod)

	// Back to the library, which mints the code and redirects to the client.
	http.Redirect(w, r, "/oidc/authorize/callback?id="+requestID.String(),
		http.StatusFound)
}

// handleOIDCResume is called by the admin UI once a user has signed in with an
// OIDC authorization pending.
//
// A separate endpoint from handleOIDCLogin because the SPA needs a JSON answer
// it can act on, rather than a redirect it would have to follow itself.
func (s *Server) handleOIDCResume(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	requestID, err := uuid.Parse(r.URL.Query().Get("auth"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid authorization request")
		return
	}

	authReq, err := s.store.AuthRequestByID(ctx, requestID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "this authorization request has expired")
		return
	}

	client, err := s.store.OIDCClientByID(ctx, authReq.ClientID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown application")
		return
	}
	access, err := s.canAccessApplication(ctx, session, client)
	if err != nil {
		s.log.ErrorContext(ctx, "application access check failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}
	if !access.Allowed {
		s.denyApplicationAccess(w, client, access)
		return
	}

	// Freshness is enforced here too, for the same reason consent is: resume is
	// reachable directly, so a rule applied only on the redirect path is a rule
	// anything skipping the SPA can skip. The SPA is expected to have performed
	// a step-up before calling this; if it has not, `session.AuthAt` is still
	// old and this refuses.
	if authReq.RequiresFreshAuthentication(session.AuthAt) {
		writeError(w, http.StatusForbidden,
			"this application asked you to authenticate again before it can sign you in")
		return
	}

	// Consent is enforced here, not only in the UI.
	//
	// A client that requires consent must not be satisfiable by calling resume
	// directly — otherwise the prompt is advisory, and anything that skips the
	// SPA skips the decision.
	askFirst, err := s.needsConsent(ctx, session.SubjectID, authReq)
	if err != nil {
		s.log.ErrorContext(ctx, "reading consent failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not check consent")
		return
	}
	if askFirst {
		writeError(w, http.StatusForbidden,
			"this application needs your consent before it can sign you in")
		return
	}

	if err := s.oidc.Storage().CompleteAuthentication(
		ctx, requestID, session.SubjectID, session); err != nil {
		s.log.ErrorContext(ctx, "completing OIDC authentication failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not complete sign-in")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"continue": "/oidc/authorize/callback?id=" + requestID.String(),
	})
}

// redirectAuthError returns an OAuth error to the client rather than to the
// user's screen.
//
// Used when the request itself cannot be satisfied — today, `prompt=none` on a
// request that would need an interaction. The client asked not to have its user
// shown anything, so rendering an error page would be both useless to it and a
// contradiction of the parameter.
//
// The redirect URI is not taken on trust: it was validated against the client's
// registration when the library accepted the request, and this reads it back
// from storage rather than from anything the browser sent.
func redirectAuthError(w http.ResponseWriter, r *http.Request,
	authReq *store.AuthRequest, code, description string,
) {
	target, err := url.Parse(authReq.RedirectURI)
	if err != nil {
		// Should be unreachable: the library rejects an unparseable redirect
		// URI long before this. Falling back to a plain error is still better
		// than redirecting somewhere unexamined.
		writeError(w, http.StatusBadRequest, "invalid redirect URI")
		return
	}

	query := target.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	// Echoed because it is the client's CSRF token for this flow; an error
	// without it is one the client cannot safely match to a request it made.
	if authReq.State != "" {
		query.Set("state", authReq.State)
	}
	target.RawQuery = query.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}
