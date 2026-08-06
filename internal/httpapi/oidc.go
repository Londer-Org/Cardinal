package httpapi

import (
	"net/http"
	"net/url"

	"github.com/google/uuid"
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

	// Access first, then consent. Asking someone to agree to release claims to
	// an application they may not use would be a strange question, and agreeing
	// would leave a consent record for access that never happened.
	if authenticated {
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

	if !authenticated || askFirst {
		// Send them to the UI, remembering what is waiting. The target is
		// Cardinal's own path, so there is no open-redirect surface here. The
		// SPA works out whether that means signing in, agreeing, or both.
		target := url.URL{Path: "/", RawQuery: url.Values{
			"oidc_auth": {requestID.String()},
		}.Encode()}
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
