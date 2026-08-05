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
	if _, err := s.store.AuthRequestByID(ctx, requestID); err != nil {
		writeError(w, http.StatusBadRequest,
			"this authorization request has expired — start again from the application")
		return
	}

	session, authenticated := SessionFrom(ctx)
	if !authenticated {
		// Send them to sign in, remembering where to come back to. The target
		// is Cardinal's own path, so there is no open-redirect surface here.
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

	if _, err := s.store.AuthRequestByID(ctx, requestID); err != nil {
		writeError(w, http.StatusBadRequest, "this authorization request has expired")
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
