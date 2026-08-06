package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/google/uuid"
)

// scopeDescriptions render a scope as something a person can weigh.
//
// "profile" tells a user nothing. If a consent screen shows raw scope names,
// the honest reading of any click on it is that nobody understood what they
// agreed to — which makes the whole exercise worse than not asking, because
// now there is a record suggesting they did.
var scopeDescriptions = map[string]string{
	"openid":         "Confirm who you are",
	"profile":        "Your name and username",
	"email":          "Your email address",
	"groups":         "Which groups you belong to",
	"offline_access": "Stay signed in without asking again",
}

type scopeDetail struct {
	Scope       string `json:"scope"`
	Description string `json:"description"`
}

// needsConsent reports whether this user must be asked before this request
// completes.
//
// One function, called from every path that can complete an authorization.
// The first version checked consent only where the SPA resumes, which left the
// single-sign-on path — an already-signed-in user arriving at /oidc/login —
// completing silently. That is the common case, so consent was effectively
// enforced only for users who happened not to have a session yet.
func (s *Server) needsConsent(ctx context.Context, subjectID uuid.UUID, authReq *store.AuthRequest) (bool, error) {
	client, err := s.store.OIDCClientByID(ctx, authReq.ClientID)
	if err != nil {
		return false, err
	}
	if !client.RequireConsent {
		return false, nil
	}

	// Asked once, not every time. A prompt shown on every sign-in becomes
	// something people dismiss without reading, at which point it records
	// agreement nobody gave.
	covered, err := s.store.ConsentCovers(ctx, subjectID, authReq.ClientID, authReq.Scopes)
	if err != nil {
		return false, err
	}
	return !covered, nil
}

type pendingAuthorizationResponse struct {
	Application string        `json:"application"`
	ClientID    string        `json:"clientId"`
	Scopes      []scopeDetail `json:"scopes"`

	// NeedsConsent is false when the client is first-party, or when standing
	// consent already covers what is being asked for. The SPA completes the
	// authorization silently in that case.
	NeedsConsent bool `json:"needsConsent"`

	ExpiresAt time.Time `json:"expiresAt"`
}

// handlePendingAuthorization describes a parked authorization to the SPA.
//
// The SPA calls this before resuming, so it knows whether to show anything.
func (s *Server) handlePendingAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	requestID, err := uuid.Parse(r.URL.Query().Get("auth"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid authorization request")
		return
	}

	authReq, err := s.store.AuthRequestByID(ctx, requestID)
	if err != nil {
		writeError(w, http.StatusBadRequest,
			"this sign-in request has expired — start again from the application")
		return
	}

	client, err := s.store.OIDCClientByID(ctx, authReq.ClientID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown application")
		return
	}

	needsConsent, err := s.needsConsent(ctx, session.SubjectID, authReq)
	if err != nil {
		s.log.ErrorContext(ctx, "reading consent failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not check consent")
		return
	}

	details := make([]scopeDetail, 0, len(authReq.Scopes))
	for _, scope := range authReq.Scopes {
		description, known := scopeDescriptions[scope]
		if !known {
			// An unrecognised scope is shown as itself rather than hidden.
			// Hiding it would mean consenting to something invisible.
			description = scope
		}
		details = append(details, scopeDetail{Scope: scope, Description: description})
	}

	writeJSON(w, http.StatusOK, pendingAuthorizationResponse{
		Application:  client.Name,
		ClientID:     client.ClientID,
		Scopes:       details,
		NeedsConsent: needsConsent,
		ExpiresAt:    authReq.ExpiresAt,
	})
}

type consentDecisionRequest struct {
	Auth    string `json:"auth"`
	Approve bool   `json:"approve"`
}

// handleConsentDecision records the user's answer.
//
// A refusal deletes the authorization request rather than leaving it parked:
// otherwise "no" would mean "not yet", and the application could pick it up on
// the next round trip.
func (s *Server) handleConsentDecision(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req consentDecisionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	requestID, err := uuid.Parse(req.Auth)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid authorization request")
		return
	}

	authReq, err := s.store.AuthRequestByID(ctx, requestID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "this sign-in request has expired")
		return
	}

	if !req.Approve {
		if err := s.store.DeleteAuthRequest(ctx, requestID); err != nil {
			s.log.ErrorContext(ctx, "discarding refused authorization failed", "error", err)
		}
		s.log.InfoContext(ctx, "authorization refused by user",
			"client_id", authReq.ClientID)
		writeJSON(w, http.StatusOK, map[string]any{"approved": false})
		return
	}

	if err := s.store.RecordConsent(ctx, session.SubjectID,
		authReq.ClientID, authReq.Scopes); err != nil {
		s.log.ErrorContext(ctx, "recording consent failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not record your decision")
		return
	}
	if err := s.store.MarkConsentGiven(ctx, requestID); err != nil {
		s.log.ErrorContext(ctx, "marking consent failed", "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]any{"approved": true})
}

type consentResponse struct {
	ClientID    string        `json:"clientId"`
	Application string        `json:"application"`
	Scopes      []scopeDetail `json:"scopes"`
	GrantedAt   time.Time     `json:"grantedAt"`
}

// handleListConsents shows what the user has agreed to.
//
// Without somewhere to see and withdraw it, consent is a click you cannot take
// back — which makes the prompt a formality rather than a decision.
func (s *Server) handleListConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	consents, err := s.store.ConsentsFor(ctx, session.SubjectID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing consents failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list applications")
		return
	}

	out := make([]consentResponse, 0, len(consents))
	for _, c := range consents {
		details := make([]scopeDetail, 0, len(c.Scopes))
		for _, scope := range c.Scopes {
			description, known := scopeDescriptions[scope]
			if !known {
				description = scope
			}
			details = append(details, scopeDetail{Scope: scope, Description: description})
		}
		out = append(out, consentResponse{
			ClientID:    c.ClientID,
			Application: c.ApplicationName,
			Scopes:      details,
			GrantedAt:   c.GrantedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRevokeConsent withdraws agreement, and the tokens it produced with it.
func (s *Server) handleRevokeConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	clientID := r.PathValue("clientID")
	if clientID == "" {
		writeError(w, http.StatusBadRequest, "missing application")
		return
	}

	if err := s.store.RevokeConsent(ctx, session.SubjectID, clientID); err != nil {
		if errors.Is(err, store.ErrConsentNotFound) {
			writeError(w, http.StatusNotFound, "no such application")
			return
		}
		s.log.ErrorContext(ctx, "revoking consent failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not withdraw access")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
