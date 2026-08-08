package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

// Step-up re-authentication.
//
// Policy can demand a device-bound credential used within the last five minutes
// (ADR 0005). Until this existed there was no way to satisfy that on demand:
// auth_at was set once, at sign-in, so becoming "fresh" meant signing out and
// signing in again — and the window then closed five minutes later, usually
// mid-task. A rule nobody can satisfy is a rule people route around, or delete.
//
// This refreshes the existing session rather than issuing a new one. Rotating
// the cookie on every step-up would sign out anything holding the old one — a
// second tab, an in-flight request — which is a strange consequence for an
// action meant to grant access.

func (s *Server) handleReAuthBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	// Bound to this session's subject, never discoverable. A discoverable
	// ceremony would accept any account's credential and refresh this session
	// with it, which turns "prove it is still you" into "prove someone is here".
	options, ceremonyID, err := s.auth.BeginLogin(ctx, session.SubjectID)
	if err != nil {
		s.log.InfoContext(ctx, "beginning re-authentication failed", "error", err)
		writeError(w, http.StatusBadRequest, "could not start re-authentication")
		return
	}

	writeJSON(w, http.StatusOK, ceremonyResponse{
		CeremonyID: ceremonyID.String(),
		Options:    options,
	})
}

type reAuthFinishRequest struct {
	CeremonyID string          `json:"ceremonyId"`
	Response   json.RawMessage `json:"response"`
}

func (s *Server) handleReAuthFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req reAuthFinishRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ceremonyID, err := uuid.Parse(req.CeremonyID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ceremony id")
		return
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Response)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed authenticator response")
		return
	}

	deviceBound, err := s.auth.ReAuthenticate(ctx, ceremonyID, parsed, session.SubjectID)
	if err != nil {
		s.log.InfoContext(ctx, "re-authentication failed",
			"subject", session.SubjectID, "error", err)
		writeError(w, http.StatusBadRequest, "re-authentication failed")
		return
	}

	if err := s.store.RefreshSessionAuth(ctx, session.ID, deviceBound); err != nil {
		s.log.ErrorContext(ctx, "refreshing session authentication failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not record that")
		return
	}

	s.log.InfoContext(ctx, "session re-authenticated",
		"subject", session.SubjectID, "device_bound", deviceBound)

	// Update the session this request is carrying, so the response below
	// reflects what was just written rather than the state the request arrived
	// with. Without this the UI would be told it still cannot administer, having
	// just proved that it can.
	session.AuthAt = time.Now().UTC()
	session.DeviceBound = deviceBound

	// The whole account shape back, so the UI re-renders from one source of
	// truth rather than patching its own cache.
	s.handleMe(w, r)
}
