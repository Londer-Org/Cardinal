package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/google/uuid"
)

// Sessions, for the person signed into them.
//
// Until now nothing could see a session — not its owner, not an administrator,
// not the CLI. Revocation existed in the store and had exactly two callers,
// both internal: signing out, and disabling an account. So the answer to "I
// think somebody else is signed in as me" was to change nothing and hope, and
// the answer to "am I still signed in on that laptop I sold" was unknowable.
//
// Self-service and nothing else, on the same reasoning as access tokens: the
// subject comes from the session on every request and never from the URL.

type sessionResponse struct {
	ID string `json:"id"`

	// Current marks the session making this request. Without it the list is a
	// row of near-identical entries and the one thing somebody must not revoke
	// by accident — the one they are using — is indistinguishable.
	Current bool `json:"current"`

	StartedAt time.Time `json:"startedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	EndsAt    time.Time `json:"endsAt"`

	AuthMethod  string    `json:"authMethod"`
	AuthAt      time.Time `json:"authAt"`
	DeviceBound bool      `json:"deviceBound"`

	// Empty when unrecorded. The console says so rather than inventing
	// "Unknown device", which reads like a finding when it is an absence.
	ClientIP  string `json:"clientIp"`
	UserAgent string `json:"userAgent"`
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	sessions, err := s.store.ListSessions(ctx, session.SubjectID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing sessions failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list your sessions")
		return
	}

	out := make([]sessionResponse, 0, len(sessions))
	for _, item := range sessions {
		out = append(out, sessionResponse{
			ID:          item.ID.String(),
			Current:     item.ID == session.ID,
			StartedAt:   item.StartedAt,
			ExpiresAt:   item.ExpiresAt,
			EndsAt:      item.AbsoluteExpiry,
			AuthMethod:  item.AuthMethod,
			AuthAt:      item.AuthAt,
			DeviceBound: item.DeviceBound,
			ClientIP:    item.ClientIP,
			UserAgent:   strings.TrimSpace(item.UserAgent),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// handleRevokeSession ends one, scoped to its owner in the statement itself.
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such session")
		return
	}

	subjectID := session.SubjectID
	if err := s.store.RevokeSessionFor(ctx, id, subjectID, &subjectID); err != nil {
		if errors.Is(err, store.ErrNoSuchSession) {
			writeError(w, http.StatusNotFound, "no such session")
			return
		}
		s.log.ErrorContext(ctx, "revoking a session failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not revoke the session")
		return
	}

	// Revoking the current one is signing out, so the cookie has to go with it.
	// Leaving it behind would send every subsequent request with a credential
	// the server now rejects, and the browser would sit on a console that
	// appears broken rather than signed out.
	if id == session.ID {
		clearCookie(w, sessionCookie, s.secureCookies, s.cfg.Server.CookieDomain)
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeOtherSessions signs out everywhere except here.
//
// The operation somebody wants after losing a device, and it deliberately keeps
// the caller signed in: the alternative locks the person out of the console at
// the moment they are trying to secure their account, which is how people end
// up not doing it at all.
func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	subjectID := session.SubjectID
	count, err := s.store.RevokeOtherSessions(ctx, subjectID, session.ID, &subjectID)
	if err != nil {
		s.log.ErrorContext(ctx, "revoking sessions failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not revoke your sessions")
		return
	}

	s.log.InfoContext(ctx, "sessions revoked", "subject", subjectID, "count", count)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": count})
}
