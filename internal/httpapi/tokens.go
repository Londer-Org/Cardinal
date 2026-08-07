package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/google/uuid"
)

// Access tokens, for their owner.
//
// Self-service and nothing else: every handler here resolves the subject from
// the session and never from the request. There is deliberately no
// administrative path to issue somebody else a token — a credential that
// authenticates as a person should be created by that person, and an
// administrator who could mint one could act as them without it appearing in
// any log as anything but the person themselves.
//
// This existed only as a CLI command until now, which meant the one credential
// that belongs to its owner was the one credential its owner could not obtain.
// An administrator with database access had to run `cardinal token create` for
// them.

// maxTokenTTL bounds how long somebody can ask for.
//
// A year. Long enough that nobody is renewing a build pipeline's token every
// month, short enough that a forgotten token in a forgotten repository stops
// working while the person who created it is still at the company.
const maxTokenTTL = 365 * 24 * time.Hour

// defaultTokenTTL matches the CLI's, so the two do not quietly disagree.
const defaultTokenTTL = 90 * 24 * time.Hour

type tokenResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// Prefix identifies a token in a list without being able to authenticate
	// one — it is what somebody compares against a value in a CI setting to
	// find out which of four tokens they are looking at.
	Prefix string `json:"prefix"`

	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	Expired    bool       `json:"expired"`
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	tokens, err := s.store.ListAccessTokens(ctx, session.SubjectID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing access tokens failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list your tokens")
		return
	}

	out := make([]tokenResponse, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, tokenResponse{
			ID: t.ID.String(), Name: t.Name, Prefix: t.Prefix,
			CreatedAt: t.CreatedAt, ExpiresAt: t.ValidUntil,
			LastUsedAt: t.LastUsedAt, Expired: t.Expired(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

type createTokenRequest struct {
	Name string `json:"name"`

	// Days rather than a duration string. The field is filled in by a select in
	// the console, and a free-text duration is a way to typo "90d" into "90m".
	Days int `json:"days"`
}

// handleCreateToken issues one, shown once.
func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req createTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest,
			"a token needs a name — it is how you tell four of them apart later")
		return
	}

	ttl := defaultTokenTTL
	if req.Days > 0 {
		ttl = time.Duration(req.Days) * 24 * time.Hour
	}
	if ttl > maxTokenTTL {
		writeError(w, http.StatusBadRequest, "a token may not last more than a year")
		return
	}

	subjectID := session.SubjectID
	token, err := s.store.CreateAccessToken(ctx, subjectID, req.Name, ttl, &subjectID)
	if err != nil {
		s.log.ErrorContext(ctx, "creating an access token failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create the token")
		return
	}

	s.log.InfoContext(ctx, "access token created",
		"subject", session.SubjectID, "token", token.ID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        token.ID.String(),
		"name":      token.Name,
		"expiresAt": token.ValidUntil,
		// The only time this is ever returned. Everything after stores and
		// compares a hash, so a console that loses this has to issue another.
		"token": token.Token,
	})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such token")
		return
	}

	// Scoped to the subject in the same statement that revokes, so somebody
	// guessing an id revokes nothing rather than somebody else's token.
	subjectID := session.SubjectID
	if err := s.store.RevokeAccessToken(ctx, id, subjectID, &subjectID); err != nil {
		if errors.Is(err, store.ErrNoSuchToken) {
			writeError(w, http.StatusNotFound, "no such token")
			return
		}
		s.log.ErrorContext(ctx, "revoking an access token failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not revoke the token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
