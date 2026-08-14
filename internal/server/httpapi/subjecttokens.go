package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// Somebody else's access tokens.
//
// The self-service endpoints take the subject from the session and the request
// body has no say, which is the whole of their security: a token minted for you
// by somebody else is a way to act as you, with your name on the audit trail.
// That stays true, and these do not weaken it.
//
// Issuing is therefore only for a service account. One has no passkeys and
// cannot sign in, so it cannot ask for its own token and somebody has to ask on
// its behalf — and a token acting as a service account is acting as exactly
// what it says, which is the difference. A person is refused here and issues
// their own.
//
// Listing and revoking are a different question and are permitted for both. An
// administrator ending somebody's token in the middle of an incident is doing
// the job, and neither call hands out a credential.

// subjectTokenTypes are the entity types that can hold an access token.
//
// A group or a device cannot authenticate at all, so a route for one would be
// an endpoint that exists to answer 400.
var subjectTokenTypes = []directory.Type{directory.TypeUser, directory.TypeServiceAccount}

// handleIssueSubjectToken issues a token for a service account.
func (s *Server) handleIssueSubjectToken(kind directory.Type) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		session, _ := SessionFrom(ctx)

		entity, err := s.store.LookupEntity(ctx, kind, r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusNotFound, "no such "+string(kind))
			return
		}

		if kind != directory.TypeServiceAccount {
			// Said in full rather than "forbidden", because the person reading
			// it is trying to get somebody a credential and needs to know which
			// door to use instead.
			writeError(w, http.StatusForbidden,
				entity.Name+" is a person, and a token issued for a person by "+
					"somebody else is a way to act as them with their name on the "+
					"audit trail. They issue their own from Access → Tokens. This "+
					"exists for service accounts, which have no passkeys and so "+
					"cannot ask for one themselves")
			return
		}

		var req createTokenRequest
		if decodeErr := decodeJSON(r, &req); decodeErr != nil {
			writeError(w, http.StatusBadRequest, decodeErr.Error())
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

		if len(req.Scopes) == 0 {
			writeError(w, http.StatusBadRequest,
				"say what this token is for: one or more of "+strings.Join(AllScopes, ", ")+
					". A token with no scope can authenticate and nothing else")
			return
		}
		for _, scope := range req.Scopes {
			if !ValidScope(scope) {
				// Refused at issue rather than at use. A misspelled scope
				// produces a token that authenticates and is then refused
				// everything, wherever it is used — usually an unattended
				// pipeline, hours later, with a message about permissions
				// rather than about spelling.
				writeError(w, http.StatusBadRequest,
					"no such scope "+scope+"; Cardinal knows "+strings.Join(AllScopes, ", "))
				return
			}
		}

		actorID := session.SubjectID
		token, err := s.store.CreateAccessToken(ctx, entity.ID, req.Name, ttl, req.Scopes, &actorID)
		if err != nil {
			s.log.ErrorContext(ctx, "issuing an access token failed", "error", err)
			writeError(w, http.StatusInternalServerError, "could not create the token")
			return
		}

		// Warn rather than info: somebody now holds a credential that acts as
		// this account, and who asked for it is the thing an incident review
		// needs.
		s.log.WarnContext(ctx, "access token issued for another subject",
			"subject", entity.Name, "name", req.Name, "scopes", req.Scopes,
			"actor", session.SubjectID)

		writeJSON(w, http.StatusCreated, map[string]any{
			"subject": entity.Name,
			// The only time the value is ever returned. Everything after stores
			// and compares a hash.
			"token":     token.Token,
			"id":        token.ID.String(),
			"name":      token.Name,
			"scopes":    token.Scopes,
			"expiresAt": token.ValidUntil,
		})
	}
}

// handleListSubjectTokens lists somebody's tokens without disclosing any value.
func (s *Server) handleListSubjectTokens(kind directory.Type) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		entity, err := s.store.LookupEntity(ctx, kind, r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusNotFound, "no such "+string(kind))
			return
		}

		tokens, err := s.store.ListAccessTokens(ctx, entity.ID)
		if err != nil {
			s.log.ErrorContext(ctx, "listing access tokens failed", "error", err)
			writeError(w, http.StatusInternalServerError, "could not list them")
			return
		}

		out := make([]tokenResponse, 0, len(tokens))
		for _, t := range tokens {
			out = append(out, tokenResponse{
				ID: t.ID.String(), Name: t.Name, Prefix: t.Prefix,
				CreatedAt: t.CreatedAt, ExpiresAt: t.ValidUntil,
				LastUsedAt: t.LastUsedAt, Expired: t.Expired(),
				Scopes: t.Scopes,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"subject": entity.Name,
			"tokens":  out,
		})
	}
}

// handleRevokeSubjectToken ends one of somebody's tokens.
func (s *Server) handleRevokeSubjectToken(kind directory.Type) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		session, _ := SessionFrom(ctx)

		entity, err := s.store.LookupEntity(ctx, kind, r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusNotFound, "no such "+string(kind))
			return
		}

		tokenID, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "that is not a token id")
			return
		}

		actorID := session.SubjectID
		// The subject is part of the lookup, not only the id: a token id from
		// one person's listing must not end a token belonging to another.
		if revokeErr := s.store.RevokeAccessToken(ctx, tokenID, entity.ID, &actorID); revokeErr != nil {
			if errors.Is(revokeErr, store.ErrNoSuchToken) {
				writeError(w, http.StatusNotFound,
					"no such token for "+entity.Name+", or it has already ended")
				return
			}
			s.log.ErrorContext(ctx, "revoking an access token failed", "error", revokeErr)
			writeError(w, http.StatusInternalServerError, "could not revoke it")
			return
		}

		s.log.WarnContext(ctx, "access token revoked for another subject",
			"subject", entity.Name, "token", tokenID, "actor", session.SubjectID)

		w.WriteHeader(http.StatusNoContent)
	}
}
