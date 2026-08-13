package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"go.londer.be/cardinal/internal/directory"
)

// Creating an entity, and taking it out of service.
//
// Users had these endpoints and no other type did, which made "the API is the
// only mutation path" false for five of the seven types the CLI offers: a
// group, a service account, a device or a role could only be created by
// whoever held the connection string.
//
// Groups had one already, with its own copy of the owner lookup. It is gone:
// two implementations of one operation is how a fix reaches one of them and
// nobody notices, which this project has already paid for once.
//
// One handler per operation across every type, for the reason renaming has one
// (see entityactions.go): the data model says a group and a service account
// differ in their type column and in nothing else that creating them touches.
// Users keep their own create handler because it does something none of the
// others can — issue an enrolment link in the same step — and folding that into
// a general handler would put a flag on five endpoints that cannot honour it.

type createEntityRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`

	// Owner is the application a group exists for, by name, and is meaningful
	// only for a group. Refused rather than ignored elsewhere: a field that
	// silently does nothing is how somebody believes they set an owner
	// (ADR 0032).
	Owner string `json:"owner,omitempty"`
}

type createEntityResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	ID          string `json:"id"`
	Type        string `json:"type"`

	// Owner echoes the application actually recorded. Echoing an empty one back
	// would tell the caller their request was ignored when it was not.
	Owner string `json:"owner,omitempty"`
}

// handleCreateEntity creates one entity of the given type.
func (s *Server) handleCreateEntity(kind directory.Type) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		session, _ := SessionFrom(ctx)

		var req createEntityRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		entity, err := directory.NewEntity(kind,
			strings.TrimSpace(req.Name), strings.TrimSpace(req.DisplayName))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		owner := strings.TrimSpace(req.Owner)
		if owner != "" {
			if kind != directory.TypeGroup {
				writeError(w, http.StatusBadRequest,
					"owner names the application a *group* exists for, and "+
						string(kind)+" is not a group")
				return
			}
			app, lookupErr := s.store.LookupEntity(ctx, directory.TypeApplication, owner)
			if lookupErr != nil {
				writeError(w, http.StatusNotFound, "no such application: "+owner)
				return
			}
			entity.OwnerID = &app.ID
		}

		actorID := session.SubjectID
		if err := s.store.CreateEntity(ctx, entity, &actorID); err != nil {
			writeCreationError(w, err)
			return
		}

		s.log.InfoContext(ctx, "entity created",
			"type", kind, "name", entity.Name, "actor", session.SubjectID)

		writeJSON(w, http.StatusCreated, createEntityResponse{
			Name:        entity.Name,
			DisplayName: entity.DisplayName,
			ID:          entity.ID.String(),
			Type:        string(kind),
			Owner:       owner,
		})
	}
}

// availabilityResponse reports what taking an entity out of service ended.
//
// Counted and returned rather than left to the log, because they are the part
// an operator has to be told: an account disabled while its holder stays signed
// in is not disabled, and somebody who cannot see that the sessions went has no
// way to know whether it worked.
type availabilityResponse struct {
	Name string `json:"name"`

	SessionsRevoked int64 `json:"sessionsRevoked"`
	TokensRevoked   int   `json:"tokensRevoked"`
}

// handleSetAvailability disables or enables one entity of the given type.
func (s *Server) handleSetAvailability(kind directory.Type, enable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		session, _ := SessionFrom(ctx)

		// LookupEntity does not filter on disabled — names resolve either way,
		// which is what makes finding a disabled entity possible at all.
		entity, err := s.store.LookupEntity(ctx, kind, r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusNotFound, "no such "+string(kind))
			return
		}

		actorID := session.SubjectID

		// Enabling restores nothing else on purpose. Disabling revoked the
		// sessions and access tokens, and one that was live while an account
		// was cut off is exactly what should not resume working.
		if enable {
			if enableErr := s.store.EnableEntity(ctx, entity.ID, &actorID); enableErr != nil {
				// The entity was found a moment ago, so "not found" here means
				// the UPDATE matched nothing: it is not disabled. A conflict
				// rather than a 404, which would say the name is wrong.
				if errors.Is(enableErr, directory.ErrNotFound) {
					writeError(w, http.StatusConflict, "that "+string(kind)+" is not disabled")
					return
				}
				s.log.ErrorContext(ctx, "enabling failed", "error", enableErr, "type", kind)
				writeError(w, http.StatusInternalServerError, "could not enable it")
				return
			}
			s.log.InfoContext(ctx, "entity enabled",
				"type", kind, "name", entity.Name, "actor", session.SubjectID)
			writeJSON(w, http.StatusOK, availabilityResponse{Name: entity.Name})
			return
		}

		// Disabling yourself is a mistake nobody means to make, and the
		// recovery costs a shell on the host. Cardinal has no reason to help.
		if entity.ID == session.SubjectID {
			writeError(w, http.StatusBadRequest,
				"you cannot disable your own account — ask another administrator")
			return
		}

		if disableErr := s.store.DisableEntity(ctx, entity.ID, &actorID); disableErr != nil {
			s.log.ErrorContext(ctx, "disabling failed", "error", disableErr, "type", kind)
			writeError(w, http.StatusInternalServerError, "could not disable it")
			return
		}

		// Sessions and tokens do not survive it, and the failure of either is
		// reported rather than logged and swallowed: an entity that is disabled
		// while a token of its own still works is the case somebody would only
		// discover from the outside.
		sessions, err := s.store.RevokeAllSessions(ctx, entity.ID, &actorID)
		if err != nil {
			s.log.ErrorContext(ctx, "revoking sessions failed", "error", err)
			writeError(w, http.StatusInternalServerError,
				"disabled, but its sessions could not be revoked — it may still be "+
					"signed in somewhere")
			return
		}
		tokens, err := s.store.RevokeAllAccessTokens(ctx, entity.ID)
		if err != nil {
			s.log.ErrorContext(ctx, "revoking access tokens failed", "error", err)
			writeError(w, http.StatusInternalServerError,
				"disabled and signed out, but its access tokens could not be "+
					"revoked — they keep working until they expire")
			return
		}

		s.log.InfoContext(ctx, "entity disabled",
			"type", kind, "name", entity.Name, "actor", session.SubjectID,
			"sessions", sessions, "tokens", tokens)

		writeJSON(w, http.StatusOK, availabilityResponse{
			Name:            entity.Name,
			SessionsRevoked: sessions,
			TokensRevoked:   tokens,
		})
	}
}

// writeCreationError answers a failed creation.
//
// One helper because the distinction kept being made in some places and not
// others: a name already taken is a conflict, which a caller can retry around
// or treat as the state it asked for, and a name that is not allowed is a bad
// request it must not retry. Answering 400 for both makes them the same event
// to anything that is not reading the sentence, which seeding scripts and the
// console's error handling are not.
func writeCreationError(w http.ResponseWriter, err error) {
	if errors.Is(err, directory.ErrAlreadyExists) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}
