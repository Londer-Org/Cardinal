package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// Actions on things the console could already show but not change.
//
// Each of these is small on its own; together they are the difference between a
// console you can look at and one you can work in. Two are worth calling out.
//
// Renaming had no implementation anywhere. The README's first claim against
// LDAP is that identity is an immutable id and the name is an attribute, so
// "renaming a person is an UPDATE, not a migration" — and nothing could rename
// anything.
//
// Rotating a client secret had none either, which meant a leaked secret could
// only be dealt with by disabling the application and registering a new one.
// That changes the client id, so it is a reconfiguration of the application
// anyway — a migration in response to an incident, at the worst moment.

type renameRequest struct {
	Name string `json:"name"`
}

// handleRename changes what an entity is called.
//
// One handler for every type. The whole point of the data model is that a name
// is an ordinary attribute, so a user, a group and a host are renamed the same
// way and by the same code; a per-type endpoint would imply a difference that
// does not exist.
func (s *Server) handleRename(kind directory.Type) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		session, _ := SessionFrom(ctx)

		current, err := s.store.LookupEntity(ctx, kind, r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusNotFound, "no such "+string(kind))
			return
		}

		var req renameRequest
		if newDecoderErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); newDecoderErr != nil {
			writeError(w, http.StatusBadRequest, "could not read the request")
			return
		}

		// System groups are the ones policy names by id, so renaming one breaks
		// nothing — which is exactly why it is tempting and exactly why it is
		// refused. Their names appear in the shipped policy set's comments and
		// in every piece of documentation about this deployment, and a renamed
		// `directory-admins` is a group nobody can find when they need it.
		if current.System {
			writeError(w, http.StatusForbidden,
				"system groups keep their names — policy references them by id, "+
					"but people find them by name")
			return
		}

		actorID := session.SubjectID
		renamed, err := s.store.RenameEntity(ctx, current.ID, req.Name, &actorID)
		if err != nil {
			switch {
			case errors.Is(err, directory.ErrAlreadyExists):
				writeError(w, http.StatusConflict, err.Error())
			case errors.Is(err, directory.ErrInvalidName):
				writeError(w, http.StatusBadRequest, err.Error())
			case errors.Is(err, directory.ErrNotFound):
				writeError(w, http.StatusNotFound, "no such "+string(kind))
			default:
				s.log.ErrorContext(ctx, "renaming failed", "error", err)
				writeError(w, http.StatusInternalServerError, "could not rename")
			}
			return
		}

		s.log.InfoContext(ctx, "entity renamed",
			"entity", renamed.ID, "type", kind, "by", session.SubjectID)

		writeJSON(w, http.StatusOK, map[string]any{"name": renamed.Name})
	}
}

// handleRotateClientSecret replaces an application's secret.
func (s *Server) handleRotateClientSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	actorID := session.SubjectID
	secret, err := s.store.RotateClientSecret(ctx, r.PathValue("clientID"), &actorID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrClientNotFound):
			writeError(w, http.StatusNotFound, "no such application")
		case errors.Is(err, store.ErrPublicClient):
			writeError(w, http.StatusBadRequest,
				"this is a public client: it has no secret, and is protected by "+
					"PKCE instead")
		default:
			s.log.ErrorContext(ctx, "rotating a client secret failed", "error", err)
			writeError(w, http.StatusInternalServerError, "could not rotate the secret")
		}
		return
	}

	s.log.WarnContext(ctx, "client secret rotated",
		"client", r.PathValue("clientID"), "by", session.SubjectID)

	writeJSON(w, http.StatusOK, map[string]any{
		// The only time it is ever returned. Everything after stores and
		// compares a hash, so an application that loses this needs another
		// rotation rather than a lookup.
		"secret": secret,
	})
}

type adminProfileRequest struct {
	DisplayName *string `json:"displayName"`
	Email       *string `json:"email"`
}

// handleUpdateUserProfile edits somebody else's details.
//
// Separate from PATCH /api/auth/me, which edits your own and is not
// administration. Deliberately cannot touch the login: renaming has its own
// endpoint, its own confirmation, and its own consequences, and folding it into
// a profile form is how somebody changes a login while meaning to fix a typo in
// a display name.
func (s *Server) handleUpdateUserProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	entity, err := s.store.LookupEntity(ctx, directory.TypeUser, r.PathValue("login"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	var req adminProfileRequest
	if newDecoderErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); newDecoderErr != nil {
		writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}

	var update store.ProfileUpdate
	if req.DisplayName != nil {
		trimmed := strings.TrimSpace(*req.DisplayName)
		if len(trimmed) > 200 {
			writeError(w, http.StatusBadRequest, "that display name is too long")
			return
		}
		update.DisplayName = &trimmed
	}
	if req.Email != nil {
		trimmed := strings.TrimSpace(*req.Email)
		if trimmed != "" {
			if checkEmailErr := s.checkEmail(trimmed); checkEmailErr != nil {
				writeError(w, statusForEmail(checkEmailErr), checkEmailErr.Error())
				return
			}
		}
		update.Email = &trimmed
	}

	actorID := session.SubjectID
	updated, err := s.store.UpdateProfile(ctx, entity.ID, update, &actorID)
	if err != nil {
		s.log.ErrorContext(ctx, "updating a profile failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not update the account")
		return
	}

	email, _ := updated.Attrs["email"].(string) //nolint:errcheck // a missing or non-string attribute is the empty string
	writeJSON(w, http.StatusOK, map[string]any{
		"displayName": updated.DisplayName,
		"email":       email,
	})
}

type posixRequest struct {
	HomeDirectory string `json:"homeDirectory"`
	LoginShell    string `json:"loginShell"`
}

// handleAssignPOSIX gives somebody a uid, or edits what comes with it.
//
// The number itself is never in the request. It is allocated once and is
// permanent — every file on every disk records it — so offering a field for it
// would be offering a mistake that cannot be corrected once a host has been
// told. `cardinal posix adopt` exists for the one case where it can still
// change, which is before any host has seen it.
func (s *Server) handleAssignPOSIX(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	entity, err := s.store.LookupEntity(ctx, directory.TypeUser, r.PathValue("login"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	var req posixRequest
	if newDecoderErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); newDecoderErr != nil {
		writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}

	actorID := session.SubjectID
	_, err = s.store.POSIXIdentityFor(ctx, entity.ID)
	switch {
	case err == nil:
		// Already has a number: this is an edit of what comes with it.
		if setPOSIXAttributesErr := s.store.SetPOSIXAttributes(ctx, entity.ID,
			req.HomeDirectory, req.LoginShell, &actorID); setPOSIXAttributesErr != nil {
			s.log.ErrorContext(ctx, "updating POSIX attributes failed", "error", setPOSIXAttributesErr)
			writeError(w, http.StatusInternalServerError, "could not update it")
			return
		}
	case errors.Is(err, store.ErrNoPOSIXIdentity):
		if _, assignPOSIXIdentityErr := s.store.AssignPOSIXIdentity(ctx, entity.ID,
			s.cfg.POSIX.Effective(), &actorID); assignPOSIXIdentityErr != nil {
			s.log.ErrorContext(ctx, "assigning a POSIX identity failed", "error", assignPOSIXIdentityErr)
			writeError(w, http.StatusInternalServerError, "could not assign a number")
			return
		}
		// The number comes from the allocator; home and shell come from the
		// request. Two calls because they are two decisions: one is permanent
		// and the other is not.
		if req.HomeDirectory != "" || req.LoginShell != "" {
			if setPOSIXAttributesErr := s.store.SetPOSIXAttributes(ctx, entity.ID,
				req.HomeDirectory, req.LoginShell, &actorID); setPOSIXAttributesErr != nil {
				writeError(w, http.StatusBadRequest, setPOSIXAttributesErr.Error())
				return
			}
		}
	default:
		s.log.ErrorContext(ctx, "reading a POSIX identity failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read it")
		return
	}

	identity, err := s.store.POSIXIdentityFor(ctx, entity.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading back the POSIX identity failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read it back")
		return
	}

	writeJSON(w, http.StatusOK, posixResponse(identity))
}

func posixResponse(p *store.POSIXIdentity) map[string]any {
	return map[string]any{
		"uid":           p.Number,
		"homeDirectory": p.HomeDirectory,
		"loginShell":    p.LoginShell,
		// Adoptable until a host has been told. After that the number is on a
		// filesystem somewhere and changing it would move files rather than
		// edit a row, so the console stops offering to.
		"adoptable": p.Adoptable(),
	}
}
