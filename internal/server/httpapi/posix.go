package httpapi

import (
	"errors"
	"net/http"
	"time"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// POSIX numbers over the API.
//
// A uid was reachable here for a person and nowhere else: groups had no route,
// nothing could list what had been handed out, and adoption — the one operation
// that makes migrating an existing fleet possible — was CLI-only. Since the CLI
// reaches PostgreSQL directly (ADR 0033), that meant migrating a fleet required
// the database credential.
//
// The number is never in an assign request. It is allocated once and is
// permanent, because every file on every disk records it, so a field for it
// would be a mistake nobody can correct. Adoption is the one path where it can
// still change, and it has its own route and its own refusals for that reason.

type posixIdentityResponse struct {
	Name string `json:"name"`
	Type string `json:"type"`

	// Number is a uid for a user and a gid for a group. One allocator serves
	// both, so the two can never collide.
	Number int `json:"number"`

	HomeDirectory string `json:"homeDirectory,omitempty"`
	LoginShell    string `json:"loginShell,omitempty"`

	// FirstServedAt is when a host was first told this number. Null means it
	// can still be adopted; set means it is on a filesystem somewhere and
	// changing it moves files rather than editing a row.
	FirstServedAt *time.Time `json:"firstServedAt"`
}

func describePOSIX(p *store.POSIXIdentity) posixIdentityResponse {
	return posixIdentityResponse{
		Name:          p.Name,
		Type:          string(p.Type),
		Number:        p.Number,
		HomeDirectory: p.HomeDirectory,
		LoginShell:    p.LoginShell,
		FirstServedAt: p.FirstServedAt,
	}
}

// handleListPOSIX lists every number handed out.
//
// The question behind it is "what is already taken", which an operator asks
// before adopting anything and which the per-entity views cannot answer.
func (s *Server) handleListPOSIX(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	identities, err := s.store.ListPOSIXIdentities(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing POSIX identities failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list them")
		return
	}

	out := make([]posixIdentityResponse, 0, len(identities))
	for i := range identities {
		out = append(out, describePOSIX(&identities[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": out})
}

// handleAssignGroupPOSIX gives a group a gid.
//
// Separate from the user route rather than one route over a type parameter,
// because the two carry different things: a group has no home directory and no
// login shell, and a single endpoint would have to accept and then ignore them.
func (s *Server) handleAssignGroupPOSIX(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	entity, err := s.store.LookupEntity(ctx, directory.TypeGroup, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such group")
		return
	}

	actorID := session.SubjectID
	identity, err := s.store.POSIXIdentityFor(ctx, entity.ID)
	switch {
	case err == nil:
		// Idempotent. A group already has one number and it cannot change, so
		// asking again is answered rather than refused.
		writeJSON(w, http.StatusOK, describePOSIX(identity))
		return
	case errors.Is(err, store.ErrNoPOSIXIdentity):
	default:
		s.log.ErrorContext(ctx, "reading a POSIX identity failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read it")
		return
	}

	assigned, err := s.store.AssignPOSIXIdentity(ctx, entity.ID, s.cfg.POSIX.Effective(), &actorID)
	if err != nil {
		s.log.ErrorContext(ctx, "assigning a group POSIX identity failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not assign a number")
		return
	}
	writeJSON(w, http.StatusCreated, describePOSIX(assigned))
}

type adoptRequest struct {
	// A pointer so an absent field can be told from an explicit zero. They
	// deserve different answers: one is a malformed request, and the other is
	// somebody asking for root's uid, which is worth naming rather than
	// reporting as a missing field.
	Number *int `json:"number"`
}

// handleAdoptPOSIX takes a number a machine already uses.
//
// The migration operation. A uid that disagrees is the one finding that blocks
// a cutover, because the moment Cardinal wins every file that account owns is
// reattributed — so the answer is to take the fleet's number rather than
// renumber the filesystem.
//
// The store refuses one that has already been served to a host, and that
// refusal is the whole safety of this: past that point the number is on a
// filesystem and changing it moves files.
func (s *Server) handleAdoptPOSIX(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	entity, err := s.store.LookupEntity(ctx, directory.TypeUser, r.PathValue("login"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	var req adoptRequest
	if decodeErr := decodeJSON(r, &req); decodeErr != nil {
		writeError(w, http.StatusBadRequest, decodeErr.Error())
		return
	}
	if req.Number == nil {
		writeError(w, http.StatusBadRequest, "a number is required")
		return
	}
	number := *req.Number

	actorID := session.SubjectID
	if adoptErr := s.store.AdoptPOSIXNumber(ctx, entity.ID, number, &actorID); adoptErr != nil {
		if errors.Is(adoptErr, store.ErrNoPOSIXIdentity) {
			writeError(w, http.StatusConflict,
				"this account has no number yet, so there is nothing to adopt into — "+
					"assign one first")
			return
		}
		// Reserved numbers and already-served ones both come back as plain
		// errors carrying the reason, and the reason is the useful part: "1002
		// was served at ..." tells an operator what to do next, and a generic
		// 500 does not.
		s.log.WarnContext(ctx, "adopting a POSIX number was refused",
			"user", entity.Name, "number", number, "error", adoptErr)
		writeError(w, http.StatusConflict, adoptErr.Error())
		return
	}

	identity, err := s.store.POSIXIdentityFor(ctx, entity.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading a POSIX identity after adoption failed", "error", err)
		writeError(w, http.StatusInternalServerError, "adopted, but could not read it back")
		return
	}
	s.log.InfoContext(ctx, "POSIX number adopted",
		"user", entity.Name, "number", number, "actor", session.SubjectID)
	writeJSON(w, http.StatusOK, describePOSIX(identity))
}
