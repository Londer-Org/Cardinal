package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// How much of the directory an application is told about, from the console.
//
// Keyed on the application name rather than a client id, like the hostname
// endpoints beside it: an application behind the proxy has no OIDC registration
// and so no client id, and it is exactly the kind that reads the groups header.

type projectionGroup struct {
	Name string `json:"name"`

	// Owned separates a group that belongs to this application from one it was
	// granted sight of. They are administered differently — ownership is set
	// when the group is created — so a list that blurred them would leave "why
	// can it see this?" unanswerable.
	Owned bool `json:"owned"`
}

type projectionResponse struct {
	Mode   string            `json:"mode"`
	Groups []projectionGroup `json:"groups"`

	// TotalGroups is what makes `all` legible. "Told about every group" is a
	// setting; "told about 14 groups, 12 of which it does not own" is an
	// argument.
	TotalGroups int `json:"totalGroups"`
}

type projectionRequest struct {
	Mode string `json:"mode"`
}

func (s *Server) handleGetProjection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	app, ok := s.lookupApplication(w, r)
	if !ok {
		return
	}

	projection, err := s.store.GroupProjectionFor(ctx, app.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading the group projection failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the projection")
		return
	}
	visible, err := s.store.GroupsVisibleTo(ctx, app.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing visible groups failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the groups")
		return
	}
	total, err := s.store.GroupCount(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "counting groups failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not count the groups")
		return
	}

	out := projectionResponse{
		Mode:        projection.Mode,
		Groups:      make([]projectionGroup, 0, len(visible)),
		TotalGroups: total,
	}
	for _, g := range visible {
		out.Groups = append(out.Groups, projectionGroup{Name: g.Name, Owned: g.Owned})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSetProjection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	app, ok := s.lookupApplication(w, r)
	if !ok {
		return
	}

	var req projectionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	mode := strings.TrimSpace(req.Mode)
	if mode != store.ProjectionAll && mode != store.ProjectionOwned {
		writeError(w, http.StatusBadRequest,
			"the mode is `all` — every group a person belongs to — or `owned`, "+
				"the groups this application owns plus any it has been allowed")
		return
	}

	actorID := session.SubjectID
	if err := s.store.SetGroupProjection(ctx, app.ID, mode, &actorID); err != nil {
		s.log.ErrorContext(ctx, "setting the group projection failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not change the projection")
		return
	}
	s.log.InfoContext(ctx, "group projection changed",
		"application", app.Name, "mode", mode, "actor", session.SubjectID)

	w.WriteHeader(http.StatusNoContent)
}

// handleAllowGroupSight and handleDenyGroupSight administer the escape hatch.
func (s *Server) handleAllowGroupSight(w http.ResponseWriter, r *http.Request) {
	s.changeGroupSight(w, r, true)
}

func (s *Server) handleDenyGroupSight(w http.ResponseWriter, r *http.Request) {
	s.changeGroupSight(w, r, false)
}

func (s *Server) changeGroupSight(w http.ResponseWriter, r *http.Request, allow bool) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	app, ok := s.lookupApplication(w, r)
	if !ok {
		return
	}

	group, err := s.store.LookupEntity(ctx, directory.TypeGroup, r.PathValue("group"))
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such group")
			return
		}
		s.log.ErrorContext(ctx, "looking up a group failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read that group")
		return
	}

	if !allow {
		if err := s.store.DenyGroupSight(ctx, app.ID, group.ID); err != nil {
			s.log.ErrorContext(ctx, "removing sight of a group failed", "error", err)
			writeError(w, http.StatusInternalServerError, "could not change the projection")
			return
		}
		s.log.InfoContext(ctx, "group sight removed",
			"application", app.Name, "group", group.Name, "actor", session.SubjectID)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	actorID := session.SubjectID
	if err := s.store.AllowGroupSight(ctx, app.ID, group.ID, &actorID); err != nil {
		// A system group is refused, and the reason is worth saying rather than
		// answering 500: membership of one is authority inside Cardinal, and an
		// application branching on it would be reading a Cardinal internal as
		// though it were one of its own roles.
		if strings.Contains(err.Error(), "authority inside Cardinal") {
			writeError(w, http.StatusBadRequest,
				"a system group confers authority inside Cardinal and is never "+
					"projected to an application")
			return
		}
		s.log.ErrorContext(ctx, "allowing sight of a group failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not change the projection")
		return
	}
	s.log.InfoContext(ctx, "group sight allowed",
		"application", app.Name, "group", group.Name, "actor", session.SubjectID)
	w.WriteHeader(http.StatusNoContent)
}

// lookupApplication resolves the {name} in the path, or writes the error.
func (s *Server) lookupApplication(w http.ResponseWriter, r *http.Request) (*directory.Entity, bool) {
	ctx := r.Context()
	app, err := s.store.LookupEntity(ctx, directory.TypeApplication, r.PathValue("name"))
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such application")
			return nil, false
		}
		s.log.ErrorContext(ctx, "looking up an application failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read that application")
		return nil, false
	}
	return app, true
}
