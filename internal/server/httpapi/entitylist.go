package httpapi

import (
	"net/http"
	"time"

	"go.londer.be/cardinal/internal/directory"
)

// The directory as a table of entities.
//
// Not a duplicate of the per-type collections, and worth being clear about why,
// because "two endpoints answering about a user" is the shape this codebase has
// been removing. They answer different questions.
//
// `GET /api/directory/users` is the people page: paged, and carrying what a
// person's page needs — memberships as grants, POSIX identity, invitations.
// There is one per type that has a page, and none for a device or a role
// because neither does.
//
// These answer "what is in this directory", across every type at once, one row
// each. That question has no per-type answer by construction, and the four
// types without a collection of their own had no answer at all: a service
// account, a device or a role could be created and then never listed by
// anything but a database client.

type entityRow struct {
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	ID          string     `json:"id"`
	DisplayName string     `json:"displayName,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	DisabledAt  *time.Time `json:"disabledAt"`
}

func describeEntity(e *directory.Entity) entityRow {
	row := entityRow{
		Type:        string(e.Type),
		Name:        e.Name,
		ID:          e.ID.String(),
		DisplayName: e.DisplayName,
		CreatedAt:   e.CreatedAt,
	}
	if !e.Active() {
		row.DisabledAt = e.DisabledAt
	}
	return row
}

// handleListEntities lists what is in the directory.
//
// Unpaged, like the POSIX listing and for the same reason: the question is
// "what exists", and an answer split across pages is one the caller has to
// reassemble before it means anything. It is behind the same tier as the rest
// of the directory.
func (s *Server) handleListEntities(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// An unknown type is refused rather than treated as no filter. Passing one
	// and receiving everything reads as "there are none of those", which is a
	// different and wrong answer.
	var kind directory.Type
	if word := r.URL.Query().Get("type"); word != "" {
		kind = directory.Type(word)
		if !kind.Valid() {
			writeError(w, http.StatusBadRequest, "no such type: "+word)
			return
		}
	}

	entities, err := s.store.ListEntities(ctx, kind, r.URL.Query().Get("all") == "true")
	if err != nil {
		s.log.ErrorContext(ctx, "listing entities failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list them")
		return
	}

	out := make([]entityRow, 0, len(entities))
	for _, e := range entities {
		out = append(out, describeEntity(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"entities": out})
}

// entityMembership is one group an entity belongs to, and how.
type entityMembership struct {
	Group string `json:"group"`

	// Direct separates a membership somebody granted from one that arrives
	// through a nested group. Depth says how far: 1 is direct, and the numbers
	// above it are the chain a person would otherwise have to walk by hand to
	// answer "why is this account in that group".
	Direct bool `json:"direct"`
	Depth  int  `json:"depth"`
}

type entityDetail struct {
	entityRow

	Memberships []entityMembership `json:"memberships"`
}

// handleGetEntity describes one entity of any type.
func (s *Server) handleGetEntity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	kind := directory.Type(r.PathValue("type"))
	if !kind.Valid() {
		writeError(w, http.StatusBadRequest, "no such type: "+r.PathValue("type"))
		return
	}

	entity, err := s.store.LookupEntity(ctx, kind, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such "+string(kind))
		return
	}

	// Resolved rather than listed: the transitive answer is the one that
	// decides anything, and a listing of direct grants would disagree with
	// every policy decision made about this account.
	memberships, err := s.store.ResolveMemberships(ctx, entity.ID, time.Time{})
	if err != nil {
		s.log.ErrorContext(ctx, "resolving memberships failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read its memberships")
		return
	}

	out := entityDetail{
		entityRow:   describeEntity(entity),
		Memberships: make([]entityMembership, 0, len(memberships)),
	}
	for _, m := range memberships {
		out.Memberships = append(out.Memberships, entityMembership{
			Group: m.GroupName, Direct: m.Direct(), Depth: m.Depth,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
