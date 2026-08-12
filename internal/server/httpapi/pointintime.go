package httpapi

import (
	"errors"
	"net/http"
	"time"

	"go.londer.be/cardinal/internal/directory"
)

// Asking the directory about an instant that is not now.
//
// Membership carries a validity period, so "who was in this group in March" is
// a query rather than log archaeology — and until this, it was a query only the
// CLI could make. That put the directory's most distinctive property behind the
// one interface that reaches PostgreSQL directly (ADR 0033), which is backwards:
// an auditor's question should not require the database credential.
//
// `at` is a query parameter rather than a separate path, because it does not
// change what is being asked, only when. A caller that omits it gets now, which
// is what every existing caller already gets.

// atFrom reads the `at` query parameter.
//
// Refused rather than ignored when it does not parse. A mistyped instant that
// silently means "now" answers a different question than the one asked and
// looks like it worked, which for an audit query is the worst of both.
func atFrom(r *http.Request) (time.Time, error) {
	raw := r.URL.Query().Get("at")
	if raw == "" {
		return time.Time{}, nil
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errors.New("`at` must be an RFC 3339 instant, e.g. 2026-03-14T09:00:00Z")
	}
	return at, nil
}

// grantHistoryEntry is one grant, whether or not it is still in force.
type grantHistoryEntry struct {
	From time.Time `json:"from"`
	//nolint:tagliatelle // `until` is null for an open-ended grant, and the
	// absence is the meaning rather than a missing field.
	Until  *time.Time `json:"until"`
	Reason string     `json:"reason"`

	// Current says whether this grant is the one in force now, so a caller
	// rendering a list does not have to compare timestamps to find out.
	Current bool `json:"current"`
}

type grantHistoryResponse struct {
	Group  string              `json:"group"`
	Member string              `json:"member"`
	Grants []grantHistoryEntry `json:"grants"`

	// Member reports whether they were in the group at the instant asked
	// about, which is the question `history -at` exists to answer and is not
	// derivable from the list without repeating the range arithmetic.
	MemberAt *bool  `json:"memberAt,omitempty"`
	At       string `json:"at,omitempty"`
}

// handleGrantHistory returns every grant ever made of one membership.
//
// Including expired and revoked ones: a revocation closes the range and keeps
// the row, so the reason recorded when the grant was made survives it. That is
// the point of the whole temporal model, and it had no way out over the API.
func (s *Server) handleGrantHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	at, err := atFrom(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	group, err := s.store.LookupEntity(ctx, directory.TypeGroup, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such group")
		return
	}

	member, err := s.lookupMember(ctx, r.PathValue("member"))
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such member")
			return
		}
		s.log.ErrorContext(ctx, "looking up a member failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read that member")
		return
	}

	grants, err := s.store.GrantHistory(ctx, group.ID, member.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading grant history failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the history")
		return
	}

	now := time.Now()
	out := grantHistoryResponse{Group: group.Name, Member: member.Name}
	for _, g := range grants {
		entry := grantHistoryEntry{From: g.Period.From, Until: g.Period.Until, Reason: g.Reason}
		entry.Current = !g.Period.From.After(now) &&
			(g.Period.Until == nil || g.Period.Until.After(now))
		out.Grants = append(out.Grants, entry)
	}

	if !at.IsZero() {
		was, err := s.store.IsMemberAt(ctx, member.ID, group.ID, at)
		if err != nil {
			s.log.ErrorContext(ctx, "reading membership at an instant failed", "error", err)
			writeError(w, http.StatusInternalServerError, "could not answer for that instant")
			return
		}
		out.MemberAt = &was
		out.At = at.UTC().Format(time.RFC3339)
	}

	writeJSON(w, http.StatusOK, out)
}
