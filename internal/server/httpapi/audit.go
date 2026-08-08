package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/store"
)

// The audit journal.
//
// Distinct from the decision explorer, which answers "why was I denied" from
// the decision log. This is the other half: what *happened* — every mutation,
// hash-chained, append-only, and enforced as such by database rules rather than
// trusted to the application.
//
// It had no reader at all. `cardinal audit verify` could tell you the chain was
// intact and nothing could tell you what was in it, so the one record that
// cannot be altered was also the one nobody could consult.

type auditEventResponse struct {
	Seq        int64     `json:"seq"`
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurredAt"`
	Action     string    `json:"action"`

	// Subject is what the event is about; Actor is who caused it. Either can be
	// absent: system-initiated events have no actor, and some events concern no
	// single entity.
	Subject *auditParty `json:"subject"`
	Actor   *auditParty `json:"actor"`

	// Payload is whatever the allowlist permitted — opaque identifiers and
	// enumerations, never free text (ADR 0010). Rendered as-is rather than
	// prose, because inventing a sentence per action is how a viewer starts
	// disagreeing with the record it is displaying.
	Payload map[string]any `json:"payload"`
}

type auditParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`

	// Redacted means the name is a tombstone rather than something somebody
	// chose. The journal deliberately holds no personal data, so an erased
	// account leaves its events intact and unreadable by name — which is the
	// design working, and worth labelling so it does not look like corruption.
	Redacted bool `json:"redacted"`
}

func party(id *uuid.UUID, name, kind string, redacted bool) *auditParty {
	if id == nil {
		return nil
	}
	return &auditParty{ID: id.String(), Name: name, Type: kind, Redacted: redacted}
}

func (s *Server) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	filter := store.EventFilter{Action: query.Get("action")}

	if raw := query.Get("subject"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "subject must be an entity id")
			return
		}
		filter.Subject = &id
	}
	if raw := query.Get("since"); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be an RFC 3339 timestamp")
			return
		}
		filter.Since = &since
	}
	if raw := query.Get("before"); raw != "" {
		seq, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "before must be a sequence number")
			return
		}
		filter.Before = seq
	}

	limit := 100
	if raw := query.Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	events, err := s.store.ListEvents(ctx, filter, limit)
	if err != nil {
		s.log.ErrorContext(ctx, "listing audit events failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the journal")
		return
	}

	out := make([]auditEventResponse, 0, len(events))
	for _, e := range events {
		out = append(out, auditEventResponse{
			Seq: e.Seq, ID: e.ID.String(), OccurredAt: e.OccurredAt, Action: e.Action,
			Subject: party(e.EntityID, e.SubjectName, e.SubjectType, e.SubjectRedacted),
			Actor:   party(e.ActorID, e.ActorName, e.ActorType, e.ActorRedacted),
			Payload: e.Payload,
		})
	}

	// The cursor for the next page, rather than an offset and a total. Counting
	// an append-only table that grows forever is a full scan on every request,
	// and an offset into one skips or repeats rows whenever something is
	// appended mid-read.
	var next int64
	if len(events) == limit {
		next = events[len(events)-1].Seq
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": out,
		"before": next,
	})
}

// handleVerifyAuditChain recomputes every hash from the first record forward.
//
// The thing that makes this a journal rather than a log, and it belongs in the
// console rather than only in a CLI: a plain PostgreSQL backup can tell you the
// data restored, and this tells you nobody altered it. Somebody who has just
// restored from backup, or who suspects direct database access, wants the
// answer without finding a shell first.
//
// It reads every event, so it is not something to put behind a page that loads
// it automatically. The console asks only when told to, and says what it is
// about to do.
func (s *Server) handleVerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	report, err := s.store.ValidateChain(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "verifying the audit chain failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not verify the journal")
		return
	}

	if !report.Valid {
		// Logged at error level on purpose. The journal is append-only and
		// protected by database rules, so a broken chain means something wrote
		// to it outside the application — a security incident, not a data
		// quality problem, and the server's own log should carry it whether or
		// not anybody is looking at the page.
		s.log.ErrorContext(ctx, "AUDIT CHAIN BROKEN",
			"seq", report.BrokenAtSeq, "reason", report.Reason)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":         report.Valid,
		"eventsChecked": report.EventsChecked,
		"brokenAtSeq":   report.BrokenAtSeq,
		"reason":        report.Reason,
	})
}
