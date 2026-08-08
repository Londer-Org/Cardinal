package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/event"
)

// eventChainLock serialises appenders to the journal.
//
// A hash chain is inherently sequential: each record needs its predecessor's
// hash, so two concurrent appenders could otherwise read the same tip and write
// two records claiming the same parent — forking the chain and making
// validation fail forever. A transaction-scoped advisory lock serialises the
// read-tip/append pair and is released automatically at commit or rollback.
//
// This is a real throughput ceiling, and an accepted one (ADR 0003): an
// internal IdP writes tens of events per second at peak. Measure before
// assuming it needs solving.
const eventChainLock int64 = 0x43415244494E414C // "CARDINAL"

// ErrChainBroken means the journal failed integrity validation. Treat it as a
// security incident, not a data-quality problem.
var ErrChainBroken = errors.New("store: event chain integrity check failed")

// AppendEvent writes ev to the journal within tx, linking it to the current tip.
//
// It deliberately takes a pgx.Tx rather than using the pool: an event must
// commit in the same transaction as the state change it describes, or the
// journal can drift from reality.
func (s *Store) AppendEvent(ctx context.Context, tx pgx.Tx, ev *event.Event) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, eventChainLock); err != nil {
		return fmt.Errorf("store: locking event chain: %w", err)
	}

	var prevHash []byte
	err := tx.QueryRow(ctx,
		`SELECT hash FROM events ORDER BY seq DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("store: reading chain tip: %w", err)
	}
	// pgx.ErrNoRows leaves prevHash nil, which is exactly right: the first
	// event is the genesis record and has no predecessor.

	if err := ev.ComputeHash(prevHash); err != nil {
		return err
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO events (id, occurred_at, action, entity_id, actor_id,
		                    payload, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING seq`,
		ev.ID, ev.OccurredAt, ev.Action, ev.EntityID, ev.ActorID,
		ev.Payload, ev.PrevHash, ev.Hash,
	).Scan(&ev.Seq)
	if err != nil {
		return fmt.Errorf("store: appending event: %w", err)
	}
	return nil
}

// ChainReport describes the outcome of a validation pass.
type ChainReport struct {
	EventsChecked int64
	Valid         bool

	// BrokenAtSeq is the first record that failed, or 0 if none did.
	BrokenAtSeq int64
	Reason      string
}

// ValidateChain recomputes every hash from the genesis record forward and
// reports the first inconsistency.
//
// Run this after any restore. A plain PostgreSQL backup can tell you the data
// came back; only this can tell you it came back unaltered.
//
// Cost is O(n) in journal size. Streaming keeps memory flat, but a large
// journal takes real time — checkpointing is future work.
func (s *Store) ValidateChain(ctx context.Context) (*ChainReport, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT seq, id, occurred_at, action, entity_id, actor_id,
		       payload, prev_hash, hash
		  FROM events
		 ORDER BY seq ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: reading events: %w", err)
	}
	defer rows.Close()

	report := &ChainReport{Valid: true}
	var expectedPrev []byte

	for rows.Next() {
		var (
			ev       event.Event
			entityID *uuid.UUID
			actorID  *uuid.UUID
		)
		if err := rows.Scan(&ev.Seq, &ev.ID, &ev.OccurredAt, &ev.Action,
			&entityID, &actorID, &ev.Payload, &ev.PrevHash, &ev.Hash); err != nil {
			return nil, fmt.Errorf("store: scanning event: %w", err)
		}
		ev.EntityID, ev.ActorID = entityID, actorID

		// Does this record point at the one that actually precedes it? Catches
		// deletion and reordering.
		if !bytes.Equal(ev.PrevHash, expectedPrev) {
			report.Valid = false
			report.BrokenAtSeq = ev.Seq
			report.Reason = fmt.Sprintf(
				"event %d claims predecessor %s but the preceding record hashes to %s "+
					"— a record was deleted or reordered",
				ev.Seq, shortHash(ev.PrevHash), shortHash(expectedPrev))
			return report, nil
		}

		// Does the record's content still hash to its stored hash? Catches
		// in-place modification.
		stored := ev.Hash
		if err := ev.ComputeHash(ev.PrevHash); err != nil {
			return nil, err
		}
		if !bytes.Equal(stored, ev.Hash) {
			report.Valid = false
			report.BrokenAtSeq = ev.Seq
			report.Reason = fmt.Sprintf(
				"event %d (%s) content does not match its stored hash — the record was modified",
				ev.Seq, ev.Action)
			return report, nil
		}

		expectedPrev = stored
		report.EventsChecked++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating events: %w", err)
	}
	return report, nil
}

func shortHash(h []byte) string {
	if len(h) == 0 {
		return "<genesis>"
	}
	if len(h) > 4 {
		h = h[:4]
	}
	return fmt.Sprintf("%x…", h)
}

// EventsForEntity returns an entity's journal entries, newest first.
//
// The journal had no read path at all until now: it could be appended to and
// validated end to end, but not inspected, which made "every mutation is
// recorded" a claim nobody could check without opening psql. The audit explorer
// in Phase 5 needs this; so does any test asserting what a mutation wrote.
//
// Deliberately not filtered by actor or action. Narrowing belongs to the caller,
// and an audit read that quietly omits rows is worse than no audit read.
func (s *Store) EventsForEntity(ctx context.Context, entityID uuid.UUID, limit int) ([]*event.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT seq, id, occurred_at, action, entity_id, actor_id, payload,
		       prev_hash, hash
		  FROM events
		 WHERE entity_id = $1
		 ORDER BY seq DESC
		 LIMIT $2`, entityID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading events: %w", err)
	}
	defer rows.Close()

	var out []*event.Event
	for rows.Next() {
		var ev event.Event
		if err := rows.Scan(&ev.Seq, &ev.ID, &ev.OccurredAt, &ev.Action,
			&ev.EntityID, &ev.ActorID, &ev.Payload, &ev.PrevHash, &ev.Hash); err != nil {
			return nil, fmt.Errorf("store: scanning event: %w", err)
		}
		out = append(out, &ev)
	}
	return out, rows.Err()
}

// EventFilter narrows an audit listing.
//
// Every field is optional and they combine with AND. Deliberately no free-text
// search: the journal holds no free text to search (ADR 0010's payload
// allowlist refuses it), so a search box would be a box that never matched
// anything and taught people the log was empty.
type EventFilter struct {
	Action string

	// Subject is either side of an event: what it was about, or who caused it.
	//
	// One field rather than two because the question is "what touched this
	// account", and answering it needs both — an administrator disabling
	// somebody appears as the actor on that person's event, and as the subject
	// of their own session events. Two filters would make the common question
	// take two queries and a mental union.
	Subject *uuid.UUID

	Since *time.Time
	Until *time.Time

	// Before pages backwards by sequence rather than by offset.
	//
	// The journal is append-only and grows forever, so OFFSET means reading and
	// discarding every row before the page — and a total count means a full
	// scan on every request. A cursor costs neither and cannot skip or repeat a
	// row when something is appended mid-read, which OFFSET does by
	// construction on a table that only ever gains rows at one end.
	Before int64
}

// EventRecord is a journal entry with its identifiers resolved.
//
// The journal stores only opaque IDs, which is the point: it is the one place
// erasure cannot reach (ADR 0010), so it must hold nothing that would need
// erasing. Names come from the entities table at read time — and when an
// account has been redacted, what comes back is its tombstone, which is the
// design working rather than a gap.
type EventRecord struct {
	event.Event

	SubjectName string
	SubjectType string

	ActorName string
	ActorType string

	// Redacted when the named entity's personal data has been erased. The name
	// is then a tombstone, and saying so beats rendering "redacted-1a2b3c4d" as
	// though somebody chose it.
	SubjectRedacted bool
	ActorRedacted   bool
}

// ListEvents returns journal entries, newest first.
func (s *Store) ListEvents(ctx context.Context, filter EventFilter, limit int) ([]EventRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT e.seq, e.id, e.occurred_at, e.action, e.entity_id, e.actor_id,
		       e.payload,
		       subject.name, subject.type, subject.redacted_at IS NOT NULL,
		       actor.name,   actor.type,   actor.redacted_at   IS NOT NULL
		  FROM events e
		  LEFT JOIN entities subject ON subject.id = e.entity_id
		  LEFT JOIN entities actor   ON actor.id   = e.actor_id
		 WHERE ($1 = '' OR e.action = $1)
		   AND ($2::uuid IS NULL OR e.entity_id = $2 OR e.actor_id = $2)
		   AND ($3::timestamptz IS NULL OR e.occurred_at >= $3)
		   AND ($4::timestamptz IS NULL OR e.occurred_at <  $4)
		   AND ($5 = 0 OR e.seq < $5)
		 ORDER BY e.seq DESC
		 LIMIT $6`,
		filter.Action, filter.Subject, filter.Since, filter.Until,
		filter.Before, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing events: %w", err)
	}
	defer rows.Close()

	out := make([]EventRecord, 0, limit)
	for rows.Next() {
		var record EventRecord
		var payload []byte
		var subjectName, subjectType, actorName, actorType *string

		if err := rows.Scan(&record.Seq, &record.ID, &record.OccurredAt,
			&record.Action, &record.EntityID, &record.ActorID, &payload,
			&subjectName, &subjectType, &record.SubjectRedacted,
			&actorName, &actorType, &record.ActorRedacted); err != nil {
			return nil, fmt.Errorf("store: scanning event: %w", err)
		}

		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &record.Payload); err != nil {
				return nil, fmt.Errorf("store: decoding event payload: %w", err)
			}
		}
		if subjectName != nil {
			record.SubjectName, record.SubjectType = *subjectName, *subjectType
		}
		if actorName != nil {
			record.ActorName, record.ActorType = *actorName, *actorType
		}
		out = append(out, record)
	}
	return out, rows.Err()
}
