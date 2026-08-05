package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/arthur-lonfils/cardinal/internal/event"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
