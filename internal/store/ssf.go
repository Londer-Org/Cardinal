package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/directory"
)

// Streams, and the queue that feeds them.
//
// The queue is the same shape as the mail outbox, and for the same reasons:
// claimed with FOR UPDATE SKIP LOCKED so two servers can both deliver and
// neither waits, and the next attempt moved forward before the attempt rather
// than after, so a process that dies mid-send leaves a row that retries rather
// than one that is stuck.
//
// What differs is what a failure costs. A lost notification costs somebody an
// email; a lost session-revoked leaves an application believing a compromised
// account is still good. So these rows are retried for far longer, and nothing
// deletes an undelivered one.

// Stream is a receiver Cardinal pushes to.
type Stream struct {
	ID       uuid.UUID
	EntityID uuid.UUID

	// ClientID is the OIDC client id, which becomes the token's audience.
	ClientID string
	Name     string

	// Endpoint is where events are POSTed, and is empty for a poll stream:
	// nothing is sent, so there is nowhere to send it.
	Endpoint string

	// DeliveryMethod is push (RFC 8935) or poll (RFC 8936).
	DeliveryMethod string

	Events  []string
	Enabled bool

	CreatedAt time.Time
	UpdatedAt time.Time
}

const streamColumns = `s.id, s.entity_id, c.client_id, e.name,
                       s.endpoint, s.delivery_method, s.events, s.enabled,
                       s.created_at, s.updated_at`

const streamFrom = `FROM ssf_streams s
                    JOIN oidc_clients c ON c.entity_id = s.entity_id
                    JOIN entities e ON e.id = s.entity_id`

func scanStream(row pgx.Row) (*Stream, error) {
	var s Stream
	err := row.Scan(&s.ID, &s.EntityID, &s.ClientID, &s.Name,
		&s.Endpoint, &s.DeliveryMethod, &s.Events, &s.Enabled,
		&s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, directory.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scanning a stream: %w", err)
	}
	return &s, nil
}

// SaveStream creates or replaces the stream for one receiver.
//
// One per receiver, enforced by the schema. Two would mean every event
// delivered twice, and a receiver cannot tell a duplicate from a repeat.
func (s *Store) SaveStream(
	ctx context.Context, entityID uuid.UUID, endpoint, delivery string,
	events []string, actorID *uuid.UUID,
) (*Stream, error) {
	if events == nil {
		events = []string{}
	}
	if delivery == "" {
		delivery = DeliveryPush
	}
	// A poll stream has nowhere to be pushed to, and the schema refuses the
	// combination. Cleared here rather than reported, because an endpoint
	// arriving with a poll stream is a caller filling in a field the form still
	// showed rather than an operator asking for something contradictory.
	if delivery == DeliveryPoll {
		endpoint = ""
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ssf_streams (entity_id, endpoint, delivery_method, events, created_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (entity_id) DO UPDATE SET
		    endpoint = excluded.endpoint,
		    delivery_method = excluded.delivery_method,
		    events = excluded.events,
		    updated_at = now()`,
		entityID, endpoint, delivery, events, actorID)
	if err != nil {
		return nil, fmt.Errorf("store: saving the stream: %w", err)
	}
	return s.StreamFor(ctx, entityID)
}

// StreamFor returns one receiver's stream.
func (s *Store) StreamFor(ctx context.Context, entityID uuid.UUID) (*Stream, error) {
	return scanStream(s.pool.QueryRow(ctx,
		`SELECT `+streamColumns+` `+streamFrom+` WHERE s.entity_id = $1`, entityID))
}

// ListStreams returns every configured receiver.
func (s *Store) ListStreams(ctx context.Context) ([]Stream, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+streamColumns+` `+streamFrom+` ORDER BY e.name`)
	if err != nil {
		return nil, fmt.Errorf("store: listing streams: %w", err)
	}
	defer rows.Close()

	out := []Stream{}
	for rows.Next() {
		var st Stream
		if err := rows.Scan(&st.ID, &st.EntityID, &st.ClientID, &st.Name,
			&st.Endpoint, &st.DeliveryMethod, &st.Events, &st.Enabled,
			&st.CreatedAt, &st.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning a stream: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// SetStreamEnabled pauses or resumes delivery.
//
// Paused rather than deleted, so a receiver that is down does not lose its
// configuration and an operator can stop delivery without forgetting what it
// was.
//
// A pause holds what is already queued and records nothing new. Both halves
// measured against the running stack: an event queued before the pause is not
// even attempted while it lasts and goes out on resume, and a revocation
// happening during the pause adds nothing to this receiver's queue, because
// EnabledStreamsFor is what Emit asks and it filters on this column.
//
// That second half is the one worth knowing, and this comment used to say the
// opposite — "resuming sends what was missed". It does not. A receiver paused
// for an hour is never told about anything revoked in that hour, so it goes on
// honouring those sessions until they expire on their own. Pausing a stream is
// therefore a decision about what an application is allowed not to know, which
// is a larger thing than it sounds like.
func (s *Store) SetStreamEnabled(ctx context.Context, entityID uuid.UUID, enabled bool) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE ssf_streams SET enabled = $2, updated_at = now() WHERE entity_id = $1`,
		entityID, enabled)
	if err != nil {
		return fmt.Errorf("store: changing stream state: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: no stream for %s", directory.ErrNotFound, entityID)
	}
	return nil
}

// DeleteStream removes a receiver entirely.
func (s *Store) DeleteStream(ctx context.Context, entityID uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		// Undelivered events go with it. They are addressed to a receiver that
		// no longer exists, and keeping them would retry against an endpoint
		// nobody is listening on until the row aged out.
		if _, err := tx.Exec(ctx, `
			DELETE FROM ssf_events
			 WHERE stream_id IN (SELECT id FROM ssf_streams WHERE entity_id = $1)`,
			entityID); err != nil {
			return fmt.Errorf("store: discarding queued events: %w", err)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM ssf_streams WHERE entity_id = $1`, entityID)
		if err != nil {
			return fmt.Errorf("store: deleting the stream: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: no stream for %s", directory.ErrNotFound, entityID)
		}
		return nil
	})
}

// QueuedEvent is one token waiting to go out.
type QueuedEvent struct {
	ID       uuid.UUID
	StreamID uuid.UUID
	Endpoint string
	Type     string
	Token    string
	Attempts int
}

// EnqueueEvent adds a signed token to the outbox.
func (s *Store) EnqueueEvent(
	ctx context.Context, streamID uuid.UUID, subjectID *uuid.UUID,
	eventType, token string, jti uuid.UUID,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ssf_events (stream_id, subject_id, event_type, token, jti)
		VALUES ($1, $2, $3, $4, $5)`,
		streamID, subjectID, eventType, token, jti)
	if err != nil {
		return fmt.Errorf("store: queueing a security event: %w", err)
	}
	return nil
}

// EnabledStreamsFor returns the streams that asked for this event type.
//
// A stream that did not subscribe receives nothing, which is the whole point of
// the subscription list: an application told about people it has never seen is
// a directory leak dressed as a feature.
func (s *Store) EnabledStreamsFor(ctx context.Context, eventType string) ([]Stream, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+streamColumns+` `+streamFrom+`
		  WHERE s.enabled AND $1 = ANY(s.events)`, eventType)
	if err != nil {
		return nil, fmt.Errorf("store: finding streams for an event: %w", err)
	}
	defer rows.Close()

	out := []Stream{}
	for rows.Next() {
		var st Stream
		if err := rows.Scan(&st.ID, &st.EntityID, &st.ClientID, &st.Name,
			&st.Endpoint, &st.DeliveryMethod, &st.Events, &st.Enabled,
			&st.CreatedAt, &st.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning a stream: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ClaimEvents takes what is due, for one worker.
//
// Backoff is capped at fifteen minutes rather than the mail queue's thirty. A
// receiver that has been unreachable for an hour is one an incident is probably
// waiting on, and an hour-long gap between attempts is a long time to leave an
// application believing a revoked session is good.
func (s *Store) ClaimEvents(ctx context.Context, limit int) ([]QueuedEvent, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE ssf_events SET
		    attempts = attempts + 1,
		    next_attempt_at = now() + (interval '1 minute' * least(attempts + 1, 15))
		 WHERE id IN (
		     SELECT e.id FROM ssf_events e
		       JOIN ssf_streams s ON s.id = e.stream_id
		      WHERE e.delivered_at IS NULL
		        AND e.next_attempt_at <= now()
		        AND s.enabled
		        -- A poll stream's events wait for the receiver to ask. Without
		        -- this the delivery loop would claim them, POST to the empty
		        -- endpoint, fail, and retry them forever while the receiver
		        -- polls and is told there is nothing waiting.
		        AND s.delivery_method = 'push'
		      ORDER BY e.next_attempt_at
		      LIMIT $1
		      FOR UPDATE OF e SKIP LOCKED)
		RETURNING id, stream_id, event_type, token, attempts`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: claiming security events: %w", err)
	}
	defer rows.Close()

	var claimed []QueuedEvent
	for rows.Next() {
		var e QueuedEvent
		if err := rows.Scan(&e.ID, &e.StreamID, &e.Type, &e.Token, &e.Attempts); err != nil {
			return nil, fmt.Errorf("store: scanning a claimed event: %w", err)
		}
		claimed = append(claimed, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The endpoint, resolved after the claim. Joining it into the UPDATE would
	// mean the returning clause read from two tables, and the claim is the part
	// that has to be atomic.
	for i := range claimed {
		if err := s.pool.QueryRow(ctx,
			`SELECT endpoint FROM ssf_streams WHERE id = $1`, claimed[i].StreamID,
		).Scan(&claimed[i].Endpoint); err != nil {
			return nil, fmt.Errorf("store: reading a stream endpoint: %w", err)
		}
	}
	return claimed, nil
}

// EventDelivered marks one done.
func (s *Store) EventDelivered(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE ssf_events SET delivered_at = now(), last_error = NULL WHERE id = $1`, id)
	return err
}

// EventFailed records why, leaving it to be retried.
//
// The receiver's own words, kept rather than summarised — the same judgement
// the mail queue makes. "connection refused" and "401 invalid token" want
// completely different responses, and a queue that says only "failed" makes
// somebody reproduce it.
func (s *Store) EventFailed(ctx context.Context, id uuid.UUID, reason string) error {
	if len(reason) > 500 {
		reason = reason[:500]
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE ssf_events SET last_error = $2 WHERE id = $1`, id, reason)
	return err
}

// PendingEvents counts what is waiting, for `cardinal ssf status`.
func (s *Store) PendingEvents(ctx context.Context) (pending, failing int, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE delivered_at IS NULL),
		       count(*) FILTER (WHERE delivered_at IS NULL AND attempts > 3)
		  FROM ssf_events`).Scan(&pending, &failing)
	if err != nil {
		return 0, 0, fmt.Errorf("store: counting queued security events: %w", err)
	}
	return pending, failing, nil
}

// JournalEntry is one act the transmitter may need to report.
type JournalEntry struct {
	Seq       int64
	Action    string
	SubjectID *uuid.UUID
	At        time.Time
}

// FollowJournal takes the next batch of acts and advances the watermark.
//
// Events are found by following the hash-chained journal rather than by calling
// a notifier from each handler. The first version did the latter and was wrong
// in a way worth keeping written down: the emission sat in the HTTP layer, so
// `cardinal user disable` on the server changed the directory and told nobody.
// Two paths and one of them unchecked, which is the shape this project keeps
// finding in itself.
//
// The journal is the one place every path passes through — the CLI, the API,
// SCIM, and whatever is added next — because a state change and its journal
// entry commit in the same transaction (ADR 0003).
//
// The whole batch is claimed under a lock on the watermark row, so several
// servers can run this and only one advances at a time. A crash between reading
// and enqueueing costs a redelivery rather than a lost event, which is the
// right direction: jti exists so a receiver can discard a repeat, and nothing
// exists to recover one that was dropped.
func (s *Store) FollowJournal(ctx context.Context, actions []string, limit int) ([]JournalEntry, error) {
	var out []JournalEntry

	err := s.InTx(ctx, func(tx pgx.Tx) error {
		var from int64
		// FOR UPDATE, so two servers cannot both read the same range. The
		// second waits, finds the watermark already advanced, and does nothing.
		if err := tx.QueryRow(ctx,
			`SELECT seq FROM ssf_watermark WHERE id LIMIT 1 FOR UPDATE`).Scan(&from); err != nil {
			return fmt.Errorf("store: reading the transmitter watermark: %w", err)
		}

		rows, err := tx.Query(ctx, `
			SELECT seq, action, entity_id, occurred_at
			  FROM events
			 WHERE seq > $1 AND action = ANY($2)
			 ORDER BY seq
			 LIMIT $3`, from, actions, limit)
		if err != nil {
			return fmt.Errorf("store: reading the journal: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var e JournalEntry
			if err := rows.Scan(&e.Seq, &e.Action, &e.SubjectID, &e.At); err != nil {
				return fmt.Errorf("store: scanning a journal entry: %w", err)
			}
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// Advanced past everything looked at, not only what matched. Otherwise
		// a long run of uninteresting entries is re-read on every tick forever,
		// and the query gets slower as the journal grows.
		var highest int64
		if err := tx.QueryRow(ctx, `
			SELECT coalesce(max(seq), $1) FROM (
			    SELECT seq FROM events WHERE seq > $1 ORDER BY seq LIMIT $2
			) AS looked_at`, from, limit).Scan(&highest); err != nil {
			return fmt.Errorf("store: finding the journal position: %w", err)
		}

		if _, err := tx.Exec(ctx,
			`UPDATE ssf_watermark SET seq = $1 WHERE id`, highest); err != nil {
			return fmt.Errorf("store: advancing the transmitter watermark: %w", err)
		}
		return nil
	})
	return out, err
}

// Delivery methods a stream may use.
//
// The short names, not the specification's URIs. These are what the column
// holds and what an operator types; the URIs appear only in the configuration
// document, where a receiver reads them.
const (
	DeliveryPush = "push"
	DeliveryPoll = "poll"
)

// PolledEvent is one token waiting for a receiver to collect it.
type PolledEvent struct {
	JTI   uuid.UUID
	Token string
}

// PollEvents returns what is waiting for one receiver, oldest first.
//
// Read-only, and deliberately: RFC 8936 has the receiver acknowledge what it
// has processed, so nothing here may mark anything delivered. A receiver that
// crashes between the response and its acknowledgement asks again and is given
// the same events, which is the behaviour that loses nothing.
//
// Events with no jti are skipped rather than returned. Those were queued before
// poll delivery existed, so they belong to a push stream and cannot be
// acknowledged — returning one would hand a receiver an event it could never
// clear, and it would arrive again on every poll forever.
func (s *Store) PollEvents(ctx context.Context, streamID uuid.UUID, limit int) ([]PolledEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT jti, token
		  FROM ssf_events
		 WHERE stream_id = $1 AND delivered_at IS NULL AND jti IS NOT NULL
		 ORDER BY created_at
		 LIMIT $2`, streamID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading queued events: %w", err)
	}
	defer rows.Close()

	out := []PolledEvent{}
	for rows.Next() {
		var e PolledEvent
		if err := rows.Scan(&e.JTI, &e.Token); err != nil {
			return nil, fmt.Errorf("store: scanning a queued event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AcknowledgeEvents marks what a receiver says it has processed, and reports
// how many rows that was.
//
// Scoped to the stream on purpose. The jti comes from the request body, so
// without the stream_id predicate a receiver could acknowledge — and so
// discard — events queued for somebody else, by quoting an identifier it read
// in one of its own tokens' place. It knows only its own, but "it should not
// know that value" is not an access control.
func (s *Store) AcknowledgeEvents(ctx context.Context, streamID uuid.UUID, jtis []uuid.UUID) (int, error) {
	if len(jtis) == 0 {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE ssf_events SET delivered_at = now()
		 WHERE stream_id = $1 AND delivered_at IS NULL AND jti = ANY($2)`,
		streamID, jtis)
	if err != nil {
		return 0, fmt.Errorf("store: acknowledging events: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// PendingForStream counts what one receiver has waiting.
//
// Used to answer moreAvailable, which a receiver uses to decide whether to poll
// again immediately or wait.
func (s *Store) PendingForStream(ctx context.Context, streamID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM ssf_events
		 WHERE stream_id = $1 AND delivered_at IS NULL AND jti IS NOT NULL`,
		streamID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: counting queued events: %w", err)
	}
	return n, nil
}
