package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrCeremonyNotFound reports that the WebAuthn ceremony is unknown or expired.
	ErrCeremonyNotFound = errors.New("store: ceremony not found or expired")
	// ErrCeremonyConsumed reports that the WebAuthn ceremony has already completed.
	ErrCeremonyConsumed = errors.New("store: ceremony already completed")
)

// SaveCeremony persists an in-flight WebAuthn challenge.
func (s *Store) SaveCeremony(ctx context.Context, kind string, entityID *uuid.UUID, session []byte, expiresAt time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO webauthn_ceremonies (kind, entity_id, session, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id`,
		kind, entityID, session, expiresAt,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("store: saving ceremony: %w", err)
	}
	return id, nil
}

// ConsumeCeremony marks a ceremony complete and returns its session data.
//
// Consume-and-return in one statement, for the same reason as break-glass: a
// ceremony must be single-use, and doing this in two steps leaves a window
// where a captured response could be replayed. `consumed_at IS NULL` in the
// WHERE clause makes concurrent completion safe — only one caller wins.
//
// Expiry is enforced here rather than trusted to a sweeper, so an unswept
// ceremony is still unusable.
func (s *Store) ConsumeCeremony(ctx context.Context, id uuid.UUID, kind string) ([]byte, *uuid.UUID, error) {
	var (
		session  []byte
		entityID *uuid.UUID
	)
	err := s.pool.QueryRow(ctx, `
		UPDATE webauthn_ceremonies
		   SET consumed_at = now()
		 WHERE id = $1
		   AND kind = $2
		   AND consumed_at IS NULL
		   AND expires_at > now()
		 RETURNING session, entity_id`,
		id, kind,
	).Scan(&session, &entityID)

	if errors.Is(err, pgx.ErrNoRows) {
		// Distinguish "already used" from "never existed or expired" only
		// enough to be useful in logs; both are refusals to the caller.
		var consumed bool
		if e := s.pool.QueryRow(ctx,
			`SELECT consumed_at IS NOT NULL FROM webauthn_ceremonies WHERE id = $1`,
			id).Scan(&consumed); e == nil && consumed {
			return nil, nil, ErrCeremonyConsumed
		}
		return nil, nil, ErrCeremonyNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("store: consuming ceremony: %w", err)
	}
	return session, entityID, nil
}

// PurgeExpiredCeremonies clears abandoned ceremonies.
//
// Unlike break-glass challenges, these are not evidence of anything: an
// abandoned login is ordinary. Consumed rows go too, once expired.
func (s *Store) PurgeExpiredCeremonies(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM webauthn_ceremonies WHERE expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("store: purging ceremonies: %w", err)
	}
	return tag.RowsAffected(), nil
}
