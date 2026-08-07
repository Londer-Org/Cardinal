package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/event"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RedactEntity erases an entity's personal data in response to a GDPR
// Article 17 request, while leaving the audit chain intact.
//
// The row is not deleted. Journal entries reference entities by ID, and a
// dangling reference would break audit queries — making the system less
// accountable in the name of privacy. Instead the personal fields are
// tombstoned:
//
//   - name        -> a stable, non-identifying placeholder
//   - display_name-> NULL
//   - attrs       -> {}
//   - reason      -> NULL on every grant this entity was party to
//
// What survives is the shape of history: that an entity existed, belonged to
// groups during particular periods, and was later erased. None of it is
// attributable to a person once the link is severed, which is the ordinary
// meaning of pseudonymisation.
//
// This is irreversible by design. A reversible erasure is not an erasure.
func (s *Store) RedactEntity(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		// The tombstone keeps the type-scoped uniqueness constraint satisfiable
		// while carrying no information about who this was. The ID suffix is
		// only to disambiguate multiple redactions of the same type.
		tombstone := fmt.Sprintf("redacted-%s", id.String()[:8])

		tag, err := tx.Exec(ctx, `
			UPDATE entities
			   SET name         = $2,
			       display_name = NULL,
			       attrs        = '{}'::jsonb,
			       redacted_at  = now(),
			       updated_at   = now()
			 WHERE id = $1 AND redacted_at IS NULL`,
			id, tombstone)
		if err != nil {
			return fmt.Errorf("store: redacting entity: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s (or already redacted)", directory.ErrNotFound, id)
		}

		// Grant justifications are free text and therefore personal data by
		// default. Clear every one this entity was party to, as member or as
		// grantor.
		if _, err := tx.Exec(ctx, `
			UPDATE group_members
			   SET reason = NULL
			 WHERE member_id = $1 OR granted_by = $1`, id); err != nil {
			return fmt.Errorf("store: clearing grant justifications: %w", err)
		}

		// Sessions carry IP addresses and user agents — personal data with no
		// audit value once the account is gone. Unlike the journal, this table
		// has no append-only rule, so they are deleted outright.
		if _, err := tx.Exec(ctx,
			`DELETE FROM sessions WHERE subject_id = $1`, id); err != nil {
			return fmt.Errorf("store: deleting sessions: %w", err)
		}

		// A home directory is /home/<login>, so it carries the name the
		// tombstone above just erased. The uid stays: it is on every file this
		// person ever created, and forgetting which erased account owned it
		// makes those files unattributable rather than private. The path is
		// rewritten rather than nulled because the column is NOT NULL in
		// spirit — a POSIX user without a home is a login that lands in /.
		if _, err := tx.Exec(ctx, `
			UPDATE posix_identities
			   SET home_directory = '/home/' || $2
			 WHERE entity_id = $1 AND home_directory IS NOT NULL`,
			id, tombstone); err != nil {
			return fmt.Errorf("store: redacting home directory: %w", err)
		}

		// The redaction itself is auditable: the payload records that an entity
		// was erased and when, which identifies nobody.
		ev, err := event.New(event.ActionEntityRedacted, &id, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// Redacted reports whether an entity's personal data has been erased.
func (s *Store) Redacted(ctx context.Context, id uuid.UUID) (bool, error) {
	var redacted bool
	err := s.pool.QueryRow(ctx,
		`SELECT redacted_at IS NOT NULL FROM entities WHERE id = $1`, id).Scan(&redacted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, directory.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("store: checking redaction: %w", err)
	}
	return redacted, nil
}
