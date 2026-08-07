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

const entityColumns = `id, type, name, coalesce(display_name, ''), attrs,
                       system, owner_id,
                       created_at, updated_at, disabled_at, redacted_at`

// CreateEntity persists a new entity and its audit event atomically.
//
// actorID is who is performing the creation. It is a pointer because
// bootstrapping has no actor yet: the very first entity necessarily creates
// itself into existence.
func (s *Store) CreateEntity(ctx context.Context, e *directory.Entity, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO entities (id, type, name, display_name, attrs, owner_id)
			VALUES ($1, $2, $3, nullif($4, ''), $5, $6)
			RETURNING created_at, updated_at`,
			e.ID, string(e.Type), e.Name, e.DisplayName, e.Attrs, e.OwnerID,
		).Scan(&e.CreatedAt, &e.UpdatedAt)
		if err != nil {
			if pgErrCode(err) == codeUniqueViolation {
				return fmt.Errorf("%w: a %s named %q already exists",
					directory.ErrAlreadyExists, e.Type, e.Name)
			}
			return fmt.Errorf("store: creating entity: %w", err)
		}

		// No "name" here: a username identifies a person, and the journal is
		// append-only, so it could never be erased. The entity_id carried by
		// the event resolves to the name via the entities table, which *is*
		// redactable. See ADR 0010.
		ev, err := event.New(event.ActionEntityCreated, &e.ID, actorID, map[string]any{
			"type": string(e.Type),
		})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// GetEntity looks an entity up by its immutable ID.
func (s *Store) GetEntity(ctx context.Context, id uuid.UUID) (*directory.Entity, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+entityColumns+` FROM entities WHERE id = $1`, id)
	return scanEntity(row)
}

// LookupEntity resolves a (type, name) pair to an entity.
//
// Names are mutable, so this is a convenience for humans at the CLI and UI
// edges only. Resolve once, then carry the ID: holding a name across a
// long-running operation reintroduces exactly the staleness bug that
// DN-as-identity causes in LDAP.
func (s *Store) LookupEntity(ctx context.Context, t directory.Type, name string) (*directory.Entity, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+entityColumns+` FROM entities WHERE type = $1 AND name = $2`,
		string(t), name)

	e, err := scanEntity(row)
	if errors.Is(err, directory.ErrNotFound) {
		return nil, fmt.Errorf("%w: no %s named %q", directory.ErrNotFound, t, name)
	}
	return e, err
}

// ListEntities returns entities of a type, oldest first. Passing an empty type
// lists everything.
func (s *Store) ListEntities(ctx context.Context, t directory.Type, includeDisabled bool) ([]*directory.Entity, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+entityColumns+`
		  FROM entities
		 WHERE ($1 = '' OR type = $1::entity_type)
		   AND ($2 OR disabled_at IS NULL)
		 ORDER BY type, name`,
		string(t), includeDisabled)
	if err != nil {
		return nil, fmt.Errorf("store: listing entities: %w", err)
	}
	defer rows.Close()

	var out []*directory.Entity
	for rows.Next() {
		e, err := scanEntity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating entities: %w", err)
	}
	return out, nil
}

// DisableEntity soft-deletes an entity.
//
// There is no hard delete, by design. Audit history has to keep resolving, and
// a departed employee's past grants still need to be explicable.
func (s *Store) DisableEntity(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE entities SET disabled_at = now(), updated_at = now()
			  WHERE id = $1 AND disabled_at IS NULL`, id)
		if err != nil {
			return fmt.Errorf("store: disabling entity: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Either it doesn't exist or it is already disabled. Both are
			// no-ops from the caller's perspective; don't write a misleading
			// audit event for something that didn't happen.
			return fmt.Errorf("%w: %s (or already disabled)", directory.ErrNotFound, id)
		}

		ev, err := event.New(event.ActionEntityDisabled, &id, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// EnableEntity undoes a disable.
//
// The other half of a door that was one-way for far too long. Disabling is the
// reversible way to cut somebody off — that is the whole reason it exists rather
// than a delete — and a "reversible" action with no way back is just a delete
// that keeps a row.
//
// What it deliberately does not restore: sessions and access tokens, which
// disabling revoked. Those are gone and should be. Somebody coming back signs
// in again, and a token that was live during the period an account was cut off
// is exactly what should not resume working.
func (s *Store) EnableEntity(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE entities SET disabled_at = NULL, updated_at = now()
			  WHERE id = $1 AND disabled_at IS NOT NULL`, id)
		if err != nil {
			return fmt.Errorf("store: enabling entity: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s (or already enabled)", directory.ErrNotFound, id)
		}

		// Refused after erasure, and this is the one case worth being firm
		// about. A redacted entity's name is a tombstone and its personal data
		// is gone; bringing it back would produce an account nobody can identify
		// and whose owner cannot be told it exists. If that person returns, they
		// get a new account.
		var redacted bool
		if err := tx.QueryRow(ctx,
			`SELECT redacted_at IS NOT NULL FROM entities WHERE id = $1`, id,
		).Scan(&redacted); err != nil {
			return fmt.Errorf("store: checking redaction: %w", err)
		}
		if redacted {
			return fmt.Errorf("store: %s was erased under the right to be "+
				"forgotten and cannot be re-enabled — create a new account", id)
		}

		ev, err := event.New(event.ActionEntityEnabled, &id, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// scanner abstracts over pgx.Row and pgx.Rows so scanEntity serves both the
// single-row and iteration paths.
type scanner interface {
	Scan(dest ...any) error
}

func scanEntity(row scanner) (*directory.Entity, error) {
	var (
		e       directory.Entity
		typeStr string
	)
	err := row.Scan(&e.ID, &typeStr, &e.Name, &e.DisplayName, &e.Attrs,
		&e.System, &e.OwnerID,
		&e.CreatedAt, &e.UpdatedAt, &e.DisabledAt, &e.RedactedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, directory.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scanning entity: %w", err)
	}
	e.Type = directory.Type(typeStr)
	if e.Attrs == nil {
		e.Attrs = map[string]any{}
	}
	return &e, nil
}

// ProfileUpdate is the subset of an entity a person may change about themselves.
//
// Deliberately not `name`. The login is what appears in policy, in group
// listings and in every audit record a colleague reads, so letting someone
// rename themselves to a colleague's login — even briefly, even reversibly — is
// an impersonation primitive. Renaming stays an administrative act.
//
// Nil means "leave alone", which is what makes a form that submits one field
// not blank the others.
type ProfileUpdate struct {
	DisplayName *string
	Email       *string
}

// UpdateProfile changes an entity's own descriptive attributes.
//
// ADR 0002 rests on names being mutable attributes rather than identifiers —
// "renaming a person is an UPDATE, not a migration". Until this existed there
// was no UPDATE: entities could be created and disabled and nothing in between,
// so the claim was true of the schema and not of the software.
//
// Email lives in attrs rather than a column because not every entity type has
// one, and the schema registry governs what may go there.
func (s *Store) UpdateProfile(ctx context.Context, id uuid.UUID, in ProfileUpdate, actorID *uuid.UUID) (*directory.Entity, error) {
	var updated *directory.Entity

	err := s.InTx(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE entities
			   SET display_name = coalesce($2, display_name),
			       attrs = CASE
			                 WHEN $3::text IS NULL THEN attrs
			                 WHEN $3 = ''        THEN attrs - 'email'
			                 ELSE jsonb_set(attrs, '{email}', to_jsonb($3::text))
			               END,
			       updated_at = now()
			 WHERE id = $1 AND disabled_at IS NULL
			 RETURNING `+entityColumns,
			id, in.DisplayName, in.Email)

		e, err := scanEntity(row)
		if err != nil {
			return err
		}
		updated = e

		// The payload records which fields moved, never their values: an audit
		// record carrying a display name or an email address would put personal
		// data in an append-only log that erasure cannot reach (ADR 0010).
		ev, err := event.New(event.ActionEntityUpdated, &id, actorID,
			map[string]any{
				"display_name_changed": in.DisplayName != nil,
				"email_changed":        in.Email != nil,
			})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})

	return updated, err
}
