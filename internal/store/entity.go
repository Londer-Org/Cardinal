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
                       created_at, updated_at, disabled_at`

// CreateEntity persists a new entity and its audit event atomically.
//
// actorID is who is performing the creation. It is a pointer because
// bootstrapping has no actor yet: the very first entity necessarily creates
// itself into existence.
func (s *Store) CreateEntity(ctx context.Context, e *directory.Entity, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO entities (id, type, name, display_name, attrs)
			VALUES ($1, $2, $3, nullif($4, ''), $5)
			RETURNING created_at, updated_at`,
			e.ID, string(e.Type), e.Name, e.DisplayName, e.Attrs,
		).Scan(&e.CreatedAt, &e.UpdatedAt)
		if err != nil {
			if pgErrCode(err) == codeUniqueViolation {
				return fmt.Errorf("%w: a %s named %q already exists",
					directory.ErrAlreadyExists, e.Type, e.Name)
			}
			return fmt.Errorf("store: creating entity: %w", err)
		}

		ev, err := event.New(event.ActionEntityCreated, &e.ID, actorID, map[string]any{
			"type": string(e.Type),
			"name": e.Name,
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
		&e.CreatedAt, &e.UpdatedAt, &e.DisabledAt)
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
