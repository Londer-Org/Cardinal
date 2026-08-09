package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.londer.be/cardinal/internal/directory"
)

// What provisioning needs that nothing else does.
//
// An identity provider keeps its own key for each account it manages and sends
// it back on every subsequent request. Storing it is what lets a reconciliation
// find the account it created last week rather than creating a second one — the
// failure mode of not storing it is a directory that grows a duplicate of every
// person each time the IdP forgets a mapping.

// ErrExternalIDTaken means another entity already claims this upstream key.
var ErrExternalIDTaken = errors.New("store: another entity already has this external id")

// EntityByExternalID finds what a provisioning client created earlier.
func (s *Store) EntityByExternalID(
	ctx context.Context, t directory.Type, externalID string,
) (*directory.Entity, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+entityColumns+` FROM entities WHERE type = $1 AND external_id = $2`,
		string(t), externalID)

	e, err := scanEntity(row)
	if errors.Is(err, directory.ErrNotFound) {
		return nil, fmt.Errorf("%w: no %s with external id %q", directory.ErrNotFound, t, externalID)
	}
	return e, err
}

// SetExternalID records the identity provider's own key for an entity.
//
// Separate from creation because the two happen at different moments: an
// account may exist long before an IdP claims it, and the first synchronisation
// after pointing Entra at an established directory is exactly that case. It
// matches on login, finds a person who is already there, and adopts them rather
// than creating a duplicate.
func (s *Store) SetExternalID(ctx context.Context, id uuid.UUID, externalID string) error {
	var value any
	if externalID != "" {
		value = externalID
	}

	_, err := s.pool.Exec(ctx,
		`UPDATE entities SET external_id = $2, updated_at = now() WHERE id = $1`,
		id, value)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == codeUniqueViolation {
			return fmt.Errorf("%w: %s", ErrExternalIDTaken, externalID)
		}
		return fmt.Errorf("store: setting the external id: %w", err)
	}
	return nil
}

// ExternalIDOf reads it back, empty when the entity was not provisioned.
func (s *Store) ExternalIDOf(ctx context.Context, id uuid.UUID) (string, error) {
	var external *string
	err := s.pool.QueryRow(ctx,
		`SELECT external_id FROM entities WHERE id = $1`, id).Scan(&external)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: entity %s", directory.ErrNotFound, id)
	}
	if err != nil {
		return "", fmt.Errorf("store: reading the external id: %w", err)
	}
	if external == nil {
		return "", nil
	}
	return *external, nil
}

// IsSystemGroup reports whether membership confers authority inside Cardinal.
//
// The check that keeps provisioning from being an escalation. Membership of a
// system group is a grant of administrative power, and a SCIM client that could
// modify one would be a path from "the IdP integration" to "directory
// administrator" (ADR 0031).
func (s *Store) IsSystemGroup(ctx context.Context, id uuid.UUID) (bool, error) {
	var system bool
	err := s.pool.QueryRow(ctx,
		`SELECT system FROM entities WHERE id = $1 AND type = 'group'`, id).Scan(&system)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("%w: group %s", directory.ErrNotFound, id)
	}
	if err != nil {
		return false, fmt.Errorf("store: reading whether a group is a system group: %w", err)
	}
	return system, nil
}
