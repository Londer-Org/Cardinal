package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/directory/event"
)

// ErrNameTaken means another host already answers to this name.
var ErrNameTaken = errors.New("store: another host already holds this name")

// AddHostAlias records another name a host may prove.
//
// Refuses a name already held by anything — another host's alias or another
// host's directory name. Both checks matter and the second is the one that is
// easy to forget: aliasing `web-02.prod` onto web-01 would hand web-01 a
// certificate for a machine that exists, which is worse than a collision
// between two aliases because the impersonated party is real.
func (s *Store) AddHostAlias(
	ctx context.Context, hostID uuid.UUID, name string, actorID *uuid.UUID,
) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("store: an alias cannot be blank")
	}

	return s.InTx(ctx, func(tx pgx.Tx) error {
		// The directory-name collision, checked explicitly because no constraint
		// can express it: aliases and entity names live in different tables.
		var otherID uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT id FROM entities
			 WHERE type = 'host' AND name = $1 AND id <> $2`, name, hostID).Scan(&otherID)
		switch {
		case err == nil:
			return fmt.Errorf("%w: %s is the directory name of another host", ErrNameTaken, name)
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("store: checking for a name collision: %w", err)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO host_aliases (host_id, name, added_by) VALUES ($1, $2, $3)`,
			hostID, name, actorID)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("%w: %s", ErrNameTaken, name)
			}
			return fmt.Errorf("store: adding host alias: %w", err)
		}

		ev, err := event.New(event.ActionHostAliasAdded, &hostID, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// RemoveHostAlias withdraws a name.
//
// Takes effect at the next renewal rather than immediately: a certificate
// already issued keeps working until it expires, because there is no revocation
// list. That is the same trade every short-lived credential here makes, and it
// is why host certificates are measured in days rather than months.
func (s *Store) RemoveHostAlias(
	ctx context.Context, hostID uuid.UUID, name string, actorID *uuid.UUID,
) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM host_aliases WHERE host_id = $1 AND name = $2`, hostID, name)
		if err != nil {
			return fmt.Errorf("store: removing host alias: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s", directory.ErrNotFound, name)
		}

		ev, err := event.New(event.ActionHostAliasRemoved, &hostID, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// HostPrincipals is every name this host may hold a certificate for.
//
// The directory name first, then aliases in the order they were added. Nothing
// is derived: a host called web-01.prod does not get `web-01` thrown in, because
// web-01.dev would then get it too and one of them would answer for the other.
func (s *Store) HostPrincipals(ctx context.Context, hostID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT e.name
		  FROM entities e
		 WHERE e.id = $1 AND e.type = 'host' AND e.disabled_at IS NULL
		 UNION ALL
		SELECT a.name
		  FROM host_aliases a
		  JOIN entities e ON e.id = a.host_id
		 WHERE a.host_id = $1 AND e.disabled_at IS NULL`, hostID)
	if err != nil {
		return nil, fmt.Errorf("store: reading host principals: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: scanning host principal: %w", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Empty means the host is disabled or gone. Returned as such rather than as
	// an empty list the caller might sign: OpenSSH treats a certificate with no
	// principals as valid for *any* name, so an empty list is the one result
	// that must never reach the signer.
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: host %s", directory.ErrNotFound, hostID)
	}
	return out, nil
}

// ListHostAliases returns a host's additional names.
func (s *Store) ListHostAliases(ctx context.Context, hostID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT name FROM host_aliases WHERE host_id = $1 ORDER BY added_at`, hostID)
	if err != nil {
		return nil, fmt.Errorf("store: listing host aliases: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: scanning host alias: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
