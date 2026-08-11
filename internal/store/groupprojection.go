package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"go.londer.be/cardinal/internal/directory"
)

// How much of a subject's group closure one application is told about.
//
// The forwardAuth header and the OIDC groups claim were built from the whole
// transitive closure, so every application a person signed into learned their
// entire position in the organisation. ADR 0032 is the argument; migration 0033
// is the schema.
//
// The rule that must not bend: this changes what an application is *told* and
// never what Cardinal *decides*. Cedar evaluates the full closure exactly as
// before, which is why nothing here is reachable from the policy path.

// errSystemGroupNotProjectable refuses the one group kind that is Cardinal's
// own business. Its own error so a handler can turn it into a 400 that names
// the reason rather than a 500 that names nothing.
var errSystemGroupNotProjectable = errors.New(
	"a system group confers authority inside Cardinal and is never projected " +
		"to an application")

// Projection modes.
const (
	// ProjectionAll is every group, which is what every deployment had before
	// this existed and what migration 0033 wrote for applications that already
	// existed.
	ProjectionAll = "all"

	// ProjectionOwned is the groups the application owns, plus any it has been
	// explicitly allowed to see.
	ProjectionOwned = "owned"
)

// GroupProjection is the answer to "which groups may this application be told
// about", resolved once per request.
type GroupProjection struct {
	Mode string

	// Visible is the set an owned-mode projection may include. Empty and unread
	// when Mode is ProjectionAll.
	Visible map[uuid.UUID]bool
}

// GroupProjectionFor resolves what one application may be told.
//
// A missing row means owned, not all. That is the conservative direction for a
// disclosure control: a row that failed to be written, or was deleted by hand,
// produces an application that sees too little — which somebody notices and
// reports — rather than one that quietly sees everything, which nobody does.
// Every application created through this package gets a row, so absence is an
// anomaly rather than the normal case.
func (s *Store) GroupProjectionFor(ctx context.Context, applicationID uuid.UUID) (GroupProjection, error) {
	var mode string
	err := s.pool.QueryRow(ctx,
		`SELECT mode FROM application_group_projection WHERE entity_id = $1`,
		applicationID).Scan(&mode)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		mode = ProjectionOwned
	case err != nil:
		return GroupProjection{}, fmt.Errorf("store: reading the group projection: %w", err)
	}

	if mode == ProjectionAll {
		return GroupProjection{Mode: ProjectionAll}, nil
	}

	// Owned and allowed in one query. Two round trips would be two chances for
	// the set to be half-read on a request that is deciding what to disclose.
	rows, err := s.pool.Query(ctx, `
		SELECT id FROM entities
		 WHERE type = 'group' AND owner_id = $1
		UNION
		SELECT group_id FROM application_visible_groups
		 WHERE application_id = $1`, applicationID)
	if err != nil {
		return GroupProjection{}, fmt.Errorf("store: reading visible groups: %w", err)
	}
	defer rows.Close()

	visible := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if scanErr := rows.Scan(&id); scanErr != nil {
			return GroupProjection{}, fmt.Errorf("store: scanning a visible group: %w", scanErr)
		}
		visible[id] = true
	}
	if err := rows.Err(); err != nil {
		return GroupProjection{}, err
	}

	return GroupProjection{Mode: ProjectionOwned, Visible: visible}, nil
}

// SetGroupProjection changes how much an application is told.
func (s *Store) SetGroupProjection(ctx context.Context, applicationID uuid.UUID, mode string, actorID *uuid.UUID) error {
	if mode != ProjectionAll && mode != ProjectionOwned {
		return fmt.Errorf("store: a projection mode is %q or %q, not %q",
			ProjectionAll, ProjectionOwned, mode)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO application_group_projection (entity_id, mode, updated_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (entity_id) DO UPDATE
		   SET mode = excluded.mode, updated_at = now(), updated_by = excluded.updated_by`,
		applicationID, mode, actorID)
	if err != nil {
		return fmt.Errorf("store: setting the group projection: %w", err)
	}
	return nil
}

// AllowGroupSight lets an application be told about a group it does not own.
//
// System groups are refused here rather than only by the CHECK in migration
// 0033. The constraint names the three that exist today because a CHECK cannot
// read another table; this reads `system` and so stays right when a later
// migration adds a fourth. Membership of one is authority inside Cardinal, and
// an application branching on it would be reading a Cardinal internal as though
// it were one of its own roles.
func (s *Store) AllowGroupSight(ctx context.Context, applicationID, groupID uuid.UUID, actorID *uuid.UUID) error {
	var system bool
	if err := s.pool.QueryRow(ctx,
		`SELECT system FROM entities WHERE id = $1 AND type = 'group'`,
		groupID).Scan(&system); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: no such group", directory.ErrNotFound)
		}
		return fmt.Errorf("store: reading the group: %w", err)
	}
	if system {
		return fmt.Errorf("store: %w", errSystemGroupNotProjectable)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO application_visible_groups (application_id, group_id, added_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (application_id, group_id) DO NOTHING`,
		applicationID, groupID, actorID)
	if err != nil {
		return fmt.Errorf("store: allowing sight of a group: %w", err)
	}
	return nil
}

// DenyGroupSight removes an allowance. Removing one the application owns is a
// no-op rather than an error: ownership is not granted here and cannot be taken
// away here either.
func (s *Store) DenyGroupSight(ctx context.Context, applicationID, groupID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM application_visible_groups
		 WHERE application_id = $1 AND group_id = $2`, applicationID, groupID)
	if err != nil {
		return fmt.Errorf("store: removing sight of a group: %w", err)
	}
	return nil
}

// defaultProjectionTx writes the mode a newly created application starts with.
//
// Owned, which is the opposite of what migration 0033 wrote for applications
// that already existed. The asymmetry is deliberate (ADR 0032): an upgrade
// tells no existing application anything different, and anything registered
// afterwards is narrow by default. The command that creates one says which it
// got, because a developer wondering where a group went should find the answer
// in the output of the command they just ran.
//
// Called from both entity-creation paths. There are two because an OIDC
// registration builds its client and its entity in one transaction while
// `application create` does not, and a rule living in only one of them would be
// a rule that applies to half the applications in the directory.
func defaultProjectionTx(ctx context.Context, tx pgx.Tx, e *directory.Entity) error {
	if e.Type != directory.TypeApplication {
		return nil
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO application_group_projection (entity_id, mode)
		VALUES ($1, $2) ON CONFLICT (entity_id) DO NOTHING`,
		e.ID, ProjectionOwned)
	if err != nil {
		return fmt.Errorf("store: setting the initial group projection: %w", err)
	}
	return nil
}

// VisibleGroup is one group an application is told about, and why.
type VisibleGroup struct {
	ID   uuid.UUID
	Name string

	// Owned distinguishes a group that belongs to this application from one it
	// was granted sight of. The two are administered differently — ownership is
	// set when the group is created — so a listing that blurred them would
	// leave "why can it see this?" unanswerable.
	Owned bool
}

// GroupsVisibleTo lists what an application in owned mode is told about.
//
// Answers the question that had no answer while every application saw
// everything: which groups does this one actually receive.
func (s *Store) GroupsVisibleTo(ctx context.Context, applicationID uuid.UUID) ([]VisibleGroup, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT e.id, e.name, true AS owned
		  FROM entities e
		 WHERE e.type = 'group' AND e.owner_id = $1
		UNION
		SELECT g.id, g.name, false
		  FROM application_visible_groups v
		  JOIN entities g ON g.id = v.group_id
		 WHERE v.application_id = $1
		 ORDER BY 2`, applicationID)
	if err != nil {
		return nil, fmt.Errorf("store: listing visible groups: %w", err)
	}
	defer rows.Close()

	out := []VisibleGroup{}
	for rows.Next() {
		var g VisibleGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Owned); err != nil {
			return nil, fmt.Errorf("store: scanning a visible group: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
