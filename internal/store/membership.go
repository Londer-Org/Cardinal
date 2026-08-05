package store

import (
	"context"
	"fmt"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/event"
	"github.com/arthur-lonfils/cardinal/internal/temporal"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Grant records a time-bounded membership.
//
// A bounded period is the shape most grants should take: whoever asks for
// access almost always knows when they will stop needing it, and a bounded
// grant cannot be forgotten about. Expiry is enforced by every read, not by a
// sweeper job whose failure would silently *extend* access.
func (s *Store) Grant(ctx context.Context, g temporal.Grant, actorID *uuid.UUID) error {
	if err := g.Period.Validate(); err != nil {
		return err
	}
	if g.GroupID == g.MemberID {
		return temporal.ErrSelfMembership
	}

	return s.InTx(ctx, func(tx pgx.Tx) error {
		// The casts are required, not decorative: without them PostgreSQL
		// cannot infer a type for a parameter sitting beside an untyped
		// 'infinity' literal, and resolves coalesce() to text instead.
		_, err := tx.Exec(ctx, `
			INSERT INTO group_members
				(group_id, member_id, valid_period, granted_by, reason)
			VALUES ($1, $2,
			        tstzrange($3::timestamptz,
			                  coalesce($4::timestamptz, 'infinity'::timestamptz)),
			        $5, nullif($6, ''))`,
			g.GroupID, g.MemberID, g.Period.From, g.Period.Until,
			g.GrantedBy, g.Reason)
		if err != nil {
			switch {
			case pgErrCode(err) == codeExclusionViolation:
				return fmt.Errorf("%w: %s already belongs to %s during %s",
					temporal.ErrOverlappingGrant, g.MemberID, g.GroupID, g.Period)
			case constraintName(err) == "group_members_no_self":
				return temporal.ErrSelfMembership
			case pgErrCode(err) == codeForeignKeyViolation:
				return fmt.Errorf("store: granting membership: group or member does not exist: %w", err)
			}
			return fmt.Errorf("store: granting membership: %w", err)
		}

		// The justification is deliberately absent: free text reliably ends up
		// containing personal data, and the journal cannot be edited. It lives
		// in group_members.reason, which is redactable, and the temporal model
		// preserves it there across revocation anyway. See ADR 0010.
		ev, err := event.New(event.ActionMembershipGranted, &g.MemberID, actorID,
			map[string]any{
				"group_id": g.GroupID,
				"from":     g.Period.From,
				"until":    g.Period.Until,
			})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// Revoke ends a membership at the given instant, leaving history intact.
//
// This is PostgreSQL 19's FOR PORTION OF doing the interesting work: rather
// than deleting the row, it truncates the validity period to end at `at`. The
// historical fact that the grant existed — and crucially who made it and why —
// survives revocation. Asking "who could reach production in March?" still
// returns the right answer afterwards.
//
// Revoking mid-period splits the row; revoking from `at` to infinity simply
// shortens it.
func (s *Store) Revoke(ctx context.Context, groupID, memberID uuid.UUID, at time.Time, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			DELETE FROM group_members
			  FOR PORTION OF valid_period FROM $3::timestamptz TO 'infinity'
			 WHERE group_id = $1 AND member_id = $2`,
			groupID, memberID, at)
		if err != nil {
			return fmt.Errorf("store: revoking membership: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s is not a member of %s at %s",
				temporal.ErrNoSuchGrant, memberID, groupID, at.Format(time.RFC3339))
		}

		ev, err := event.New(event.ActionMembershipRevoked, &memberID, actorID,
			map[string]any{
				"group_id":   groupID,
				"revoked_at": at,
			})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// DirectMembers lists entities directly in a group at the given instant.
// Pass the zero time for "now".
func (s *Store) DirectMembers(ctx context.Context, groupID uuid.UUID, at time.Time) ([]temporal.Grant, error) {
	at = orNow(at)

	rows, err := s.pool.Query(ctx, `
		SELECT member_id, lower(valid_period),
		       nullif(upper(valid_period), 'infinity'),
		       granted_by, coalesce(reason, '')
		  FROM group_members
		 WHERE group_id = $1 AND valid_period @> $2::timestamptz
		 ORDER BY lower(valid_period)`,
		groupID, at)
	if err != nil {
		return nil, fmt.Errorf("store: listing members: %w", err)
	}
	defer rows.Close()

	var out []temporal.Grant
	for rows.Next() {
		g := temporal.Grant{GroupID: groupID}
		if err := rows.Scan(&g.MemberID, &g.Period.From, &g.Period.Until,
			&g.GrantedBy, &g.Reason); err != nil {
			return nil, fmt.Errorf("store: scanning member: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ResolveMemberships returns every group an entity belongs to at the given
// instant, transitively through nested groups. Pass the zero time for "now".
//
// This is the reference implementation of the MembershipResolver contract: a
// recursive CTE, chosen over PostgreSQL 19's SQL/PGQ property graphs because
// the release notes state property graphs are "processed internally like
// views, written as standard relational queries" — so PGQ is ergonomic sugar
// over the same relational plan rather than a distinct execution engine. A PGQ
// implementation may be added later as a readability refactor and validated
// differentially against this one, but this stays the correctness baseline.
//
// UNION rather than UNION ALL is load-bearing: nested groups can form cycles,
// and duplicate elimination is what guarantees termination.
func (s *Store) ResolveMemberships(ctx context.Context, memberID uuid.UUID, at time.Time) ([]temporal.Membership, error) {
	at = orNow(at)

	rows, err := s.pool.Query(ctx, `
		WITH RECURSIVE reachable AS (
			-- Direct memberships active at the instant in question.
			SELECT gm.group_id, 1 AS depth
			  FROM group_members gm
			 WHERE gm.member_id = $1
			   AND gm.valid_period @> $2::timestamptz

			UNION

			-- Groups reachable through groups we already reached. The period
			-- check applies at every hop: an expired link breaks the chain, so
			-- inherited access cannot outlive the membership granting it.
			SELECT gm.group_id, r.depth + 1
			  FROM group_members gm
			  JOIN reachable r ON gm.member_id = r.group_id
			 WHERE gm.valid_period @> $2::timestamptz
			   AND r.depth < $3
		)
		SELECT r.group_id, e.name, min(r.depth) AS depth
		  FROM reachable r
		  JOIN entities e ON e.id = r.group_id
		 -- A disabled group grants nothing, even while memberships persist.
		 WHERE e.disabled_at IS NULL
		 GROUP BY r.group_id, e.name
		 ORDER BY depth, e.name`,
		memberID, at, temporal.MaxResolutionDepth)
	if err != nil {
		return nil, fmt.Errorf("store: resolving memberships: %w", err)
	}
	defer rows.Close()

	var out []temporal.Membership
	for rows.Next() {
		var m temporal.Membership
		if err := rows.Scan(&m.GroupID, &m.GroupName, &m.Depth); err != nil {
			return nil, fmt.Errorf("store: scanning membership: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// IsMemberAt reports whether memberID belongs to groupID at the given instant,
// directly or transitively.
//
// This is the question every authorization decision ultimately reduces to.
func (s *Store) IsMemberAt(ctx context.Context, memberID, groupID uuid.UUID, at time.Time) (bool, error) {
	memberships, err := s.ResolveMemberships(ctx, memberID, at)
	if err != nil {
		return false, err
	}
	for _, m := range memberships {
		if m.GroupID == groupID {
			return true, nil
		}
	}
	return false, nil
}

// GrantHistory returns every grant for a pair, including expired and revoked
// ones, oldest first.
//
// This is what makes "who had access in March, and who gave it to them?"
// answerable — the question a boolean membership model cannot answer at all.
func (s *Store) GrantHistory(ctx context.Context, groupID, memberID uuid.UUID) ([]temporal.Grant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT lower(valid_period), nullif(upper(valid_period), 'infinity'),
		       granted_by, coalesce(reason, '')
		  FROM group_members
		 WHERE group_id = $1 AND member_id = $2
		 ORDER BY lower(valid_period)`,
		groupID, memberID)
	if err != nil {
		return nil, fmt.Errorf("store: reading grant history: %w", err)
	}
	defer rows.Close()

	var out []temporal.Grant
	for rows.Next() {
		g := temporal.Grant{GroupID: groupID, MemberID: memberID}
		if err := rows.Scan(&g.Period.From, &g.Period.Until,
			&g.GrantedBy, &g.Reason); err != nil {
			return nil, fmt.Errorf("store: scanning grant: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}
