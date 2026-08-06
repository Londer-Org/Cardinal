package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Aggregate reads for the admin console.
//
// Written as single queries with sub-selects rather than a list followed by a
// count per row. The N+1 version is easy to write and gets slower in proportion
// to how much the directory is used, which is exactly backwards.

// UserSummary is one row of the people list.
type UserSummary struct {
	ID          uuid.UUID
	Login       string
	DisplayName string
	Email       string

	// Credentials is how many passkeys the account holds. Zero means nobody can
	// sign in to it yet, which is worth seeing at a glance: it distinguishes an
	// account waiting to be set up from one in use.
	Credentials int

	// Groups counts direct memberships only. Transitive membership needs the
	// recursive resolver per user, which is a query each and not worth it for a
	// number in a list.
	Groups int

	InvitationPending bool
	CreatedAt         time.Time
}

// FullyEnrolled reports whether losing one device would lock this account out.
func (u *UserSummary) FullyEnrolled() bool {
	return u.Credentials >= MinCredentialsForFullEnrollment
}

// ListUsers returns every active user with the counts the console shows.
func (s *Store) ListUsers(ctx context.Context) ([]*UserSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT e.id, e.name, coalesce(e.display_name, ''),
		       coalesce(e.attrs->>'email', ''),
		       (SELECT count(*) FROM webauthn_credentials w
		         WHERE w.entity_id = e.id AND w.revoked_at IS NULL),
		       (SELECT count(*) FROM group_members m
		         WHERE m.member_id = e.id AND m.valid_period @> now()),
		       EXISTS (SELECT 1 FROM enrollment_invitations i
		                WHERE i.subject_id = e.id
		                  AND i.redeemed_at IS NULL AND i.revoked_at IS NULL
		                  AND i.expires_at > now()),
		       e.created_at
		  FROM entities e
		 WHERE e.type = 'user' AND e.disabled_at IS NULL
		 ORDER BY e.name`)
	if err != nil {
		return nil, fmt.Errorf("store: listing users: %w", err)
	}
	defer rows.Close()

	var out []*UserSummary
	for rows.Next() {
		var u UserSummary
		if err := rows.Scan(&u.ID, &u.Login, &u.DisplayName, &u.Email,
			&u.Credentials, &u.Groups, &u.InvitationPending, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning user: %w", err)
		}
		out = append(out, &u)
	}
	return out, rows.Err()
}

// GroupSummary is one row of the groups list.
type GroupSummary struct {
	ID          uuid.UUID
	Name        string
	DisplayName string

	// Members counts direct members currently valid. A group whose grants have
	// all expired shows zero, which is the truth and the point of the temporal
	// model — membership is a fact about a moment, not a flag.
	Members int
}

// ListGroups returns every active group with its current member count.
func (s *Store) ListGroups(ctx context.Context) ([]*GroupSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT e.id, e.name, coalesce(e.display_name, ''),
		       (SELECT count(*) FROM group_members m
		         WHERE m.group_id = e.id AND m.valid_period @> now())
		  FROM entities e
		 WHERE e.type = 'group' AND e.disabled_at IS NULL
		 ORDER BY e.name`)
	if err != nil {
		return nil, fmt.Errorf("store: listing groups: %w", err)
	}
	defer rows.Close()

	var out []*GroupSummary
	for rows.Next() {
		var g GroupSummary
		if err := rows.Scan(&g.ID, &g.Name, &g.DisplayName, &g.Members); err != nil {
			return nil, fmt.Errorf("store: scanning group: %w", err)
		}
		out = append(out, &g)
	}
	return out, rows.Err()
}

// NamedGrant is a membership with both ends resolved to names.
//
// The console shows people and groups, not UUIDs. Resolving in SQL rather than
// looking each one up afterwards keeps a member list one query.
type NamedGrant struct {
	GroupID   uuid.UUID
	GroupName string

	MemberID   uuid.UUID
	MemberName string
	MemberType string

	From  time.Time
	Until *time.Time // nil means unbounded

	GrantedBy   *uuid.UUID
	GrantedByAs string
	Reason      string
}

// Expiring reports whether this grant has an end date.
//
// Until is nil for an unbounded grant. That needs saying because unbounded is
// stored as PostgreSQL's 'infinity' rather than NULL — a deliberate choice so
// range operators behave — which means upper_inf() is false for it and the
// obvious query hands Go a timestamp it cannot represent.
func (g *NamedGrant) Expiring() bool { return g.Until != nil }

const namedGrantColumns = `
	m.group_id, g.name,
	m.member_id, e.name, e.type::text,
	lower(m.valid_period),
	CASE
	  WHEN upper_inf(m.valid_period)
	    OR upper(m.valid_period) = 'infinity'::timestamptz
	  THEN NULL ELSE upper(m.valid_period)
	END,
	m.granted_by, coalesce(a.name, ''), coalesce(m.reason, '')`

const namedGrantJoins = `
	  FROM group_members m
	  JOIN entities g ON g.id = m.group_id
	  JOIN entities e ON e.id = m.member_id
	  LEFT JOIN entities a ON a.id = m.granted_by`

func scanNamedGrants(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
},
) ([]*NamedGrant, error) {
	var out []*NamedGrant
	for rows.Next() {
		var g NamedGrant
		if err := rows.Scan(&g.GroupID, &g.GroupName, &g.MemberID, &g.MemberName,
			&g.MemberType, &g.From, &g.Until, &g.GrantedBy, &g.GrantedByAs,
			&g.Reason); err != nil {
			return nil, fmt.Errorf("store: scanning grant: %w", err)
		}
		out = append(out, &g)
	}
	return out, rows.Err()
}

// MembersOfGroup lists a group's direct members as of now.
func (s *Store) MembersOfGroup(ctx context.Context, groupID uuid.UUID) ([]*NamedGrant, error) {
	rows, err := s.pool.Query(ctx, `SELECT`+namedGrantColumns+namedGrantJoins+`
		 WHERE m.group_id = $1 AND m.valid_period @> now()
		 ORDER BY e.name`, groupID)
	if err != nil {
		return nil, fmt.Errorf("store: listing members: %w", err)
	}
	defer rows.Close()
	return scanNamedGrants(rows)
}

// GroupsOfMember lists a subject's direct memberships as of now.
//
// Direct only, deliberately. The console shows what an administrator granted,
// because that is what they can revoke — a transitive membership has no grant
// to remove, and offering to remove it would be a lie.
func (s *Store) GroupsOfMember(ctx context.Context, memberID uuid.UUID) ([]*NamedGrant, error) {
	rows, err := s.pool.Query(ctx, `SELECT`+namedGrantColumns+namedGrantJoins+`
		 WHERE m.member_id = $1 AND m.valid_period @> now()
		 ORDER BY g.name`, memberID)
	if err != nil {
		return nil, fmt.Errorf("store: listing memberships: %w", err)
	}
	defer rows.Close()
	return scanNamedGrants(rows)
}
