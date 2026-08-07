package store

import (
	"context"
	"fmt"
	"strings"
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

// Page bounds a listing.
//
// Offset rather than a cursor, because these lists are ordered by name and a
// directory's names do not churn between page turns the way a feed's do. Offset
// also gives a total, and "3 of 412 people" is worth more to an administrator
// than an opaque next-page token.
type Page struct {
	// Search matches login, display name and email. Empty matches everything.
	Search string

	Limit  int
	Offset int
}

// normalise clamps a page to something safe to put in a query.
func (p Page) normalise() Page {
	if p.Limit <= 0 || p.Limit > 200 {
		// A caller asking for everything gets a page anyway. An unbounded list
		// endpoint is a denial of service with a friendly name.
		p.Limit = 25
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	p.Search = strings.TrimSpace(p.Search)
	return p
}

// ListUsers returns a page of active users with the counts the console shows.
//
// Returns the total as well, so the caller can say how many there are rather
// than only how many it was given.
func (s *Store) ListUsers(ctx context.Context, page Page) ([]*UserSummary, int, error) {
	page = page.normalise()

	// One pattern, applied to login, display name and email. Deliberately not
	// full-text search: an administrator typing "alon" expects to find
	// "alonfils", and to_tsquery would not match a prefix of a single token
	// without more machinery than the problem deserves at this size.
	pattern := "%" + strings.ToLower(page.Search) + "%"

	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM entities e
		 WHERE e.type = 'user' AND e.disabled_at IS NULL
		   AND ($1 = '' OR lower(e.name) LIKE $2
		        OR lower(coalesce(e.display_name, '')) LIKE $2
		        OR lower(coalesce(e.attrs->>'email', '')) LIKE $2)`,
		page.Search, pattern).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: counting users: %w", err)
	}

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
		   AND ($1 = '' OR lower(e.name) LIKE $2
		        OR lower(coalesce(e.display_name, '')) LIKE $2
		        OR lower(coalesce(e.attrs->>'email', '')) LIKE $2)
		 ORDER BY e.name
		 LIMIT $3 OFFSET $4`, page.Search, pattern, page.Limit, page.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: listing users: %w", err)
	}
	defer rows.Close()

	var out []*UserSummary
	for rows.Next() {
		var u UserSummary
		if err := rows.Scan(&u.ID, &u.Login, &u.DisplayName, &u.Email,
			&u.Credentials, &u.Groups, &u.InvitationPending, &u.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("store: scanning user: %w", err)
		}
		out = append(out, &u)
	}
	return out, total, rows.Err()
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

	// System marks a group whose membership confers authority within Cardinal.
	System bool

	// Owner is the application this group exists for, empty when none.
	Owner string
}

// GroupKind narrows a group listing to one category.
//
// The three are genuinely different things that happen to share a table, and an
// administrator looking for the group an application uses should not have to
// read past the ones that hand out administrative power.
type GroupKind string

const (
	// AnyGroupKind is the unfiltered listing.
	AnyGroupKind GroupKind = ""

	// SystemGroups confer authority within Cardinal.
	SystemGroups GroupKind = "system"

	// ApplicationGroups exist for a registered application.
	ApplicationGroups GroupKind = "application"

	// PlainGroups belong to neither: ordinary directory structure.
	PlainGroups GroupKind = "plain"
)

// condition renders the kind as SQL against the entities alias `e`.
//
// Written here rather than assembled at the call site so the filter and the
// count cannot disagree — a total that counts different rows from the page is
// worse than no total.
func (k GroupKind) condition() string {
	switch k {
	case SystemGroups:
		return "e.system"
	case ApplicationGroups:
		return "NOT e.system AND e.owner_id IS NOT NULL"
	case PlainGroups:
		return "NOT e.system AND e.owner_id IS NULL"
	case AnyGroupKind:
		return "true"
	default:
		// An unrecognised filter shows everything rather than nothing. A typo
		// in a query string should not look like an empty directory.
		return "true"
	}
}

// ListGroups returns a page of active groups with their current member counts.
func (s *Store) ListGroups(ctx context.Context, page Page, kind GroupKind) ([]*GroupSummary, int, error) {
	page = page.normalise()
	pattern := "%" + strings.ToLower(page.Search) + "%"
	where := `
		 WHERE e.type = 'group' AND e.disabled_at IS NULL
		   AND (` + kind.condition() + `)
		   AND ($1 = '' OR lower(e.name) LIKE $2
		        OR lower(coalesce(e.display_name, '')) LIKE $2)`

	var total int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM entities e`+where,
		page.Search, pattern).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: counting groups: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT e.id, e.name, coalesce(e.display_name, ''),
		       (SELECT count(*) FROM group_members m
		         WHERE m.group_id = e.id AND m.valid_period @> now()),
		       e.system, coalesce(o.name, '')
		  FROM entities e
		  LEFT JOIN entities o ON o.id = e.owner_id`+where+`
		 ORDER BY e.name
		 LIMIT $3 OFFSET $4`, page.Search, pattern, page.Limit, page.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: listing groups: %w", err)
	}
	defer rows.Close()

	var out []*GroupSummary
	for rows.Next() {
		var g GroupSummary
		if err := rows.Scan(&g.ID, &g.Name, &g.DisplayName, &g.Members,
			&g.System, &g.Owner); err != nil {
			return nil, 0, fmt.Errorf("store: scanning group: %w", err)
		}
		out = append(out, &g)
	}
	return out, total, rows.Err()
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

// ApplicationRef is the least an owner picker needs.
type ApplicationRef struct {
	Name        string
	DisplayName string
}

// ListApplicationNames returns applications by name, for reference.
//
// Deliberately not the full registration. Associating a group with an
// application means naming it, not inspecting its redirect URIs — and the tier
// that manages groups is not the tier that registers clients, so handing it the
// whole record to populate a dropdown would widen access for a dropdown's sake.
func (s *Store) ListApplicationNames(ctx context.Context, page Page) ([]ApplicationRef, int, error) {
	page = page.normalise()
	pattern := "%" + strings.ToLower(page.Search) + "%"
	where := `
		 WHERE e.type = 'application' AND e.disabled_at IS NULL
		   AND ($1 = '' OR lower(e.name) LIKE $2
		        OR lower(coalesce(e.display_name, '')) LIKE $2)`

	var total int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM entities e`+where,
		page.Search, pattern).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: counting applications: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT e.name, coalesce(e.display_name, '')
		  FROM entities e`+where+`
		 ORDER BY e.name
		 LIMIT $3 OFFSET $4`, page.Search, pattern, page.Limit, page.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: listing applications: %w", err)
	}
	defer rows.Close()

	var out []ApplicationRef
	for rows.Next() {
		var a ApplicationRef
		if err := rows.Scan(&a.Name, &a.DisplayName); err != nil {
			return nil, 0, fmt.Errorf("store: scanning application: %w", err)
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// HostSummary is one machine, as the inventory shows it.
type HostSummary struct {
	ID          uuid.UUID
	Name        string
	DisplayName string

	// Enrolled means a live credential exists — the machine has proved which
	// host it is at least once.
	Enrolled bool

	// LastSeenAt is the operational question the whole page exists to answer.
	// Nil for a host that has never authenticated.
	LastSeenAt *time.Time

	// Aliases is how many additional names it may prove. Worth a column because
	// each one is the power to *be* that name, and a machine quietly holding
	// four of them is worth noticing.
	Aliases int

	// Groups it belongs to, which is what policy matches on. A host in no group
	// is one no rule can reach.
	Groups int

	Disabled bool
}

// ListHosts returns the fleet.
//
// Deliberately includes disabled hosts, unlike the other listings. A machine
// somebody cut off is exactly what an operator comes here looking for, and a
// page that hid it would answer "no such host" to the question "did we disable
// that one?".
func (s *Store) ListHosts(ctx context.Context, page Page) ([]*HostSummary, int, error) {
	page = page.normalise()
	pattern := "%" + strings.ToLower(page.Search) + "%"
	where := `
		 WHERE e.type = 'host'
		   AND ($1 = '' OR lower(e.name) LIKE $2
		        OR lower(coalesce(e.display_name, '')) LIKE $2
		        OR EXISTS (SELECT 1 FROM host_aliases a
		                    WHERE a.host_id = e.id AND lower(a.name) LIKE $2))`

	var total int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM entities e`+where,
		page.Search, pattern).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: counting hosts: %w", err)
	}

	// The credential columns come from the live row only. A retired one carries
	// a last-seen from before a rebuild, and showing it would say a machine is
	// healthy when what is actually alive is a key nobody uses.
	rows, err := s.pool.Query(ctx, `
		SELECT e.id, e.name, coalesce(e.display_name, ''),
		       c.id IS NOT NULL, c.last_seen_at,
		       (SELECT count(*) FROM host_aliases a WHERE a.host_id = e.id),
		       (SELECT count(*) FROM group_members m
		         WHERE m.member_id = e.id AND m.valid_period @> now()),
		       e.disabled_at IS NOT NULL
		  FROM entities e
		  LEFT JOIN host_credentials c
		         ON c.host_id = e.id AND c.valid_period @> now()`+where+`
		 ORDER BY e.name
		 LIMIT $3 OFFSET $4`, page.Search, pattern, page.Limit, page.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: listing hosts: %w", err)
	}
	defer rows.Close()

	var out []*HostSummary
	for rows.Next() {
		var h HostSummary
		if err := rows.Scan(&h.ID, &h.Name, &h.DisplayName, &h.Enrolled,
			&h.LastSeenAt, &h.Aliases, &h.Groups, &h.Disabled); err != nil {
			return nil, 0, fmt.Errorf("store: scanning host: %w", err)
		}
		out = append(out, &h)
	}
	return out, total, rows.Err()
}
