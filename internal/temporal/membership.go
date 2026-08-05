package temporal

import (
	"errors"

	"github.com/google/uuid"
)

// MaxResolutionDepth caps transitive group resolution.
//
// Nested groups form a directed graph, and nothing prevents a cycle: A may be a
// member of B while B is a member of A. The database rejects only *direct*
// self-membership. Resolution uses UNION (not UNION ALL), so duplicate
// elimination already guarantees termination — this cap is a second line of
// defence and a guard against pathological nesting depth, which in practice
// signals a modelling mistake rather than a legitimate hierarchy.
const MaxResolutionDepth = 32

// Grant is one time-bounded membership: MemberID belongs to GroupID for Period.
type Grant struct {
	GroupID  uuid.UUID
	MemberID uuid.UUID

	Period Period

	// GrantedBy and Reason are the audit trail that survives revocation.
	// Because revoking truncates the period rather than deleting the row, the
	// record of who granted access and why outlives the access itself — which
	// is exactly what an auditor asks for and what a boolean membership model
	// destroys.
	GrantedBy uuid.UUID
	Reason    string
}

// Membership is a resolved membership, direct or inherited.
type Membership struct {
	GroupID   uuid.UUID
	GroupName string

	// Depth is 1 for direct membership and increases through nested groups.
	// Surfacing it lets a UI explain *why* someone has access rather than only
	// that they do.
	Depth int
}

// Direct reports whether this membership is immediate rather than inherited.
func (m Membership) Direct() bool { return m.Depth == 1 }

var (
	// ErrOverlappingGrant means an active grant for this pair already covers
	// part of the requested period. The database enforces this via the
	// WITHOUT OVERLAPS primary key, so contradictory grants are impossible
	// rather than merely discouraged.
	ErrOverlappingGrant = errors.New("temporal: an overlapping grant already exists")

	// ErrSelfMembership means a group was made a member of itself.
	ErrSelfMembership = errors.New("temporal: a group cannot be a member of itself")

	// ErrNoSuchGrant means there was nothing to revoke.
	ErrNoSuchGrant = errors.New("temporal: no matching grant")
)
