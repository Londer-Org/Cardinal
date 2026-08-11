// Package claims resolves a subject into the facts every consumer needs.
//
// This package deliberately imports no protocol types. It answers one question
// — "who is this, what do they belong to, and how did they authenticate?" — and
// four different surfaces serialise that answer their own way:
//
//	OIDC provider          → ID-token / userinfo claims
//	Traefik forwardAuth    → X-Auth-Request-* headers
//	SCIM server            → User/Group resource attributes
//	SSH certificate issuer → certificate principals and extensions
//
// Keeping the resolution in one place means those four cannot drift into
// disagreeing about who someone is, which in an authorization system is not a
// cosmetic problem. See ADR 0007; the constraint is enforced by a test.
package claims

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// Subject is a resolved principal at a point in time.
//
// It is a snapshot, not a live view. ResolvedAt records when, because a
// consumer that caches this must know how stale it is allowed to be — and for
// authorization, "how stale" is a security question.
type Subject struct {
	ID          uuid.UUID
	Login       string
	DisplayName string
	Type        directory.Type

	// Attrs are schema-registry-governed extension attributes.
	Attrs map[string]any

	// Groups is the transitive closure, nearest first. Depth is preserved so a
	// UI can explain *why* someone has access rather than only that they do.
	Groups []Group

	// Auth describes how this session came to exist. Policy uses it for
	// step-up: an administrative action can demand a device-bound passkey
	// authenticated minutes ago, not merely a valid session that began fresh
	// this morning.
	Auth AuthContext

	ResolvedAt time.Time
}

// Group is one membership, direct or inherited.
type Group struct {
	ID    uuid.UUID
	Name  string
	Depth int
}

// Direct reports whether the membership is immediate rather than inherited.
func (g Group) Direct() bool { return g.Depth == 1 }

// AuthContext is what policy needs to know about how the subject proved
// themselves.
type AuthContext struct {
	Method string
	At     time.Time

	// DeviceBound means the credential cannot leave its hardware. Only a
	// device-bound factor reaches the highest assurance level, so policy can
	// require it for privileged actions.
	DeviceBound bool

	SessionID uuid.UUID
}

// Age is how long ago the subject actually authenticated.
//
// Distinct from session age on purpose: a twelve-hour session is fine for
// reading, and not fine for issuing recovery codes.
func (a AuthContext) Age() time.Duration { return time.Since(a.At) }

// GroupNames returns membership names, for display and for humans.
//
// Not for an application's permission logic — see GroupIDs. A name is a mutable
// attribute here by design (ADR 0002), so a relying party that branches on the
// string "aura-admins" has coupled itself to something Cardinal intends to be
// renameable, and the day someone renames it people lose access silently.
func (s *Subject) GroupNames() []string {
	names := make([]string, 0, len(s.Groups))
	for _, g := range s.Groups {
		names = append(names, g.Name)
	}
	return names
}

// GroupIDs returns membership identifiers, which is what an application should
// branch on.
//
// Cardinal's whole objection to LDAP is that the DN was both the identity and
// the path, so moving or renaming anything broke every reference to it
// (ADR 0002). Internally that is solved: a group is a UUID and its name is an
// attribute. The claims boundary was quietly re-introducing the same mistake,
// because names were the only thing that crossed it — so every application
// downstream had a permission model keyed on a mutable string.
//
// Emitted alongside the names rather than instead of them: a name is genuinely
// the right thing to *show* somebody, and an existing relying party should not
// break to fix a problem it does not have yet.
func (s *Subject) GroupIDs() []string {
	ids := make([]string, 0, len(s.Groups))
	for _, g := range s.Groups {
		ids = append(ids, g.ID.String())
	}
	return ids
}

// Resolver builds Subjects from directory state.
type Resolver struct {
	store *store.Store
}

// NewResolver builds a claims resolver over the given store.
func NewResolver(s *store.Store) *Resolver { return &Resolver{store: s} }

// Resolve projects a session into a Subject.
//
// Membership is resolved from the database on every call rather than from a
// cache, because a stale projection is an authorization bug: someone removed
// from a group must stop being in it immediately, not once a TTL expires.
// Caching belongs above this, with invalidation the caller can reason about.
func (r *Resolver) Resolve(ctx context.Context, session *store.Session) (*Subject, error) {
	entity, err := r.store.GetEntity(ctx, session.SubjectID)
	if err != nil {
		return nil, fmt.Errorf("claims: loading subject: %w", err)
	}
	if !entity.Active() {
		// A disabled account may still hold a valid session token. Refusing
		// here is what makes disabling take effect immediately.
		return nil, fmt.Errorf("claims: subject %s is disabled", entity.ID)
	}

	memberships, err := r.store.ResolveMemberships(ctx, entity.ID, time.Time{})
	if err != nil {
		return nil, fmt.Errorf("claims: resolving memberships: %w", err)
	}

	groups := make([]Group, 0, len(memberships))
	for _, m := range memberships {
		groups = append(groups, Group{ID: m.GroupID, Name: m.GroupName, Depth: m.Depth})
	}

	return &Subject{
		ID:          entity.ID,
		Login:       entity.Name,
		DisplayName: entity.DisplayName,
		Type:        entity.Type,
		Attrs:       entity.Attrs,
		Groups:      groups,
		Auth: AuthContext{
			Method:      session.AuthMethod,
			At:          session.AuthAt,
			DeviceBound: session.DeviceBound,
			SessionID:   session.ID,
		},
		ResolvedAt: time.Now().UTC(),
	}, nil
}

// ResolveByID projects an entity with no session context.
//
// For consumers that need the identity but not the authentication story —
// SCIM reads, or a host's POSIX record. The Auth context is left zero, and
// policy that depends on it will correctly refuse.
func (r *Resolver) ResolveByID(ctx context.Context, id uuid.UUID) (*Subject, error) {
	entity, err := r.store.GetEntity(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("claims: loading subject: %w", err)
	}

	memberships, err := r.store.ResolveMemberships(ctx, id, time.Time{})
	if err != nil {
		return nil, fmt.Errorf("claims: resolving memberships: %w", err)
	}

	groups := make([]Group, 0, len(memberships))
	for _, m := range memberships {
		groups = append(groups, Group{ID: m.GroupID, Name: m.GroupName, Depth: m.Depth})
	}

	return &Subject{
		ID:          entity.ID,
		Login:       entity.Name,
		DisplayName: entity.DisplayName,
		Type:        entity.Type,
		Attrs:       entity.Attrs,
		Groups:      groups,
		ResolvedAt:  time.Now().UTC(),
	}, nil
}

// Projected is the subset of a subject's groups that one application is told
// about.
//
// Deliberately not []Group. The assignment that would put a filtered set back
// into the Subject the policy engine reads does not compile, and that is the
// whole reason this type exists: forwardauth.go resolves one subject and uses
// it three times — as the policy input, in the decision log, and to write the
// headers — so narrowing that variable is the obvious way to add filtering and
// would silently change what Cardinal decides.
//
// Both directions of that mistake are real. `directory-admins-may-administer`
// permits on group membership, so filtering before the decision would refuse
// administration to actual administrators; and a deployment writing a forbid
// keyed on a group would find it stops matching once that group is filtered
// out, granting access instead of refusing it.
//
// The field is unexported so a Projected cannot be built outside this package
// either. See ADR 0032.
type Projected struct{ groups []Group }

// Names is what to show a person. See GroupNames for why a name is the wrong
// thing for an application to branch on.
func (p Projected) Names() []string {
	names := make([]string, 0, len(p.groups))
	for _, g := range p.groups {
		names = append(names, g.Name)
	}
	return names
}

// IDs is what an application should key on.
func (p Projected) IDs() []string {
	ids := make([]string, 0, len(p.groups))
	for _, g := range p.groups {
		ids = append(ids, g.ID.String())
	}
	return ids
}

// Len reports how many groups survived the projection, for the log line that
// says an application is being told about none.
func (p Projected) Len() int { return len(p.groups) }

// GroupsFor narrows the closure to what one application may be told.
//
// Order and depth are preserved, so the nearest-first contract still holds for
// whoever receives it. Subject.Groups is untouched: the console, self-service
// and the decision log all want the whole thing, and a projection that reached
// back into resolution would make "what am I a member of" depend on who asked.
func (s *Subject) GroupsFor(p store.GroupProjection) Projected {
	if p.Mode == store.ProjectionAll {
		return Projected{groups: s.Groups}
	}
	visible := make([]Group, 0, len(s.Groups))
	for _, g := range s.Groups {
		if p.Visible[g.ID] {
			visible = append(visible, g)
		}
	}
	return Projected{groups: visible}
}
