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
	"slices"
	"strings"
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

// InGroup reports transitive membership by name.
//
// Convenient for simple checks, but not a substitute for policy: it answers
// "are they in this group", never "may they do this thing".
func (s *Subject) InGroup(name string) bool {
	return slices.ContainsFunc(s.Groups, func(g Group) bool {
		return strings.EqualFold(g.Name, name)
	})
}

// Resolver builds Subjects from directory state.
type Resolver struct {
	store *store.Store
}

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
