// Package directory implements Cardinal's core identity model.
//
// The central idea, and the thing that separates Cardinal from LDAP, is that an
// entity's ID is assigned once and never changes or is reused. Names, emails
// and organisational placement are ordinary mutable attributes hanging off it.
// See docs/adr/0002-identity-is-an-immutable-uuid.md.
package directory

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Type enumerates the kinds of entity Cardinal knows about. Every principal and
// every resource lives in one identity space, so a host can be a member of a
// group and a group can be the subject of a policy without special-casing.
type Type string

const (
	TypeUser           Type = "user"
	TypeGroup          Type = "group"
	TypeHost           Type = "host"
	TypeServiceAccount Type = "service_account"
	TypeApplication    Type = "application"
	TypeDevice         Type = "device"
	TypeRole           Type = "role"
)

// AllTypes is the authoritative list, kept in sync with the entity_type enum in
// migrations/0001_foundation.sql.
var AllTypes = []Type{
	TypeUser, TypeGroup, TypeHost, TypeServiceAccount,
	TypeApplication, TypeDevice, TypeRole,
}

func (t Type) Valid() bool { return slices.Contains(AllTypes, t) }

func (t Type) String() string { return string(t) }

// namePattern constrains entity names to something safe to embed in a POSIX
// account name, an SSH certificate principal, and a Cedar entity identifier
// without escaping. Being strict here avoids a whole class of injection
// problems later, and loosening a rule is far easier than tightening one.
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Entity is a principal or resource. Its ID is the only true identifier.
type Entity struct {
	// ID is immutable for the entity's entire existence and is never reused,
	// even after deletion. Every reference anywhere in Cardinal is by ID.
	ID uuid.UUID

	Type Type

	// Name is human-readable and unique per type, but freely mutable. It is
	// never an identifier: resolve it to an ID at the edge and use the ID from
	// there on.
	Name string

	DisplayName string

	// Attrs holds schema-registry-governed extension attributes. Core
	// attributes get real columns; this is for organisation-specific
	// additions. The map[string]any is a deliberate serialisation boundary.
	Attrs map[string]any

	// System marks a group whose membership confers authority within Cardinal
	// itself. Granting one is an administrative act of the same weight as the
	// power it hands over, so it needs AdministerDirectory rather than merely
	// ManageUsers — otherwise a narrow tier can hand itself a broad one.
	System bool

	// OwnerID is the application a group exists for, if any. Organisational
	// only: Cardinal treats an owned group exactly like any other, and it still
	// reaches applications through the groups claim.
	OwnerID *uuid.UUID

	CreatedAt time.Time
	UpdatedAt time.Time

	// RedactedAt records GDPR erasure. The row survives so audit references
	// still resolve, but every personal field has been tombstoned. See ADR 0010.
	RedactedAt *time.Time

	// DisabledAt implements soft deletion. Entities are never hard-deleted:
	// audit history must keep resolving, and a departed employee's past grants
	// still need to be explicable.
	DisabledAt *time.Time
}

// Redacted reports whether this entity's personal data has been erased.
func (e *Entity) Redacted() bool { return e.RedactedAt != nil }

// Active reports whether the entity may be used as a principal. Callers must
// check this; the database deliberately does not filter disabled entities out
// of joins, because historical queries need to see them.
func (e *Entity) Active() bool { return e.DisabledAt == nil }

var (
	ErrNotFound      = errors.New("directory: entity not found")
	ErrAlreadyExists = errors.New("directory: entity already exists")
	ErrInvalidType   = errors.New("directory: invalid entity type")
	ErrInvalidName   = errors.New("directory: invalid entity name")
)

// ValidateName enforces namePattern and reports precisely what is wrong, since
// this error usually reaches a human at a CLI prompt.
func ValidateName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: must not be empty", ErrInvalidName)
	case len(name) > 63:
		return fmt.Errorf("%w: %q is %d characters, maximum is 63",
			ErrInvalidName, name, len(name))
	case name != strings.ToLower(name):
		return fmt.Errorf("%w: %q must be lowercase", ErrInvalidName, name)
	case !namePattern.MatchString(name):
		return fmt.Errorf(
			"%w: %q must start with a letter or digit and contain only "+
				"lowercase letters, digits, dot, underscore or hyphen",
			ErrInvalidName, name)
	}
	return nil
}

// NewEntity builds a validated Entity with a fresh UUIDv7.
//
// UUIDv7 rather than v4 because it is time-ordered, which keeps index locality
// good on the primary key and makes IDs roughly sortable by creation time when
// reading raw tables during an incident.
func NewEntity(t Type, name, displayName string) (*Entity, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidType, t)
	}
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("directory: generating id: %w", err)
	}

	return &Entity{
		ID:          id,
		Type:        t,
		Name:        name,
		DisplayName: displayName,
		Attrs:       map[string]any{},
	}, nil
}
