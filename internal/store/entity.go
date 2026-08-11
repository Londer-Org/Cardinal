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

const entityColumns = `id, type, name, coalesce(display_name, ''), attrs,
                       system, owner_id,
                       created_at, updated_at, disabled_at, redacted_at`

// PolicyReferenceExists reports whether an entity a policy names is there.
//
// The signature is deliberately plain strings: internal/server/policy cannot
// import this package without a cycle, so it defines the question and this
// answers it.
//
// A disabled entity counts as existing. Disabling a group is not the same
// mistake as never creating one — the rule still resolves, membership still
// resolves through it, and reporting it as missing would bury the case this
// check exists to find under one that is deliberate.
func (s *Store) PolicyReferenceExists(ctx context.Context, kind, identifier string) (bool, error) {
	column := "id"
	var value any

	switch kind {
	case "application":
		// Named by directory name, which is what the OIDC and forwardAuth
		// decision points put in the request. Deliberate, and stated in the
		// policy file: policy has to be readable by whoever maintains it.
		column, value = "name", identifier

	case "group", "host", "user":
		// Named by immutable UUID, because names are mutable (ADR 0002).
		//
		// A non-UUID here is not a lookup to attempt by name — it is a rule that
		// can never match whatever the directory contains, because the decision
		// points build these identifiers from the entity's id. Reporting it as
		// absent is therefore correct rather than a near miss, and it catches
		// the likelier authoring mistake: writing the group's name where its
		// identifier belongs, which produces a rule that looks obviously right
		// and never fires.
		id, err := uuid.Parse(identifier)
		if err != nil {
			//nolint:nilerr // not a lookup failure: an identifier that is not a UUID cannot name one of these, so "absent" is the answer rather than an error
			return false, nil
		}
		value = id

	default:
		return false, fmt.Errorf("store: %q is not an entity type policy can name", kind)
	}

	var found bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM entities WHERE `+column+` = $1 AND type = $2)`,
		value, kind).Scan(&found)
	if err != nil {
		return false, fmt.Errorf("store: checking for %s %q: %w", kind, identifier, err)
	}
	return found, nil
}

// CreateEntity persists a new entity and its audit event atomically.
//
// actorID is who is performing the creation. It is a pointer because
// bootstrapping has no actor yet: the very first entity necessarily creates
// itself into existence.
func (s *Store) CreateEntity(ctx context.Context, e *directory.Entity, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO entities (id, type, name, display_name, attrs, owner_id)
			VALUES ($1, $2, $3, nullif($4, ''), $5, $6)
			RETURNING created_at, updated_at`,
			e.ID, string(e.Type), e.Name, e.DisplayName, e.Attrs, e.OwnerID,
		).Scan(&e.CreatedAt, &e.UpdatedAt)
		if err != nil {
			if pgErrCode(err) == codeUniqueViolation {
				return fmt.Errorf("%w: a %s named %q already exists",
					directory.ErrAlreadyExists, e.Type, e.Name)
			}
			return fmt.Errorf("store: creating entity: %w", err)
		}

		// No "name" here: a username identifies a person, and the journal is
		// append-only, so it could never be erased. The entity_id carried by
		// the event resolves to the name via the entities table, which *is*
		// redactable. See ADR 0010.
		if projErr := defaultProjectionTx(ctx, tx, e); projErr != nil {
			return projErr
		}

		ev, err := event.New(event.ActionEntityCreated, &e.ID, actorID, map[string]any{
			"type": string(e.Type),
		})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// GetEntity looks an entity up by its immutable ID.
func (s *Store) GetEntity(ctx context.Context, id uuid.UUID) (*directory.Entity, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+entityColumns+` FROM entities WHERE id = $1`, id)
	return scanEntity(row)
}

// LookupEntity resolves a (type, name) pair to an entity.
//
// Names are mutable, so this is a convenience for humans at the CLI and UI
// edges only. Resolve once, then carry the ID: holding a name across a
// long-running operation reintroduces exactly the staleness bug that
// DN-as-identity causes in LDAP.
func (s *Store) LookupEntity(ctx context.Context, t directory.Type, name string) (*directory.Entity, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+entityColumns+` FROM entities WHERE type = $1 AND name = $2`,
		string(t), name)

	e, err := scanEntity(row)
	if errors.Is(err, directory.ErrNotFound) {
		return nil, fmt.Errorf("%w: no %s named %q", directory.ErrNotFound, t, name)
	}
	return e, err
}

// ListEntities returns entities of a type, oldest first. Passing an empty type
// lists everything.
func (s *Store) ListEntities(ctx context.Context, t directory.Type, includeDisabled bool) ([]*directory.Entity, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+entityColumns+`
		  FROM entities
		 WHERE ($1 = '' OR type = $1::entity_type)
		   AND ($2 OR disabled_at IS NULL)
		 ORDER BY type, name`,
		string(t), includeDisabled)
	if err != nil {
		return nil, fmt.Errorf("store: listing entities: %w", err)
	}
	defer rows.Close()

	var out []*directory.Entity
	for rows.Next() {
		e, err := scanEntity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating entities: %w", err)
	}
	return out, nil
}

// DisableEntity soft-deletes an entity.
//
// There is no hard delete, by design. Audit history has to keep resolving, and
// a departed employee's past grants still need to be explicable.
func (s *Store) DisableEntity(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE entities SET disabled_at = now(), updated_at = now()
			  WHERE id = $1 AND disabled_at IS NULL`, id)
		if err != nil {
			return fmt.Errorf("store: disabling entity: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Either it doesn't exist or it is already disabled. Both are
			// no-ops from the caller's perspective; don't write a misleading
			// audit event for something that didn't happen.
			return fmt.Errorf("%w: %s (or already disabled)", directory.ErrNotFound, id)
		}

		ev, err := event.New(event.ActionEntityDisabled, &id, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// EnableEntity undoes a disable.
//
// The other half of a door that was one-way for far too long. Disabling is the
// reversible way to cut somebody off — that is the whole reason it exists rather
// than a delete — and a "reversible" action with no way back is just a delete
// that keeps a row.
//
// What it deliberately does not restore: sessions and access tokens, which
// disabling revoked. Those are gone and should be. Somebody coming back signs
// in again, and a token that was live during the period an account was cut off
// is exactly what should not resume working.
func (s *Store) EnableEntity(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE entities SET disabled_at = NULL, updated_at = now()
			  WHERE id = $1 AND disabled_at IS NOT NULL`, id)
		if err != nil {
			return fmt.Errorf("store: enabling entity: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s (or already enabled)", directory.ErrNotFound, id)
		}

		// Refused after erasure, and this is the one case worth being firm
		// about. A redacted entity's name is a tombstone and its personal data
		// is gone; bringing it back would produce an account nobody can identify
		// and whose owner cannot be told it exists. If that person returns, they
		// get a new account.
		var redacted bool
		if queryErr := tx.QueryRow(ctx,
			`SELECT redacted_at IS NOT NULL FROM entities WHERE id = $1`, id,
		).Scan(&redacted); queryErr != nil {
			return fmt.Errorf("store: checking redaction: %w", queryErr)
		}
		if redacted {
			return fmt.Errorf("store: %s was erased under the right to be "+
				"forgotten and cannot be re-enabled — create a new account", id)
		}

		ev, err := event.New(event.ActionEntityEnabled, &id, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// scanner abstracts over pgx.Row and pgx.Rows so scanEntity serves both the
// single-row and iteration paths.
type scanner interface {
	Scan(dest ...any) error
}

func scanEntity(row scanner) (*directory.Entity, error) {
	var (
		e       directory.Entity
		typeStr string
	)
	err := row.Scan(&e.ID, &typeStr, &e.Name, &e.DisplayName, &e.Attrs,
		&e.System, &e.OwnerID,
		&e.CreatedAt, &e.UpdatedAt, &e.DisabledAt, &e.RedactedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, directory.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scanning entity: %w", err)
	}
	e.Type = directory.Type(typeStr)
	if e.Attrs == nil {
		e.Attrs = map[string]any{}
	}
	return &e, nil
}

// ProfileUpdate is the subset of an entity a person may change about themselves.
//
// Deliberately not `name`. The login is what appears in policy, in group
// listings and in every audit record a colleague reads, so letting someone
// rename themselves to a colleague's login — even briefly, even reversibly — is
// an impersonation primitive. Renaming stays an administrative act.
//
// Nil means "leave alone", which is what makes a form that submits one field
// not blank the others.
type ProfileUpdate struct {
	DisplayName *string
	Email       *string
}

// UpdateProfile changes an entity's own descriptive attributes.
//
// ADR 0002 rests on names being mutable attributes rather than identifiers —
// "renaming a person is an UPDATE, not a migration". Until this existed there
// was no UPDATE: entities could be created and disabled and nothing in between,
// so the claim was true of the schema and not of the software.
//
// Email lives in attrs rather than a column because not every entity type has
// one, and the schema registry governs what may go there.
func (s *Store) UpdateProfile(ctx context.Context, id uuid.UUID, in ProfileUpdate, actorID *uuid.UUID) (*directory.Entity, error) {
	var updated *directory.Entity

	err := s.InTx(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE entities
			   SET display_name = coalesce($2, display_name),
			       attrs = CASE
			                 WHEN $3::text IS NULL THEN attrs
			                 WHEN $3 = ''        THEN attrs - 'email'
			                 ELSE jsonb_set(attrs, '{email}', to_jsonb($3::text))
			               END,
			       updated_at = now()
			 WHERE id = $1 AND disabled_at IS NULL
			 RETURNING `+entityColumns,
			id, in.DisplayName, in.Email)

		e, err := scanEntity(row)
		if err != nil {
			return err
		}
		updated = e

		// The payload records which fields moved, never their values: an audit
		// record carrying a display name or an email address would put personal
		// data in an append-only log that erasure cannot reach (ADR 0010).
		ev, err := event.New(event.ActionEntityUpdated, &id, actorID,
			map[string]any{
				"display_name_changed": in.DisplayName != nil,
				"email_changed":        in.Email != nil,
			})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})

	return updated, err
}

// RenameEntity changes what something is called.
//
// The operation the whole data model exists to make ordinary. LDAP's original
// sin is that the DN *is* the identity, so renaming a person breaks every
// reference to them; here the identity is an immutable UUIDv7 and the name is
// an attribute, which means this is an UPDATE of one column and nothing else
// moves (ADR 0002).
//
// That claim was in the README and in no code. Nothing could rename anything.
//
// What genuinely follows a rename, and what does not, is worth being precise
// about because it is the interesting part:
//
//   - Group membership, policy, sessions, tokens, credentials and the audit
//     journal all reference the id. None of them notice.
//   - POSIX identity does follow: the assignment endpoint joins entities.name,
//     so `getent passwd` reports the new name on the next refresh. The uid does
//     not change, so every file on every disk keeps its owner — which is the
//     whole reason the number is permanent and the name is not.
//   - The home directory does *not* follow, and must not. It is recorded per
//     identity and the files are in it; moving them would be the data migration
//     this design exists to avoid.
//   - SSH certificate principals are issued per login, so the next certificate
//     carries the new name. Ones already issued keep the old, and expire within
//     minutes.
func (s *Store) RenameEntity(ctx context.Context, id uuid.UUID, name string, actorID *uuid.UUID) (*directory.Entity, error) {
	name = strings.TrimSpace(name)
	if err := directory.ValidateName(name); err != nil {
		return nil, err
	}

	var out *directory.Entity
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		var e directory.Entity
		var displayName *string

		err := tx.QueryRow(ctx, `
			UPDATE entities
			   SET name = $2, updated_at = now()
			 WHERE id = $1 AND redacted_at IS NULL
			 RETURNING id, type, name, display_name, attrs, created_at, updated_at,
			           disabled_at, redacted_at`,
			id, name,
		).Scan(&e.ID, &e.Type, &e.Name, &displayName, &e.Attrs, &e.CreatedAt,
			&e.UpdatedAt, &e.DisabledAt, &e.RedactedAt)

		if errors.Is(err, pgx.ErrNoRows) {
			// Redacted is deliberately indistinguishable from absent here. An
			// erased account's tombstone must not become editable, and renaming
			// one would reintroduce a name to a record whose whole purpose is
			// not to have one.
			return directory.ErrNotFound
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: another %s is already called %q",
				directory.ErrAlreadyExists, e.Type, name)
		}
		if err != nil {
			return fmt.Errorf("store: renaming entity: %w", err)
		}
		if displayName != nil {
			e.DisplayName = *displayName
		}

		// The fact, never the names. A login identifies a person and the
		// journal cannot hold one (ADR 0010) — so the old name is gone from the
		// record the moment it is replaced, which is the cost of the journal
		// being the one thing erasure cannot reach.
		ev, err := event.New(event.ActionEntityUpdated, &id, actorID,
			map[string]any{"name_changed": true})
		if err != nil {
			return err
		}
		if err := s.AppendEvent(ctx, tx, ev); err != nil {
			return err
		}

		out = &e
		return nil
	})
	return out, err
}
