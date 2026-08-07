package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/event"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrNoPOSIXIdentity means this entity has no uid or gid.
	//
	// Not an error condition on its own: most entities never need one. An
	// application has no business having a uid, and a person who only signs in
	// to web applications does not need one either.
	ErrNoPOSIXIdentity = errors.New("store: entity has no POSIX identity")

	// ErrPOSIXRangeExhausted means the configured range has no numbers left.
	ErrPOSIXRangeExhausted = errors.New("store: the POSIX id range is exhausted")
)

// POSIXFloor is the lowest number Cardinal will ever allocate.
//
// Enforced by a database constraint as well, because the consequence of getting
// it wrong is not a validation error but a machine where Cardinal's idea of uid
// 0 disagrees with the kernel's.
const POSIXFloor = 65536

// DefaultLoginShell is what a user gets when nobody says otherwise.
//
// /bin/bash rather than /bin/sh, because the number of people who want the
// second one and cannot say so is zero, and the number who get a surprising
// shell from a "safe" default is everybody.
const DefaultLoginShell = "/bin/bash"

// POSIXIdentity is an entity's number, and what a Unix machine does with it.
type POSIXIdentity struct {
	EntityID uuid.UUID
	Name     string
	Type     directory.Type

	// Number is a uid for a user and a gid for a group. One allocator serves
	// both, so the two can never collide.
	Number int

	// HomeDirectory and LoginShell are empty for a group.
	HomeDirectory string
	LoginShell    string
}

// PrimaryGroup is the user-private group a user belongs to.
//
// Same name, same number. Not a directory group and not stored anywhere — the
// convention is that every user has one, so there is nothing to record.
func (p POSIXIdentity) PrimaryGroup() (name string, gid int) {
	return p.Name, p.Number
}

// POSIXRange bounds allocation.
type POSIXRange struct {
	Low, High int
}

// DefaultPOSIXRange is where numbers come from when configuration is silent.
//
// Starts well above systemd's DynamicUser reservation (61184–65519) and far
// above the distribution's own accounts, and is large enough that nobody will
// reach the end of it. Deliberately not randomised per deployment the way
// FreeIPA does: that exists to make merging two directories safer, and Cardinal
// has no merge story to protect yet. Choosing a range per deployment is a
// setting rather than a surprise.
var DefaultPOSIXRange = POSIXRange{Low: 100000, High: 999999}

// posixAllocationLock serialises number allocation.
//
// An arbitrary constant; only its uniqueness within this database matters. The
// digits spell nothing — a readable value would invite somebody to pick a
// "related" one for a different lock and collide.
const posixAllocationLock int64 = 7079736978

// AssignPOSIXIdentity allocates the next free number to an entity.
//
// max + 1 within the range rather than filling gaps. Filling them would be
// tidier and is exactly wrong: a gap exists because somebody's number was
// released, and the files they owned still carry it.
//
// Allocation is serialised by a transaction-scoped advisory lock, which is not
// belt-and-braces. Under READ COMMITTED, `SELECT max(id_number)` cannot see a
// concurrent transaction's uncommitted INSERT, so two administrators creating
// accounts in the same moment both compute the same next number — measured, not
// theorised: six concurrent assignments produced three unique-violations before
// this lock existed. The constraint caught them, so no two accounts ever shared
// a uid, but half the callers got an error that reads like a bug in Cardinal.
//
// The lock is held for the length of one INSERT and released at commit. Handing
// out a uid happens when a person joins, so there is nothing here to contend
// over.
func (s *Store) AssignPOSIXIdentity(
	ctx context.Context, entityID uuid.UUID, r POSIXRange, actorID *uuid.UUID,
) (*POSIXIdentity, error) {
	if r.Low < POSIXFloor {
		return nil, fmt.Errorf(
			"store: a POSIX range starting at %d would collide with the system's "+
				"own accounts; the lowest allowed is %d", r.Low, POSIXFloor)
	}

	entity, err := s.GetEntity(ctx, entityID)
	if err != nil {
		return nil, err
	}
	if entity.Type != directory.TypeUser && entity.Type != directory.TypeGroup {
		return nil, fmt.Errorf(
			"store: %s is a %s — only users and groups have POSIX identities",
			entity.Name, entity.Type)
	}

	out := &POSIXIdentity{EntityID: entityID, Name: entity.Name, Type: entity.Type}

	if entity.Type == directory.TypeUser {
		out.HomeDirectory = DefaultHomeDirectory(entity.Name)
		out.LoginShell = DefaultLoginShell
	}

	err = s.InTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock($1)`, posixAllocationLock); err != nil {
			return fmt.Errorf("store: taking the POSIX allocation lock: %w", err)
		}

		var (
			home  *string
			shell *string
		)
		if out.HomeDirectory != "" {
			home, shell = &out.HomeDirectory, &out.LoginShell
		}

		err := tx.QueryRow(ctx, `
			INSERT INTO posix_identities
				(entity_id, id_number, home_directory, login_shell)
			SELECT $1, next.number, $4, $5
			  FROM (SELECT coalesce(max(id_number) + 1, $2) AS number
			          FROM posix_identities
			         WHERE id_number BETWEEN $2 AND $3) next
			 WHERE next.number <= $3
			RETURNING id_number`,
			entityID, r.Low, r.High, home, shell,
		).Scan(&out.Number)

		// No row means the WHERE excluded it, which can only be the range being
		// full. Distinguished from a real failure because the answer is
		// different: one is a configuration change, the other is an incident.
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %d–%d", ErrPOSIXRangeExhausted, r.Low, r.High)
		}
		if err != nil {
			return fmt.Errorf("store: assigning POSIX identity: %w", err)
		}

		ev, err := event.New(event.ActionPOSIXIdentityAssigned, &entityID, actorID,
			map[string]any{"id_number": out.Number})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DefaultHomeDirectory is where a login lands.
//
// /home/<login>, which is what every distribution does and what every runbook
// assumes. Configurable per user afterwards, because migrations inherit paths
// that were chosen years ago and refusing to represent them would mean refusing
// to import.
func DefaultHomeDirectory(login string) string {
	return "/home/" + login
}

// POSIXIdentityFor reads one entity's identity.
func (s *Store) POSIXIdentityFor(ctx context.Context, entityID uuid.UUID) (*POSIXIdentity, error) {
	var (
		p     POSIXIdentity
		home  *string
		shell *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT p.entity_id, e.name, e.type, p.id_number, p.home_directory, p.login_shell
		  FROM posix_identities p
		  JOIN entities e ON e.id = p.entity_id
		 WHERE p.entity_id = $1`, entityID,
	).Scan(&p.EntityID, &p.Name, &p.Type, &p.Number, &home, &shell)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoPOSIXIdentity
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading POSIX identity: %w", err)
	}
	if home != nil {
		p.HomeDirectory, p.LoginShell = *home, *shell
	}
	return &p, nil
}

// SetPOSIXAttributes changes a user's home directory or shell.
//
// The number is deliberately absent: it is the one field that must never
// change, because every file on every disk already records it. Changing it is
// not an edit, it is a new identity, and doing that is releasing the old number
// — which this design does not do.
func (s *Store) SetPOSIXAttributes(
	ctx context.Context, entityID uuid.UUID, home, shell string, actorID *uuid.UUID,
) error {
	home, shell = strings.TrimSpace(home), strings.TrimSpace(shell)
	if home == "" || shell == "" {
		return errors.New("store: home directory and login shell are both required")
	}
	if !strings.HasPrefix(home, "/") || !strings.HasPrefix(shell, "/") {
		return errors.New("store: home directory and login shell must be absolute paths")
	}

	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE posix_identities
			   SET home_directory = $2, login_shell = $3
			 WHERE entity_id = $1 AND home_directory IS NOT NULL`,
			entityID, home, shell)
		if err != nil {
			return fmt.Errorf("store: updating POSIX attributes: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNoPOSIXIdentity
		}

		ev, err := event.New(event.ActionPOSIXAttributesChanged, &entityID, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// ListPOSIXIdentities returns every assigned number, lowest first.
func (s *Store) ListPOSIXIdentities(ctx context.Context) ([]POSIXIdentity, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.entity_id, e.name, e.type, p.id_number, p.home_directory, p.login_shell
		  FROM posix_identities p
		  JOIN entities e ON e.id = p.entity_id
		 ORDER BY p.id_number`)
	if err != nil {
		return nil, fmt.Errorf("store: listing POSIX identities: %w", err)
	}
	defer rows.Close()

	var out []POSIXIdentity
	for rows.Next() {
		var (
			p     POSIXIdentity
			home  *string
			shell *string
		)
		if err := rows.Scan(&p.EntityID, &p.Name, &p.Type, &p.Number, &home, &shell); err != nil {
			return nil, fmt.Errorf("store: scanning POSIX identity: %w", err)
		}
		if home != nil {
			p.HomeDirectory, p.LoginShell = *home, *shell
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
