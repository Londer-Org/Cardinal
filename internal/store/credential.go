package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/event"
)

// MinCredentialsForFullEnrollment is why lockout is rare rather than merely
// recoverable.
//
// One passkey on one laptop is one theft away from an account nobody can reach.
// Requiring a second — ideally a hardware key kept elsewhere — means most
// recovery events simply never happen, which beats any recovery mechanism.
const MinCredentialsForFullEnrollment = 2

var (
	ErrCredentialNotFound = errors.New("store: credential not found")
	ErrCredentialExists   = errors.New("store: credential already registered")

	// ErrCloneDetected means an authenticator's signature counter went
	// backwards, which should be impossible for a genuine device.
	ErrCloneDetected = errors.New("store: authenticator signature counter regressed")
)

// Credential is a registered passkey.
type Credential struct {
	ID       uuid.UUID
	EntityID uuid.UUID

	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	AAGUID       []byte

	// BackupEligible reports whether the credential can sync to a cloud
	// account. Synced passkeys are far more recoverable but less hardware-bound,
	// so policy may require BackupEligible == false for high-assurance roles.
	BackupEligible bool
	BackupState    bool

	Name       string
	Transports []string

	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

func (c *Credential) Active() bool { return c.RevokedAt == nil }

// RegisterCredential stores a newly created passkey.
func (s *Store) RegisterCredential(ctx context.Context, entityID uuid.UUID, cred *webauthn.Credential, name string) (*Credential, error) {
	out := &Credential{
		EntityID:       entityID,
		CredentialID:   cred.ID,
		PublicKey:      cred.PublicKey,
		SignCount:      cred.Authenticator.SignCount,
		AAGUID:         cred.Authenticator.AAGUID,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		Name:           name,
		Transports:     transportStrings(cred.Transport),
	}

	err := s.InTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO webauthn_credentials
				(entity_id, credential_id, public_key, sign_count, aaguid,
				 backup_eligible, backup_state, name, transports)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING id, created_at`,
			entityID, out.CredentialID, out.PublicKey, int64(out.SignCount),
			out.AAGUID, out.BackupEligible, out.BackupState, name, out.Transports,
		).Scan(&out.ID, &out.CreatedAt)
		if err != nil {
			if pgErrCode(err) == codeUniqueViolation {
				return ErrCredentialExists
			}
			return fmt.Errorf("store: registering credential: %w", err)
		}

		// No credential name in the payload: users label their keys with
		// things like "Arthur's work laptop", which is personal data, and the
		// journal cannot be erased (ADR 0010).
		ev, err := event.New(event.ActionCredentialRegistered, &entityID, &entityID,
			map[string]any{"device_bound": !out.BackupEligible})
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

// CredentialsFor returns an entity's active credentials.
func (s *Store) CredentialsFor(ctx context.Context, entityID uuid.UUID) ([]*Credential, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, entity_id, credential_id, public_key, sign_count, aaguid,
		       backup_eligible, backup_state, name, transports,
		       created_at, last_used_at, revoked_at
		  FROM webauthn_credentials
		 WHERE entity_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at`, entityID)
	if err != nil {
		return nil, fmt.Errorf("store: listing credentials: %w", err)
	}
	defer rows.Close()

	var out []*Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CredentialByID looks up a credential by the authenticator's own identifier,
// which is what arrives during authentication.
func (s *Store) CredentialByID(ctx context.Context, credentialID []byte) (*Credential, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, entity_id, credential_id, public_key, sign_count, aaguid,
		       backup_eligible, backup_state, name, transports,
		       created_at, last_used_at, revoked_at
		  FROM webauthn_credentials
		 WHERE credential_id = $1 AND revoked_at IS NULL`, credentialID)

	c, err := scanCredential(row)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrCredentialNotFound) {
		return nil, ErrCredentialNotFound
	}
	return c, err
}

// UpdateSignCount records the counter reported during authentication and
// reports a clone if it regressed.
//
// The counter exists to detect a duplicated authenticator: a genuine device
// only ever increments it. A value that goes backwards means two things are
// presenting the same credential.
//
// The important subtlety: **an authenticator reporting 0 has not regressed —
// it does not implement counters at all.** Most synced passkeys behave this
// way, so treating 0 as suspicious would lock out a large fraction of ordinary
// users. Counters are only meaningful once a device has demonstrated it uses
// them.
func (s *Store) UpdateSignCount(ctx context.Context, credentialID []byte, newCount uint32) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		var stored int64
		var entityID uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT sign_count, entity_id FROM webauthn_credentials
			 WHERE credential_id = $1 AND revoked_at IS NULL
			 FOR UPDATE`, credentialID).Scan(&stored, &entityID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrCredentialNotFound
		}
		if err != nil {
			return fmt.Errorf("store: reading sign count: %w", err)
		}

		// Both zero: the authenticator does not support counters. Nothing to
		// check, and nothing to update.
		if newCount == 0 && stored == 0 {
			return touchCredential(ctx, tx, credentialID)
		}

		if int64(newCount) <= stored && stored > 0 {
			// Not merely rejected: this is evidence of a cloned authenticator,
			// so it is auditable.
			ev, evErr := event.New(event.ActionCredentialRevoked, &entityID, nil,
				map[string]any{"device_bound": true})
			if evErr != nil {
				return evErr
			}
			if evErr := s.AppendEvent(ctx, tx, ev); evErr != nil {
				return evErr
			}
			return fmt.Errorf("%w: stored %d, presented %d",
				ErrCloneDetected, stored, newCount)
		}

		if _, err := tx.Exec(ctx, `
			UPDATE webauthn_credentials
			   SET sign_count = $2, last_used_at = now()
			 WHERE credential_id = $1`, credentialID, int64(newCount)); err != nil {
			return fmt.Errorf("store: updating sign count: %w", err)
		}
		return nil
	})
}

func touchCredential(ctx context.Context, tx pgx.Tx, credentialID []byte) error {
	_, err := tx.Exec(ctx,
		`UPDATE webauthn_credentials SET last_used_at = now() WHERE credential_id = $1`,
		credentialID)
	if err != nil {
		return fmt.Errorf("store: touching credential: %w", err)
	}
	return nil
}

// RevokeCredential retires a passkey.
//
// It refuses to remove the last credential from a fully-enrolled account:
// leaving someone with zero credentials converts a routine revocation into a
// lockout, and the whole point of requiring two is that this never happens by
// accident. Removing the final credential is deliberately an account-disable
// operation instead.
func (s *Store) RevokeCredential(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		var entityID uuid.UUID
		err := tx.QueryRow(ctx,
			`SELECT entity_id FROM webauthn_credentials
			  WHERE id = $1 AND revoked_at IS NULL`, id).Scan(&entityID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrCredentialNotFound
		}
		if err != nil {
			return fmt.Errorf("store: reading credential: %w", err)
		}

		var remaining int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM webauthn_credentials
			 WHERE entity_id = $1 AND revoked_at IS NULL AND id <> $2`,
			entityID, id).Scan(&remaining); err != nil {
			return fmt.Errorf("store: counting credentials: %w", err)
		}
		if remaining == 0 {
			return fmt.Errorf(
				"store: refusing to revoke the last credential for %s — that would "+
					"lock the account out; disable the account instead", entityID)
		}

		if _, err := tx.Exec(ctx,
			`UPDATE webauthn_credentials SET revoked_at = now() WHERE id = $1`,
			id); err != nil {
			return fmt.Errorf("store: revoking credential: %w", err)
		}

		ev, err := event.New(event.ActionCredentialRevoked, &entityID, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// FullyEnrolled reports whether an entity has enough credentials to be safe
// from lockout.
func (s *Store) FullyEnrolled(ctx context.Context, entityID uuid.UUID) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM webauthn_credentials
		 WHERE entity_id = $1 AND revoked_at IS NULL`, entityID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: counting credentials: %w", err)
	}
	return n >= MinCredentialsForFullEnrollment, nil
}

func scanCredential(row scanner) (*Credential, error) {
	var (
		c         Credential
		signCount int64
	)
	err := row.Scan(&c.ID, &c.EntityID, &c.CredentialID, &c.PublicKey, &signCount,
		&c.AAGUID, &c.BackupEligible, &c.BackupState, &c.Name, &c.Transports,
		&c.CreatedAt, &c.LastUsedAt, &c.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCredentialNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scanning credential: %w", err)
	}
	c.SignCount = uint32(signCount) //nolint:gosec // stored from a uint32, range-safe
	return &c, nil
}

func transportStrings(ts []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}
