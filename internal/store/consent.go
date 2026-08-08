package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/event"
)

var ErrConsentNotFound = errors.New("store: no consent record")

// Consent is a user's standing agreement to release claims to an application.
type Consent struct {
	ID        uuid.UUID
	SubjectID uuid.UUID
	ClientID  string

	// ApplicationName is the directory name of the application, joined in for
	// display — a consent list showing opaque client IDs would be useless to
	// the person deciding whether to revoke one.
	ApplicationName string

	Scopes    []string
	GrantedAt time.Time
	RevokedAt *time.Time
}

func (c *Consent) Active() bool { return c.RevokedAt == nil }

// ConsentCovers reports whether standing consent already covers a request.
//
// Every requested scope must have been agreed to. A request for something
// wider does not match, so the user is asked again — which is the moment their
// answer might genuinely differ, and the only moment a prompt carries
// information.
func (s *Store) ConsentCovers(ctx context.Context, subjectID uuid.UUID, clientID string, scopes []string) (bool, error) {
	var granted []string
	err := s.pool.QueryRow(ctx, `
		SELECT scopes FROM oidc_consents
		 WHERE subject_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
		subjectID, clientID).Scan(&granted)

	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: reading consent: %w", err)
	}

	for _, scope := range scopes {
		if !slices.Contains(granted, scope) {
			return false, nil
		}
	}
	return true, nil
}

// RecordConsent stores or widens a user's agreement.
//
// Scopes are merged into a live agreement, so agreeing to something new does
// not silently withdraw an earlier one the application still relies on. They
// are *replaced* when the previous agreement was withdrawn: merging there would
// resurrect scopes the user explicitly took back and never saw the second time,
// which would make withdrawal a pause rather than a decision.
func (s *Store) RecordConsent(ctx context.Context, subjectID uuid.UUID, clientID string, scopes []string) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oidc_consents (subject_id, client_id, scopes)
			VALUES ($1, $2, $3)
			ON CONFLICT (subject_id, client_id) DO UPDATE
			   SET scopes = CASE
			         WHEN oidc_consents.revoked_at IS NOT NULL THEN EXCLUDED.scopes
			         ELSE (
			           SELECT array_agg(DISTINCT s)
			             FROM unnest(oidc_consents.scopes || EXCLUDED.scopes) AS s
			         )
			       END,
			       granted_at = now(),
			       revoked_at = NULL`,
			subjectID, clientID, orEmpty(scopes)); err != nil {
			return fmt.Errorf("store: recording consent: %w", err)
		}

		// No client id or scope list in the payload: both are safe, but the
		// entity reference is enough to reconstruct this from the consents
		// table, and the journal is append-only (ADR 0010).
		ev, err := event.New(event.ActionConsentGranted, &subjectID, &subjectID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// RevokeConsent withdraws agreement and kills the tokens it produced.
//
// Withdrawing consent while leaving live access tokens behind would make the
// action meaningless for up to their lifetime — the application would keep
// working, which is precisely what the user just asked it not to do.
func (s *Store) RevokeConsent(ctx context.Context, subjectID uuid.UUID, clientID string) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE oidc_consents SET revoked_at = now()
			 WHERE subject_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
			subjectID, clientID)
		if err != nil {
			return fmt.Errorf("store: revoking consent: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrConsentNotFound
		}

		if _, err := tx.Exec(ctx, `
			UPDATE oidc_tokens SET revoked_at = now()
			 WHERE subject_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
			subjectID, clientID); err != nil {
			return fmt.Errorf("store: revoking tokens for withdrawn consent: %w", err)
		}

		ev, err := event.New(event.ActionConsentRevoked, &subjectID, &subjectID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// ConsentsFor lists a subject's standing agreements, newest first.
//
// This is what makes consent more than a prompt: without somewhere to see and
// withdraw what you agreed to, "consent" is a click you cannot take back.
func (s *Store) ConsentsFor(ctx context.Context, subjectID uuid.UUID) ([]*Consent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.subject_id, c.client_id, coalesce(e.name, c.client_id),
		       c.scopes, c.granted_at, c.revoked_at
		  FROM oidc_consents c
		  LEFT JOIN oidc_clients oc ON oc.client_id = c.client_id
		  LEFT JOIN entities e ON e.id = oc.entity_id
		 WHERE c.subject_id = $1 AND c.revoked_at IS NULL
		 ORDER BY c.granted_at DESC`, subjectID)
	if err != nil {
		return nil, fmt.Errorf("store: listing consents: %w", err)
	}
	defer rows.Close()

	var out []*Consent
	for rows.Next() {
		var c Consent
		if err := rows.Scan(&c.ID, &c.SubjectID, &c.ClientID, &c.ApplicationName,
			&c.Scopes, &c.GrantedAt, &c.RevokedAt); err != nil {
			return nil, fmt.Errorf("store: scanning consent: %w", err)
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// MarkConsentGiven records that the user was actually asked for this request.
//
// Distinct from the standing consent record: it makes an authorization that ran
// without a prompt distinguishable from one where the user agreed, which is the
// difference between "they consented" and "we never asked".
func (s *Store) MarkConsentGiven(ctx context.Context, requestID uuid.UUID) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE oidc_auth_requests SET consent_given_at = now() WHERE id = $1`,
		requestID); err != nil {
		return fmt.Errorf("store: marking consent: %w", err)
	}
	return nil
}
