package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/directory/event"
)

var (
	// ErrRecoveryNotFound reports that there is no open recovery request.
	ErrRecoveryNotFound = errors.New("store: no open recovery request")
	// ErrAlreadyApproved reports that this administrator has already approved the
	// request. Dual control means two *different* people (ADR 0015).
	ErrAlreadyApproved = errors.New("store: you have already approved this")
	// ErrSelfRecovery reports an attempt to approve one's own recovery, which would
	// reduce dual control to one person (ADR 0015).
	ErrSelfRecovery = errors.New("store: you cannot recover your own account")
)

// RecoveryApprovals is how many distinct administrators a recovery needs.
//
// Two, counting the one who asked. Dual control means two people, not two
// button presses — the requester's own request is their approval, so the second
// must come from somebody else. Three would be safer and would also mean an
// organisation with two administrators cannot recover anything, which is how a
// control gets removed rather than followed.
const RecoveryApprovals = 2

// RecoveryTTL bounds how long a request waits for its second approval.
//
// Long enough for a colleague in another timezone to see it; short enough that
// a request nobody remembers cannot be approved months later by someone who no
// longer recalls why it was made.
const RecoveryTTL = 72 * time.Hour

// RecoveryRequest is an open ask to restore access to an account.
type RecoveryRequest struct {
	ID        uuid.UUID
	SubjectID uuid.UUID
	Subject   string

	RequestedBy   uuid.UUID
	RequestedByAs string
	RequestedAt   time.Time
	ExpiresAt     time.Time
	Reason        string

	// Approvers are the administrators who have signed off, the requester
	// included. Names rather than ids: the point of showing this is that a
	// second person can see who else has agreed.
	Approvers []string
}

// Satisfied reports whether enough distinct administrators have approved.
func (r *RecoveryRequest) Satisfied() bool { return len(r.Approvers) >= RecoveryApprovals }

// RequestRecovery opens a request and records the requester's own approval.
//
// The requester approving their own request is not a loophole: they are one of
// the two people, and making them press a second button would only teach them
// that the second press is a formality.
func (s *Store) RequestRecovery(ctx context.Context, subjectID, requestedBy uuid.UUID, reason string) (*RecoveryRequest, error) {
	if subjectID == requestedBy {
		return nil, ErrSelfRecovery
	}

	var req RecoveryRequest
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		row := tx.QueryRow(ctx, `
			INSERT INTO recovery_requests
				(subject_id, requested_by, requested_at, expires_at, reason)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id`,
			subjectID, requestedBy, now, now.Add(RecoveryTTL), reason)
		if err := row.Scan(&req.ID); err != nil {
			return fmt.Errorf("store: opening recovery request: %w", err)
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO recovery_approvals (request_id, approver_id)
			VALUES ($1, $2)`, req.ID, requestedBy); err != nil {
			return fmt.Errorf("store: recording the requester's approval: %w", err)
		}

		ev, err := event.New(event.ActionRecoveryRequested, &subjectID, &requestedBy, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}

	return s.RecoveryRequestFor(ctx, subjectID)
}

// ApproveRecovery records one administrator's approval.
//
// Returns the request as it stands afterwards, so the caller can see whether it
// is now satisfied without asking again.
func (s *Store) ApproveRecovery(ctx context.Context, subjectID, approverID uuid.UUID) (*RecoveryRequest, error) {
	if subjectID == approverID {
		// Belt and braces: the subject cannot normally authenticate, but a
		// recovery someone can approve for themselves is not dual control.
		return nil, ErrSelfRecovery
	}

	err := s.InTx(ctx, func(tx pgx.Tx) error {
		var requestID uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT id FROM recovery_requests
			 WHERE subject_id = $1
			   AND completed_at IS NULL AND cancelled_at IS NULL
			   AND expires_at > now()`, subjectID).Scan(&requestID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRecoveryNotFound
		}
		if err != nil {
			return fmt.Errorf("store: reading recovery request: %w", err)
		}

		tag, err := tx.Exec(ctx, `
			INSERT INTO recovery_approvals (request_id, approver_id)
			VALUES ($1, $2)
			ON CONFLICT (request_id, approver_id) DO NOTHING`, requestID, approverID)
		if err != nil {
			return fmt.Errorf("store: recording approval: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Silently accepting would let one administrator satisfy the
			// threshold by pressing twice, or at least believe they had.
			return ErrAlreadyApproved
		}

		ev, err := event.New(event.ActionRecoveryApproved, &subjectID, &approverID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}

	return s.RecoveryRequestFor(ctx, subjectID)
}

// CompleteRecovery marks a request spent once its invitation has been issued.
func (s *Store) CompleteRecovery(ctx context.Context, requestID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE recovery_requests SET completed_at = now()
		 WHERE id = $1 AND completed_at IS NULL AND cancelled_at IS NULL`, requestID)
	if err != nil {
		return fmt.Errorf("store: completing recovery: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRecoveryNotFound
	}
	return nil
}

// CancelRecovery withdraws an open request.
func (s *Store) CancelRecovery(ctx context.Context, subjectID uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE recovery_requests SET cancelled_at = now()
			 WHERE subject_id = $1 AND completed_at IS NULL AND cancelled_at IS NULL`,
			subjectID)
		if err != nil {
			return fmt.Errorf("store: cancelling recovery: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrRecoveryNotFound
		}

		ev, err := event.New(event.ActionRecoveryCancelled, &subjectID, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

const recoveryColumns = `
	r.id, r.subject_id, s.name, r.requested_by, coalesce(q.name, ''),
	r.requested_at, r.expires_at, r.reason,
	coalesce(
	  (SELECT array_agg(a.name ORDER BY a.name)
	     FROM recovery_approvals ra
	     JOIN entities a ON a.id = ra.approver_id
	    WHERE ra.request_id = r.id),
	  '{}')`

const recoveryJoins = `
	  FROM recovery_requests r
	  JOIN entities s ON s.id = r.subject_id
	  LEFT JOIN entities q ON q.id = r.requested_by`

func scanRecovery(row pgx.Row) (*RecoveryRequest, error) {
	var r RecoveryRequest
	if err := row.Scan(&r.ID, &r.SubjectID, &r.Subject, &r.RequestedBy,
		&r.RequestedByAs, &r.RequestedAt, &r.ExpiresAt, &r.Reason,
		&r.Approvers); err != nil {
		return nil, err
	}
	return &r, nil
}

// RecoveryRequestFor returns the open request for an account, if any.
func (s *Store) RecoveryRequestFor(ctx context.Context, subjectID uuid.UUID) (*RecoveryRequest, error) {
	r, err := scanRecovery(s.pool.QueryRow(ctx, `SELECT`+recoveryColumns+recoveryJoins+`
		 WHERE r.subject_id = $1
		   AND r.completed_at IS NULL AND r.cancelled_at IS NULL
		   AND r.expires_at > now()`, subjectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRecoveryNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading recovery request: %w", err)
	}
	return r, nil
}

// OpenRecoveries lists every request waiting for approval.
//
// Worth surfacing rather than leaving to whoever was told about it: a request
// nobody notices is one that expires, and the person it concerns is locked out
// in the meantime.
func (s *Store) OpenRecoveries(ctx context.Context) ([]*RecoveryRequest, error) {
	rows, err := s.pool.Query(ctx, `SELECT`+recoveryColumns+recoveryJoins+`
		 WHERE r.completed_at IS NULL AND r.cancelled_at IS NULL
		   AND r.expires_at > now()
		 ORDER BY r.requested_at`)
	if err != nil {
		return nil, fmt.Errorf("store: listing recovery requests: %w", err)
	}
	defer rows.Close()

	var out []*RecoveryRequest
	for rows.Next() {
		r, err := scanRecovery(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning recovery request: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
