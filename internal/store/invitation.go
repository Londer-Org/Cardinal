package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/directory/event"
)

var (
	// ErrInvitationNotFound covers expired, revoked, already-redeemed and never
	// existed. Deliberately one error: telling the holder of a bad token which
	// of those it is tells an attacker whether they guessed a real account.
	ErrInvitationNotFound = errors.New("store: no usable invitation")

	// ErrAlreadyEnrolled reports that the account already has a credential, so an
	// enrollment invitation for it would be a second way in rather than a first.
	ErrAlreadyEnrolled = errors.New("store: account already has credentials")
)

// InvitationTTL is how long an invitation may sit unused.
//
// A day, because an invitation is sent to a person who may be asleep, on
// another continent, or not at their desk — and an onboarding link that expires
// before its recipient reads the message produces a support request rather than
// security. It is short enough that a link left in a chat log stops working
// long before anyone goes looking through the backlog.
const InvitationTTL = 24 * time.Hour

// Invitation authorises registering a first passkey on one account.
type Invitation struct {
	ID        uuid.UUID
	SubjectID uuid.UUID

	// Login and DisplayName are joined in so the enrollment screen can say who
	// the invitation is for. It has to: someone opening a link from a chat
	// message needs to see whose account they are about to take possession of.
	Login       string
	DisplayName string

	IssuedBy   *uuid.UUID
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RedeemedAt *time.Time
	RevokedAt  *time.Time
}

// Live reports whether this invitation can still be redeemed.
func (i *Invitation) Live() bool {
	return i.RedeemedAt == nil && i.RevokedAt == nil && time.Now().Before(i.ExpiresAt)
}

// IssuedInvitation is returned once, at issue.
type IssuedInvitation struct {
	Invitation *Invitation

	// Token is shown once and never recoverable — only its hash is stored, for
	// the same reason a session token is hashed: a database read must not yield
	// a working credential.
	Token string
}

func hashInvitationToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// IssueInvitation creates a single-use enrollment link for an account.
//
// Any existing live invitation for the same account is revoked first. Two
// working links would make revocation ambiguous, which is the worst property to
// discover while revoking one in a hurry.
func (s *Store) IssueInvitation(ctx context.Context, subjectID uuid.UUID, issuedBy *uuid.UUID, ttl time.Duration) (*IssuedInvitation, error) {
	if ttl <= 0 {
		ttl = InvitationTTL
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("store: generating invitation token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	var inv Invitation
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE enrollment_invitations SET revoked_at = now()
			 WHERE subject_id = $1 AND redeemed_at IS NULL AND revoked_at IS NULL`,
			subjectID); err != nil {
			return fmt.Errorf("store: superseding invitation: %w", err)
		}

		now := time.Now().UTC()
		row := tx.QueryRow(ctx, `
			INSERT INTO enrollment_invitations
				(subject_id, token_hash, issued_by, issued_at, expires_at)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, subject_id, issued_by, issued_at, expires_at`,
			subjectID, hashInvitationToken(token), issuedBy, now, now.Add(ttl))

		if err := row.Scan(&inv.ID, &inv.SubjectID, &inv.IssuedBy,
			&inv.IssuedAt, &inv.ExpiresAt); err != nil {
			return fmt.Errorf("store: issuing invitation: %w", err)
		}

		ev, err := event.New(event.ActionInvitationIssued, &subjectID, issuedBy, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}

	return &IssuedInvitation{Invitation: &inv, Token: token}, nil
}

// InvitationByToken resolves a token to a live invitation.
//
// Expiry, revocation and prior redemption are all checked in SQL, so a race
// between two redemptions of the same token cannot both pass this.
func (s *Store) InvitationByToken(ctx context.Context, token string) (*Invitation, error) {
	var inv Invitation
	err := s.pool.QueryRow(ctx, `
		SELECT i.id, i.subject_id, e.name, coalesce(e.display_name, ''),
		       i.issued_by, i.issued_at, i.expires_at
		  FROM enrollment_invitations i
		  JOIN entities e ON e.id = i.subject_id
		 WHERE i.token_hash = $1
		   AND i.redeemed_at IS NULL
		   AND i.revoked_at IS NULL
		   AND i.expires_at > now()
		   AND e.disabled_at IS NULL`,
		hashInvitationToken(token),
	).Scan(&inv.ID, &inv.SubjectID, &inv.Login, &inv.DisplayName,
		&inv.IssuedBy, &inv.IssuedAt, &inv.ExpiresAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvitationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading invitation: %w", err)
	}
	return &inv, nil
}

// RedeemInvitation marks an invitation spent, exactly once.
//
// Consume-and-return in one statement, for the same reason authorization codes
// are: a check-then-mark would leave a window in which two requests holding the
// same link both proceed, and both would enrol a credential on the account.
func (s *Store) RedeemInvitation(ctx context.Context, token string, from netip.Addr) (*Invitation, error) {
	var ip *netip.Addr
	if from.IsValid() {
		ip = &from
	}

	var inv Invitation
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE enrollment_invitations i
			   SET redeemed_at = now(), redeemed_ip = $2
			  FROM entities e
			 WHERE e.id = i.subject_id
			   AND i.token_hash = $1
			   AND i.redeemed_at IS NULL
			   AND i.revoked_at IS NULL
			   AND i.expires_at > now()
			   AND e.disabled_at IS NULL
			RETURNING i.id, i.subject_id, e.name, coalesce(e.display_name, ''),
			          i.issued_by, i.issued_at, i.expires_at, i.redeemed_at`,
			hashInvitationToken(token), ip)

		if err := row.Scan(&inv.ID, &inv.SubjectID, &inv.Login, &inv.DisplayName,
			&inv.IssuedBy, &inv.IssuedAt, &inv.ExpiresAt, &inv.RedeemedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvitationNotFound
			}
			return fmt.Errorf("store: redeeming invitation: %w", err)
		}

		// The actor is the subject: nobody else was present. The invitation
		// proves authorisation, and who issued it is already on the issue event.
		ev, err := event.New(event.ActionInvitationRedeemed, &inv.SubjectID, &inv.SubjectID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

// RevokeInvitation withdraws an unused invitation.
func (s *Store) RevokeInvitation(ctx context.Context, subjectID uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE enrollment_invitations SET revoked_at = now()
			 WHERE subject_id = $1 AND redeemed_at IS NULL AND revoked_at IS NULL`,
			subjectID)
		if err != nil {
			return fmt.Errorf("store: revoking invitation: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrInvitationNotFound
		}

		ev, err := event.New(event.ActionInvitationRevoked, &subjectID, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// PendingInvitations lists accounts waiting to be enrolled.
//
// The reason this is worth showing: an account with an outstanding invitation
// is one nobody can sign in to yet, and an invitation that quietly expired
// leaves a person locked out with no signal to anyone.
func (s *Store) PendingInvitations(ctx context.Context) ([]*Invitation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.subject_id, e.name, coalesce(e.display_name, ''),
		       i.issued_by, i.issued_at, i.expires_at
		  FROM enrollment_invitations i
		  JOIN entities e ON e.id = i.subject_id
		 WHERE i.redeemed_at IS NULL AND i.revoked_at IS NULL
		   AND e.disabled_at IS NULL
		 ORDER BY i.expires_at`)
	if err != nil {
		return nil, fmt.Errorf("store: listing invitations: %w", err)
	}
	defer rows.Close()

	var out []*Invitation
	for rows.Next() {
		var inv Invitation
		if err := rows.Scan(&inv.ID, &inv.SubjectID, &inv.Login, &inv.DisplayName,
			&inv.IssuedBy, &inv.IssuedAt, &inv.ExpiresAt); err != nil {
			return nil, fmt.Errorf("store: scanning invitation: %w", err)
		}
		out = append(out, &inv)
	}
	return out, rows.Err()
}

// HasCredentials reports whether an account can already sign in.
//
// Used to distinguish onboarding from recovery. Issuing an invitation for an
// account that already has passkeys is a legitimate administrative act — it is
// how someone who lost every device gets back in — but it is also the shape of
// an account takeover, so the caller logs it differently rather than treating
// the two as the same event.
func (s *Store) HasCredentials(ctx context.Context, subjectID uuid.UUID) (bool, error) {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM webauthn_credentials
		  WHERE entity_id = $1 AND revoked_at IS NULL`, subjectID).Scan(&n); err != nil {
		return false, fmt.Errorf("store: counting credentials: %w", err)
	}
	return n > 0, nil
}

// PendingInvitationFor returns the outstanding invitation for an account.
//
// Distinct from InvitationByToken, which answers "is this link usable" for
// whoever holds one. This answers "is someone expected to arrive", which is the
// question an administrator looking at an account is asking.
func (s *Store) PendingInvitationFor(ctx context.Context, subjectID uuid.UUID) (*Invitation, error) {
	var inv Invitation
	err := s.pool.QueryRow(ctx, `
		SELECT i.id, i.subject_id, e.name, coalesce(e.display_name, ''),
		       i.issued_by, i.issued_at, i.expires_at
		  FROM enrollment_invitations i
		  JOIN entities e ON e.id = i.subject_id
		 WHERE i.subject_id = $1
		   AND i.redeemed_at IS NULL AND i.revoked_at IS NULL
		   AND i.expires_at > now()`,
		subjectID,
	).Scan(&inv.ID, &inv.SubjectID, &inv.Login, &inv.DisplayName,
		&inv.IssuedBy, &inv.IssuedAt, &inv.ExpiresAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvitationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading invitation: %w", err)
	}
	return &inv, nil
}
