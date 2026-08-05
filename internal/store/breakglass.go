package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/breakglass"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrChallengeConsumed means a challenge was replayed. A valid signature
	// does not rescue it: single use is the point.
	ErrChallengeConsumed = errors.New("store: break-glass challenge already used")

	ErrChallengeUnknown = errors.New("store: break-glass challenge not found")
)

// IssueBreakGlassChallenge creates a challenge for the operator to sign offline.
//
// Challenges are persisted rather than held in memory so that any node can
// verify one any other node issued, and so that single use is enforced by a
// database constraint rather than by hoping the same node handles the reply.
func (s *Store) IssueBreakGlassChallenge(ctx context.Context, from netip.Addr) (*breakglass.Challenge, error) {
	c, err := breakglass.NewChallenge()
	if err != nil {
		return nil, err
	}

	var ip *netip.Addr
	if from.IsValid() {
		ip = &from
	}

	if _, err := s.pool.Exec(ctx, `
		INSERT INTO break_glass_challenges (nonce, issued_at, expires_at, issued_to_ip)
		VALUES ($1, $2, $3, $4)`,
		c.Nonce, c.IssuedAt, c.ExpiresAt, ip,
	); err != nil {
		return nil, fmt.Errorf("store: issuing break-glass challenge: %w", err)
	}
	return c, nil
}

// RedeemBreakGlassChallenge verifies a signature and, on success, consumes the
// challenge and opens a short-lived emergency session.
//
// Ordering matters. The challenge is consumed by a conditional UPDATE *before*
// the signature is checked, so that two concurrent redemptions of the same
// challenge cannot both proceed — the loser sees zero rows affected. Verifying
// first and consuming second would leave a window where a replayed challenge
// with a captured signature could be used twice.
//
// A failed signature therefore burns the challenge. That is deliberate: an
// attacker guessing at signatures gets one attempt per challenge, and every
// attempt is recorded.
func (s *Store) RedeemBreakGlassChallenge(
	ctx context.Context,
	nonce []byte,
	signature string,
	pubKeyConfig string,
	subjectID uuid.UUID,
) (*Session, error) {
	pub, err := breakglass.DecodePublic(pubKeyConfig)
	if err != nil {
		return nil, err
	}

	// Step 1: consume the challenge, on its own connection so it AUTOCOMMITS.
	//
	// This deliberately does not run inside the session-creating transaction.
	// If it did, a failed signature would roll the consumption back along with
	// everything else, handing an attacker unlimited attempts against a single
	// challenge. The consumption must outlive the failure.
	//
	// `consumed_at IS NULL` in the WHERE clause is also what makes concurrent
	// redemption safe: only one caller can win the UPDATE.
	var issuedAt, expiresAt time.Time
	err = s.pool.QueryRow(ctx, `
		UPDATE break_glass_challenges
		   SET consumed_at = now()
		 WHERE nonce = $1 AND consumed_at IS NULL
		 RETURNING issued_at, expires_at`,
		nonce,
	).Scan(&issuedAt, &expiresAt)

	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if e := s.pool.QueryRow(ctx,
			`SELECT true FROM break_glass_challenges WHERE nonce = $1`,
			nonce).Scan(&exists); e == nil {
			return nil, ErrChallengeConsumed
		}
		return nil, ErrChallengeUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("store: consuming break-glass challenge: %w", err)
	}

	// Step 2: verify. The challenge is already spent, so a wrong signature
	// costs the attacker the whole challenge — one attempt each, every one
	// recorded.
	challenge := &breakglass.Challenge{
		Nonce:     nonce,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}
	if err := challenge.Verify(pub, signature); err != nil {
		return nil, err
	}

	// Step 3: mint the session and record the use, atomically together.
	var session *Session
	err = s.InTx(ctx, func(tx pgx.Tx) error {
		var err error
		session, err = createSessionTx(ctx, tx, subjectID, sessionSpec{
			AuthMethod:  "break_glass",
			TTL:         breakglass.SessionTTL,
			DeviceBound: false,
		})
		if err != nil {
			return err
		}

		// Break-glass that nobody notices is just a backdoor. This event exists
		// to be alerted on, and that alerting is an operational obligation
		// recorded in ADR 0009.
		ev, err := newBreakGlassEvent(subjectID, session.ID)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}
	return session, nil
}

// PurgeExpiredChallenges removes challenges that were never redeemed.
//
// Consumed ones are kept: an unredeemed challenge is noise, but a consumed one
// is evidence that someone attempted emergency access.
func (s *Store) PurgeExpiredChallenges(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM break_glass_challenges
		 WHERE consumed_at IS NULL AND expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("store: purging challenges: %w", err)
	}
	return tag.RowsAffected(), nil
}
