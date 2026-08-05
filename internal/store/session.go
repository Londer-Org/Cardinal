package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/event"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// sessionTokenBytes is 32 bytes of entropy. Session tokens are bearer
// credentials, so this is the one place where being generous costs nothing.
const sessionTokenBytes = 32

var (
	ErrSessionInvalid = errors.New("store: session is invalid or expired")
	ErrNoSuchSession  = errors.New("store: no such session")
)

// Session is an authenticated session.
type Session struct {
	ID        uuid.UUID
	SubjectID uuid.UUID

	// Token is the bearer credential, populated only at creation. It is never
	// read back from the database, because only its hash is stored.
	Token string

	ValidFrom  time.Time
	ValidUntil time.Time

	// AuthMethod and AuthAt feed Cedar policy. Administrative actions can then
	// require a device-bound passkey authenticated within the last few minutes,
	// rather than merely a valid session that began fresh eight hours ago.
	AuthMethod  string
	AuthAt      time.Time
	DeviceBound bool

	CredentialID *uuid.UUID
}

// Emergency reports whether this session came from break-glass. Such sessions
// bypass normal authentication and must be treated as an incident in progress.
func (s *Session) Emergency() bool { return s.AuthMethod == "break_glass" }

// Expired reports whether the session has passed its validity window.
//
// Callers must check this at read time and not rely on cache invalidation:
// NOTIFY is a hint, never a guarantee (ADR 0004), so a dropped notification
// must be a latency problem rather than an authorization bypass.
func (s *Session) Expired() bool { return time.Now().After(s.ValidUntil) }

type sessionSpec struct {
	AuthMethod   string
	TTL          time.Duration
	DeviceBound  bool
	CredentialID *uuid.UUID
}

// createSessionTx mints a session inside an existing transaction.
//
// The raw token is returned to the caller and never stored: the database holds
// only its SHA-256 hash, so reading the sessions table yields nothing that can
// authenticate. Hashing is plain SHA-256 rather than Argon2id deliberately —
// unlike a password, the token has 256 bits of entropy and is not guessable, so
// a slow KDF would only add latency to every request.
func createSessionTx(ctx context.Context, tx pgx.Tx, subjectID uuid.UUID, spec sessionSpec) (*Session, error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("store: generating session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))

	now := time.Now().UTC().Truncate(time.Microsecond)
	s := &Session{
		SubjectID:    subjectID,
		Token:        token,
		ValidFrom:    now,
		ValidUntil:   now.Add(spec.TTL),
		AuthMethod:   spec.AuthMethod,
		AuthAt:       now,
		DeviceBound:  spec.DeviceBound,
		CredentialID: spec.CredentialID,
	}

	err := tx.QueryRow(ctx, `
		INSERT INTO sessions (subject_id, token_hash, valid_period, auth_method,
		                      auth_at, device_bound, credential_id)
		VALUES ($1, $2, tstzrange($3::timestamptz, $4::timestamptz), $5, $6, $7, $8)
		RETURNING id`,
		subjectID, sum[:], s.ValidFrom, s.ValidUntil,
		s.AuthMethod, s.AuthAt, s.DeviceBound, s.CredentialID,
	).Scan(&s.ID)
	if err != nil {
		return nil, fmt.Errorf("store: creating session: %w", err)
	}
	return s, nil
}

// CreateSession mints a session and records it.
func (s *Store) CreateSession(ctx context.Context, subjectID uuid.UUID, spec sessionSpec) (*Session, error) {
	var out *Session
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = createSessionTx(ctx, tx, subjectID, spec)
		if err != nil {
			return err
		}
		ev, err := event.New(event.ActionSessionCreated, &subjectID, &subjectID,
			map[string]any{
				"session_id":   out.ID,
				"auth_method":  out.AuthMethod,
				"device_bound": out.DeviceBound,
			})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	return out, err
}

// LookupSession resolves a bearer token to a session.
//
// Validity is checked in SQL, at read time, on every request. That is the
// enforcement point for revocation: cache invalidation via NOTIFY is only ever
// an optimisation, and a session whose window has closed must fail here even if
// no notification was ever delivered.
func (s *Store) LookupSession(ctx context.Context, token string) (*Session, error) {
	sum := sha256.Sum256([]byte(token))

	var sess Session
	err := s.pool.QueryRow(ctx, `
		SELECT id, subject_id, lower(valid_period), upper(valid_period),
		       auth_method, auth_at, device_bound, credential_id
		  FROM sessions
		 WHERE token_hash = $1 AND valid_period @> now()`,
		sum[:],
	).Scan(&sess.ID, &sess.SubjectID, &sess.ValidFrom, &sess.ValidUntil,
		&sess.AuthMethod, &sess.AuthAt, &sess.DeviceBound, &sess.CredentialID)

	if errors.Is(err, pgx.ErrNoRows) {
		// Deliberately indistinguishable: whether the token was wrong, expired
		// or revoked is information an attacker should not receive.
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("store: looking up session: %w", err)
	}
	return &sess, nil
}

// RevokeSession ends a session immediately.
//
// The row's validity range is closed rather than deleted, keeping the record
// that the session existed and when it ended.
func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		var subjectID uuid.UUID
		err := tx.QueryRow(ctx, `
			UPDATE sessions
			   SET valid_period = tstzrange(lower(valid_period), now())
			 WHERE id = $1 AND upper(valid_period) > now()
			 RETURNING subject_id`, id).Scan(&subjectID)

		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchSession
		}
		if err != nil {
			return fmt.Errorf("store: revoking session: %w", err)
		}

		ev, err := event.New(event.ActionSessionRevoked, &subjectID, actorID,
			map[string]any{"session_id": id})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// RevokeAllSessions ends every active session for a subject, used when a
// credential is lost or an account is compromised.
func (s *Store) RevokeAllSessions(ctx context.Context, subjectID uuid.UUID, actorID *uuid.UUID) (int64, error) {
	var count int64
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE sessions
			   SET valid_period = tstzrange(lower(valid_period), now())
			 WHERE subject_id = $1 AND upper(valid_period) > now()`, subjectID)
		if err != nil {
			return fmt.Errorf("store: revoking sessions: %w", err)
		}
		count = tag.RowsAffected()
		if count == 0 {
			return nil
		}

		ev, err := event.New(event.ActionSessionRevoked, &subjectID, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	return count, err
}

// newBreakGlassEvent records emergency access. Separate from ordinary session
// creation so it is trivial to alert on.
func newBreakGlassEvent(subjectID, sessionID uuid.UUID) (*event.Event, error) {
	return event.New(event.ActionBreakGlassUsed, &subjectID, &subjectID,
		map[string]any{
			"session_id":  sessionID,
			"auth_method": "break_glass",
		})
}

// ConstantTimeCompare is used where a secret is compared outside the database.
// Kept here so call sites cannot accidentally reach for ==.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
