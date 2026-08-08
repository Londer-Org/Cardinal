package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/directory/event"
)

// TokenPrefix marks a Cardinal access token wherever it turns up.
//
// Deliberately recognisable. A credential that looks like random base64 is one
// nobody spots in a pasted log, a committed .env or a support ticket — whereas
// a fixed prefix can be grepped for, matched by a secret scanner, and
// recognised by whoever is about to paste it somewhere it should not go.
const TokenPrefix = "crd_pat_"

// accessTokenBytes is the entropy after the prefix. The same 32 bytes a session
// token gets: this is a bearer credential and there is no reason to be thrifty.
const accessTokenBytes = 32

var (
	// ErrTokenInvalid covers absent, malformed, expired and revoked alike.
	// Deliberately one error: telling a caller which of those it was would let
	// anyone holding a wrong token learn whether a right one exists.
	ErrTokenInvalid = errors.New("store: access token is invalid or expired")

	// ErrNoSuchToken is for management by id, where the caller is the owner and
	// already knows the token exists.
	ErrNoSuchToken = errors.New("store: no such access token")
)

// AccessToken is a bearer credential for a script.
type AccessToken struct {
	ID        uuid.UUID
	SubjectID uuid.UUID
	Name      string

	// Token is populated only at creation, and only then. Everything after
	// stores and compares the hash.
	Token string

	// Prefix identifies a token in a list without being able to authenticate
	// one. It is the leading characters, kept in clear on purpose.
	Prefix string

	ValidFrom  time.Time
	ValidUntil time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// Expired reports whether the token's window has closed.
func (t *AccessToken) Expired() bool { return !t.ValidUntil.After(time.Now()) }

// CreateAccessToken issues a token for a subject.
//
// The plaintext is returned once, in the result, and never again — the same
// contract as a client secret or a recovery code. Storing something we could
// hand back later would make the database a place credentials can be read from,
// which is the property the hash exists to remove.
func (s *Store) CreateAccessToken(
	ctx context.Context, subjectID uuid.UUID, name string, ttl time.Duration, actorID *uuid.UUID,
) (*AccessToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("store: an access token needs a name")
	}
	if ttl <= 0 {
		return nil, errors.New("store: an access token needs a positive lifetime")
	}

	raw := make([]byte, accessTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("store: generating access token: %w", err)
	}
	secret := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))

	// Enough to tell two tokens apart in a list, and far too little to guess
	// the rest of one.
	prefix := secret[:len(TokenPrefix)+6]

	token := &AccessToken{
		SubjectID: subjectID,
		Name:      name,
		Token:     secret,
		Prefix:    prefix,
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // a rollback after a successful commit returns ErrTxClosed

	err = tx.QueryRow(ctx, `
		INSERT INTO access_tokens (subject_id, name, token_hash, prefix, valid_period, created_by)
		VALUES ($1, $2, $3, $4, tstzrange(now(), now() + $5::interval), $6)
		RETURNING id, lower(valid_period), upper(valid_period), created_at`,
		subjectID, name, sum[:], prefix, ttl, actorID,
	).Scan(&token.ID, &token.ValidFrom, &token.ValidUntil, &token.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: creating access token: %w", err)
	}

	// In the same transaction as the row, so the journal cannot disagree with
	// the directory about which credentials exist.
	// Deliberately not the token's name. The owner wrote it, so it is free text
	// that will eventually say something about a person — and the journal is
	// the one place erasure cannot reach (ADR 0010). The name lives on the row,
	// which redaction can.
	ev, err := event.New(event.ActionAccessTokenIssued, &subjectID, actorID,
		map[string]any{"token_id": token.ID, "until": token.ValidUntil})
	if err != nil {
		return nil, err
	}
	if err := s.AppendEvent(ctx, tx, ev); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("store: committing access token: %w", err)
	}
	return token, nil
}

// LookupAccessToken authenticates a presented token and records its use.
//
// Validity is checked in SQL on every request, exactly as it is for sessions:
// revocation has to take effect at read time rather than by anything expiring
// from a cache (ADR 0004).
//
// last_used_at is throttled to once a minute. Writing it on every request is
// the standard way to make a token table the busiest table in the database, and
// the value is only ever read by a human wondering whether a token is still in
// use.
func (s *Store) LookupAccessToken(ctx context.Context, presented string) (*AccessToken, error) {
	if !strings.HasPrefix(presented, TokenPrefix) {
		// Not ours. Refused without a query, so an endpoint sprayed with
		// bearer tokens from some other system costs nothing.
		return nil, ErrTokenInvalid
	}
	sum := sha256.Sum256([]byte(presented))

	var t AccessToken
	err := s.pool.QueryRow(ctx, `
		UPDATE access_tokens
		   SET last_used_at = now()
		 WHERE token_hash = $1
		   AND valid_period @> now()
		   AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')
		RETURNING id, subject_id, name, prefix,
		          lower(valid_period), upper(valid_period), created_at, last_used_at`,
		sum[:],
	).Scan(&t.ID, &t.SubjectID, &t.Name, &t.Prefix,
		&t.ValidFrom, &t.ValidUntil, &t.CreatedAt, &t.LastUsedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		// Either invalid, or valid but used within the last minute so the
		// throttle skipped the update. Read it plainly to tell them apart.
		err = s.pool.QueryRow(ctx, `
			SELECT id, subject_id, name, prefix,
			       lower(valid_period), upper(valid_period), created_at, last_used_at
			  FROM access_tokens
			 WHERE token_hash = $1 AND valid_period @> now()`,
			sum[:],
		).Scan(&t.ID, &t.SubjectID, &t.Name, &t.Prefix,
			&t.ValidFrom, &t.ValidUntil, &t.CreatedAt, &t.LastUsedAt)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("store: looking up access token: %w", err)
	}
	return &t, nil
}

// ListAccessTokens returns a subject's tokens, live ones first.
func (s *Store) ListAccessTokens(ctx context.Context, subjectID uuid.UUID) ([]AccessToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, subject_id, name, prefix,
		       lower(valid_period), upper(valid_period), created_at, last_used_at
		  FROM access_tokens
		 WHERE subject_id = $1
		 ORDER BY (valid_period @> now()) DESC, created_at DESC`, subjectID)
	if err != nil {
		return nil, fmt.Errorf("store: listing access tokens: %w", err)
	}
	defer rows.Close()

	var out []AccessToken
	for rows.Next() {
		var t AccessToken
		if err := rows.Scan(&t.ID, &t.SubjectID, &t.Name, &t.Prefix,
			&t.ValidFrom, &t.ValidUntil, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, fmt.Errorf("store: scanning access token: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAccessToken ends a token now, keeping the row.
//
// Closing the range rather than deleting: the token existed, it was used, and
// an audit that cannot see a revoked credential cannot answer what it did while
// it was live.
//
// Ownership is part of the WHERE clause rather than a separate read, so there
// is no window between checking and acting.
func (s *Store) RevokeAccessToken(
	ctx context.Context, tokenID, subjectID uuid.UUID, actorID *uuid.UUID,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // a rollback after a successful commit returns ErrTxClosed

	tag, err := tx.Exec(ctx, `
		UPDATE access_tokens
		   SET valid_period = tstzrange(lower(valid_period), now())
		 WHERE id = $1 AND subject_id = $2 AND valid_period @> now()`,
		tokenID, subjectID)
	if err != nil {
		return fmt.Errorf("store: revoking access token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchToken
	}

	ev, err := event.New(event.ActionAccessTokenRevoked, &subjectID, actorID,
		map[string]any{"token_id": tokenID})
	if err != nil {
		return err
	}
	if err := s.AppendEvent(ctx, tx, ev); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: committing revocation: %w", err)
	}
	return nil
}

// RevokeAllAccessTokens ends every live token for a subject.
//
// Used when an account is disabled or redacted: a token outliving the account
// it belongs to is exactly the failure that makes people distrust bearer
// credentials.
func (s *Store) RevokeAllAccessTokens(ctx context.Context, subjectID uuid.UUID) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE access_tokens
		   SET valid_period = tstzrange(lower(valid_period), now())
		 WHERE subject_id = $1 AND valid_period @> now()`, subjectID)
	if err != nil {
		return 0, fmt.Errorf("store: revoking access tokens: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
