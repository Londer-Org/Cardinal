package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuthRequestTTL bounds an in-flight authorization.
//
// Long enough to authenticate, find a security key, and consent. Short enough
// that an abandoned request is not lying around to be resumed by whoever next
// uses the browser.
const AuthRequestTTL = 15 * time.Minute

var (
	// ErrAuthRequestNotFound reports that the authorization request is unknown or
	// has expired.
	ErrAuthRequestNotFound = errors.New("store: authorization request not found or expired")
	// ErrAuthCodeReplayed reports that an authorization code was presented twice.
	// Codes are single-use, and a replay means the first use may not have been the
	// legitimate one.
	ErrAuthCodeReplayed = errors.New("store: authorization code already redeemed")
	// ErrTokenNotFound reports that no such token exists.
	ErrTokenNotFound = errors.New("store: token not found")
)

// AuthRequest is one in-flight authorization code flow.
type AuthRequest struct {
	ID        uuid.UUID
	ClientID  string
	SubjectID *uuid.UUID

	Scopes       []string
	ResponseType string
	RedirectURI  string
	State        string
	Nonce        string

	CodeChallenge       string
	CodeChallengeMethod string

	AuthTime time.Time
	AMR      []string

	// What the client asked for about authentication itself, rather than about
	// who is authenticating. Empty and nil mean "no constraint" — see
	// migration 0015.
	Prompt []string
	MaxAge *int64

	Done      bool
	ExpiresAt time.Time
}

// RequiresFreshAuthentication reports whether this request may be completed
// from an authentication performed at `authAt`.
//
// `prompt=login` is unconditional: the client asked for the ceremony, not for
// an opinion about whether one was needed. `max_age` is a bound on age, and a
// zero max_age means every completion needs a new authentication — which is
// what the specification says and what oidcc-max-age-1 checks.
func (a *AuthRequest) RequiresFreshAuthentication(authAt time.Time) bool {
	for _, p := range a.Prompt {
		if p == "login" {
			return true
		}
	}
	if a.MaxAge == nil {
		return false
	}
	return time.Since(authAt) > time.Duration(*a.MaxAge)*time.Second
}

// PromptedFor reports whether the client asked for a given prompt value.
func (a *AuthRequest) PromptedFor(value string) bool {
	for _, p := range a.Prompt {
		if p == value {
			return true
		}
	}
	return false
}

// CreateAuthRequest stores a new authorization request.
//
// Persisted rather than held in memory so any node can complete a flow another
// began, and so single-use of the code is a database guarantee (ADR 0004).
func (s *Store) CreateAuthRequest(ctx context.Context, r *AuthRequest) error {
	r.ExpiresAt = time.Now().Add(AuthRequestTTL)

	err := s.pool.QueryRow(ctx, `
		INSERT INTO oidc_auth_requests
			(client_id, subject_id, scopes, response_type, redirect_uri, state,
			 nonce, code_challenge, code_challenge_method, expires_at,
			 prompt, max_age)
		VALUES ($1, $2, $3, $4, $5, nullif($6,''), nullif($7,''),
		        nullif($8,''), nullif($9,''), $10, $11, $12)
		RETURNING id`,
		r.ClientID, r.SubjectID, orEmpty(r.Scopes), r.ResponseType, r.RedirectURI,
		r.State, r.Nonce, r.CodeChallenge, r.CodeChallengeMethod, r.ExpiresAt,
		orEmpty(r.Prompt), r.MaxAge,
	).Scan(&r.ID)
	if err != nil {
		return fmt.Errorf("store: creating authorization request: %w", err)
	}
	return nil
}

// AuthRequestByID loads a pending request.
func (s *Store) AuthRequestByID(ctx context.Context, id uuid.UUID) (*AuthRequest, error) {
	return s.scanAuthRequest(s.pool.QueryRow(ctx, `
		SELECT id, client_id, subject_id, scopes, response_type, redirect_uri,
		       coalesce(state,''), coalesce(nonce,''),
		       coalesce(code_challenge,''), coalesce(code_challenge_method,''),
		       coalesce(auth_time, 'epoch'::timestamptz), amr, done, expires_at,
		       coalesce(prompt, '{}'), max_age
		  FROM oidc_auth_requests
		 WHERE id = $1 AND expires_at > now() AND consumed_at IS NULL`, id))
}

// CompleteAuthRequest records that a user has authenticated and consented.
func (s *Store) CompleteAuthRequest(ctx context.Context, id, subjectID uuid.UUID, authTime time.Time, amr []string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oidc_auth_requests
		   SET subject_id = $2, auth_time = $3, amr = $4, done = true
		 WHERE id = $1 AND expires_at > now() AND consumed_at IS NULL`,
		id, subjectID, authTime, orEmpty(amr))
	if err != nil {
		return fmt.Errorf("store: completing authorization request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAuthRequestNotFound
	}
	return nil
}

// SaveAuthCode attaches an authorization code to a completed request.
//
// The code is hashed, for the same reason a session token is: reading the
// database must not yield something redeemable.
func (s *Store) SaveAuthCode(ctx context.Context, id uuid.UUID, code string) error {
	sum := sha256.Sum256([]byte(code))

	tag, err := s.pool.Exec(ctx, `
		UPDATE oidc_auth_requests
		   SET code_hash = $2
		 WHERE id = $1 AND done = true AND expires_at > now() AND consumed_at IS NULL`,
		id, sum[:])
	if err != nil {
		return fmt.Errorf("store: saving authorization code: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAuthRequestNotFound
	}
	return nil
}

// RedeemAuthCode exchanges a code for its request, exactly once.
//
// Consume-and-return in a single statement. An authorization code is a bearer
// credential that grants tokens, so a window between "looks valid" and "is
// spent" is a window in which a stolen code can be used twice — and OAuth's
// threat model assumes codes leak, via referrers, logs and shoulder surfing.
// `consumed_at IS NULL` in the WHERE clause is what closes it.
func (s *Store) RedeemAuthCode(ctx context.Context, code string) (*AuthRequest, error) {
	sum := sha256.Sum256([]byte(code))

	req, err := s.scanAuthRequest(s.pool.QueryRow(ctx, `
		UPDATE oidc_auth_requests
		   SET consumed_at = now()
		 WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > now()
		 RETURNING id, client_id, subject_id, scopes, response_type, redirect_uri,
		           coalesce(state,''), coalesce(nonce,''),
		           coalesce(code_challenge,''), coalesce(code_challenge_method,''),
		           coalesce(auth_time,'epoch'::timestamptz), amr, done, expires_at,
		           coalesce(prompt, '{}'), max_age`,
		sum[:]))

	if errors.Is(err, ErrAuthRequestNotFound) {
		// Distinguish replay from "never existed", but only in the log — the
		// client learns nothing either way.
		var used bool
		if e := s.pool.QueryRow(ctx,
			`SELECT consumed_at IS NOT NULL FROM oidc_auth_requests WHERE code_hash = $1`,
			sum[:]).Scan(&used); e == nil && used {
			return nil, ErrAuthCodeReplayed
		}
	}
	return req, err
}

// DeleteAuthRequest abandons a flow.
func (s *Store) DeleteAuthRequest(ctx context.Context, id uuid.UUID) error {
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM oidc_auth_requests WHERE id = $1`, id); err != nil {
		return fmt.Errorf("store: deleting authorization request: %w", err)
	}
	return nil
}

func (s *Store) scanAuthRequest(row pgx.Row) (*AuthRequest, error) {
	var r AuthRequest
	err := row.Scan(&r.ID, &r.ClientID, &r.SubjectID, &r.Scopes, &r.ResponseType,
		&r.RedirectURI, &r.State, &r.Nonce, &r.CodeChallenge,
		&r.CodeChallengeMethod, &r.AuthTime, &r.AMR, &r.Done, &r.ExpiresAt,
		&r.Prompt, &r.MaxAge)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAuthRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scanning authorization request: %w", err)
	}
	return &r, nil
}

// ── Tokens ─────────────────────────────────────────────────────────────────

// Token is an issued access or refresh token.
type Token struct {
	ID        uuid.UUID
	ClientID  string
	SubjectID uuid.UUID
	SessionID *uuid.UUID

	Scopes   []string
	Audience []string

	AuthTime  time.Time
	AMR       []string
	ExpiresAt time.Time
}

// CreateToken records an issued token.
//
// Access tokens are JWTs and are not stored: their signature is the check, and
// storing them would create a second place to leak them from without adding
// one. Only the refresh token's hash is kept, because refresh tokens must be
// revocable and long-lived.
func (s *Store) CreateToken(ctx context.Context, t *Token, refreshToken string) error {
	var refreshHash []byte
	if refreshToken != "" {
		sum := sha256.Sum256([]byte(refreshToken))
		refreshHash = sum[:]
	}

	// A nil Go slice becomes SQL NULL, not an empty array, which violates the
	// NOT NULL columns. Normalising here rather than making every caller
	// remember: "no audience" is a legitimate thing to mean.
	scopes, audience, amr := orEmpty(t.Scopes), orEmpty(t.Audience), orEmpty(t.AMR)

	err := s.pool.QueryRow(ctx, `
		INSERT INTO oidc_tokens
			(client_id, subject_id, session_id, scopes, audience,
			 refresh_hash, auth_time, amr, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`,
		t.ClientID, t.SubjectID, t.SessionID, scopes, audience,
		refreshHash, t.AuthTime, amr, t.ExpiresAt,
	).Scan(&t.ID)
	if err != nil {
		return fmt.Errorf("store: creating token: %w", err)
	}
	return nil
}

// TokenByRefresh resolves a refresh token.
func (s *Store) TokenByRefresh(ctx context.Context, refreshToken string) (*Token, error) {
	sum := sha256.Sum256([]byte(refreshToken))

	var t Token
	err := s.pool.QueryRow(ctx, `
		SELECT id, client_id, subject_id, session_id, scopes, audience,
		       auth_time, amr, expires_at
		  FROM oidc_tokens
		 WHERE refresh_hash = $1 AND revoked_at IS NULL AND expires_at > now()`,
		sum[:],
	).Scan(&t.ID, &t.ClientID, &t.SubjectID, &t.SessionID, &t.Scopes,
		&t.Audience, &t.AuthTime, &t.AMR, &t.ExpiresAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: loading token: %w", err)
	}
	return &t, nil
}

// RevokeToken invalidates a token immediately.
func (s *Store) RevokeToken(ctx context.Context, id uuid.UUID) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE oidc_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`,
		id); err != nil {
		return fmt.Errorf("store: revoking token: %w", err)
	}
	return nil
}

// revokeTokensForSessions invalidates every token issued from these sessions.
//
// Takes the transaction rather than the pool, and is unexported, because both
// facts are the fix for the bug it was written for. It existed as a public
// method for months, documented as "called on sign-out", and nothing called it:
// signing out closed the session and left the access tokens minted from it live
// for their full lifetime. Ending a session and killing its tokens are one
// change to one security boundary, so they commit together or not at all —
// the same argument ADR 0003 makes for the journal.
//
// Being unexported means the only way to reach it is through a function that
// also closes a session, so the two cannot drift apart again.
func revokeTokensForSessions(ctx context.Context, tx pgx.Tx, sessionIDs []uuid.UUID) error {
	if len(sessionIDs) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE oidc_tokens SET revoked_at = now()
		  WHERE session_id = ANY($1) AND revoked_at IS NULL`, sessionIDs); err != nil {
		return fmt.Errorf("store: revoking session tokens: %w", err)
	}
	return nil
}

// PurgeExpiredOIDCFlows clears abandoned requests and dead tokens.
func (s *Store) PurgeExpiredOIDCFlows(ctx context.Context) (int64, error) {
	var total int64

	tag, err := s.pool.Exec(ctx,
		`DELETE FROM oidc_auth_requests WHERE expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, fmt.Errorf("store: purging authorization requests: %w", err)
	}
	total += tag.RowsAffected()

	tag, err = s.pool.Exec(ctx,
		`DELETE FROM oidc_tokens WHERE expires_at < now() - interval '24 hours'`)
	if err != nil {
		return total, fmt.Errorf("store: purging tokens: %w", err)
	}
	return total + tag.RowsAffected(), nil
}

// orEmpty converts a nil slice to an empty one.
//
// pgx encodes a nil slice as SQL NULL rather than an empty array, so a NOT NULL
// array column rejects it. The distinction is invisible in Go and surfaces as a
// constraint violation at the worst moment.
func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
