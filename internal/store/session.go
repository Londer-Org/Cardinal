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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/event"
)

// Authentication methods, as recorded on a session and surfaced to policy.
//
// Strings rather than an enum because they travel: into the decision log, into
// `amr` on an ID token, and into Cedar as a principal attribute. A value here
// is part of the contract with anything reading those.
const (
	AuthMethodPasskey = "passkey"

	// AuthMethodAccessToken is a bearer token used by a script. Recorded so a
	// decision log can be read for "what did automation do", which is the
	// question the proxy-bypass arrangement it replaces made unanswerable.
	AuthMethodAccessToken = "access_token"
)

// sessionTokenBytes is 32 bytes of entropy. Session tokens are bearer
// credentials, so this is the one place where being generous costs nothing.
const sessionTokenBytes = 32

var (
	// ErrSessionInvalid reports that the session has expired or been revoked.
	ErrSessionInvalid = errors.New("store: session is invalid or expired")
	// ErrNoSuchSession reports that the session does not exist, or belongs to
	// somebody else — the two are deliberately indistinguishable to the caller.
	ErrNoSuchSession = errors.New("store: no such session")
)

// Session is an authenticated session.
// Two clocks bound a session, which is what every session system converges on.
//
// Idle is how long it survives without being used, and it slides: a request
// pushes it forward, so somebody working through a morning is not signed out
// because of when they started.
//
// Absolute is the hard end, never extended. It is what makes "everyone
// re-authenticates eventually" true rather than aspirational — sliding expiry
// with no cap means a stolen token is valid indefinitely provided it is used,
// which is precisely the case a cap exists for.
//
// Defaults, not law: an operator sets these in [sessions]. Eight hours is a
// working day, so signing in once in the morning carries someone through it —
// and the tempting shorter values are the ones that get raised, because a
// control people route around is worse than a looser one they keep.
//
// Neither governs administration. Changing the directory needs a device-bound
// key used within five minutes regardless of session age, and that rule lives
// in the policy set.
const (
	DefaultIdleSessionTTL     = 8 * time.Hour
	DefaultAbsoluteSessionTTL = 7 * 24 * time.Hour
)

// SessionLimits are the two clocks, as configured.
type SessionLimits struct {
	Idle     time.Duration
	Absolute time.Duration
}

// withDefaults fills anything unset, so a zero value is usable rather than
// meaning "no expiry at all" — which is the one thing these must never mean.
func (l SessionLimits) withDefaults() SessionLimits {
	if l.Idle <= 0 {
		l.Idle = DefaultIdleSessionTTL
	}
	if l.Absolute <= 0 {
		l.Absolute = DefaultAbsoluteSessionTTL
	}
	return l
}

// Session is a signed-in session, including how it was authenticated and
// whether that credential was device-bound (ADR 0018).
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

	// AbsoluteExpiry is the hard end of this session, never extended.
	AbsoluteExpiry time.Time

	// Where it was created from. Empty when unknown.
	ClientIP  string
	UserAgent string
}

// Expired reports whether the session has passed its validity window.
//
// Callers must check this at read time and not rely on cache invalidation:
// NOTIFY is a hint, never a guarantee (ADR 0004), so a dropped notification
// must be a latency problem rather than an authorization bypass.
func (s *Session) Expired() bool { return time.Now().After(s.ValidUntil) }

// SessionSpec describes a session to be created.
type SessionSpec struct {
	AuthMethod string

	// TTL is the idle window: how long the session survives without being used.
	// It slides forward as the session is used.
	TTL time.Duration

	// AbsoluteTTL is the hard end, never extended. Zero means
	// AbsoluteSessionTTL. A deployment wanting shorter-lived sessions than the
	// default sets this rather than shortening the idle window, which would
	// only mean signing people out mid-task more often.
	AbsoluteTTL time.Duration

	DeviceBound  bool
	CredentialID *uuid.UUID

	// AuthAt is when the ceremony behind this session actually happened.
	//
	// Zero means now, which is right for a session created by a ceremony. It is
	// set only when a session inherits one — a terminal borrowing the console's
	// passkey — because a policy asking `authAgeSeconds <= 300` must get the age
	// of the ceremony and not the age of the exchange. Resetting the clock here
	// would let a sign-in from this morning satisfy a rule that exists to demand
	// one from this minute.
	AuthAt time.Time

	// ClientIP and UserAgent are what let somebody recognise a session as
	// theirs, or fail to.
	//
	// Both columns have existed since the first migration and nothing ever
	// wrote them, so every session looked identical to every other and a list
	// of them would have been a list of timestamps. "Firefox on Linux, from
	// this address, an hour ago" is what turns the list into a security
	// control: the entry somebody does not recognise is the reason the revoke
	// button is there.
	//
	// Both are personal data. They live here rather than in the event journal
	// precisely because this table can be deleted (ADR 0010), and the payload
	// allowlist refuses them for that reason.
	SessionOrigin
}

// SessionOrigin is where a session was opened from.
//
// Its own type so it can be carried through the authentication layer without
// that layer growing two loose strings it does nothing with.
type SessionOrigin struct {
	ClientIP  string
	UserAgent string
}

// maxUserAgentLength bounds what a client can make us store.
//
// A User-Agent header is attacker-controlled and unbounded; without a cap,
// signing in repeatedly with a megabyte of it is a cheap way to fill the
// sessions table. 512 is longer than any real browser sends.
const maxUserAgentLength = 512

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// createSessionTx mints a session inside an existing transaction.
//
// The raw token is returned to the caller and never stored: the database holds
// only its SHA-256 hash, so reading the sessions table yields nothing that can
// authenticate. Hashing is plain SHA-256 rather than Argon2id deliberately —
// unlike a password, the token has 256 bits of entropy and is not guessable, so
// a slow KDF would only add latency to every request.
func createSessionTx(ctx context.Context, tx pgx.Tx, subjectID uuid.UUID, spec SessionSpec, limits SessionLimits) (*Session, error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("store: generating session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))

	now := time.Now().UTC().Truncate(time.Microsecond)

	// A zero TTL means the configured idle window, not an instantly-expired
	// session — the one interpretation that would be a silent lockout.
	limits = limits.withDefaults()
	idle := spec.TTL
	if idle <= 0 {
		idle = limits.Idle
	}

	authAt := spec.AuthAt
	if authAt.IsZero() {
		authAt = now
	}

	s := &Session{
		SubjectID:    subjectID,
		Token:        token,
		ValidFrom:    now,
		ValidUntil:   now.Add(idle),
		AuthMethod:   spec.AuthMethod,
		AuthAt:       authAt,
		DeviceBound:  spec.DeviceBound,
		CredentialID: spec.CredentialID,
	}

	absolute := spec.AbsoluteTTL
	if absolute <= 0 {
		absolute = limits.Absolute
	}
	s.AbsoluteExpiry = now.Add(absolute)

	// NULL rather than empty string when unknown, so "we did not record this"
	// and "the client sent nothing" stay distinguishable — a session created by
	// a CLI or a test legitimately has neither.
	var ip, agent *string
	if spec.ClientIP != "" {
		ip = &spec.ClientIP
	}
	if spec.UserAgent != "" {
		trimmed := truncate(spec.UserAgent, maxUserAgentLength)
		agent = &trimmed
	}
	s.ClientIP, s.UserAgent = spec.ClientIP, spec.UserAgent

	err := tx.QueryRow(ctx, `
		INSERT INTO sessions (subject_id, token_hash, valid_period, auth_method,
		                      auth_at, device_bound, credential_id, absolute_expiry,
		                      client_ip, user_agent)
		VALUES ($1, $2, tstzrange($3::timestamptz, $4::timestamptz), $5, $6, $7, $8, $9,
		        $10::inet, $11)
		RETURNING id`,
		subjectID, sum[:], s.ValidFrom, s.ValidUntil,
		s.AuthMethod, s.AuthAt, s.DeviceBound, s.CredentialID, s.AbsoluteExpiry,
		ip, agent,
	).Scan(&s.ID)
	if err != nil {
		return nil, fmt.Errorf("store: creating session: %w", err)
	}
	return s, nil
}

// CreateSession mints a session and records it.
func (s *Store) CreateSession(ctx context.Context, subjectID uuid.UUID, spec SessionSpec) (*Session, error) {
	var out *Session
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = createSessionTx(ctx, tx, subjectID, spec, s.sessionLimits())
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

	// Resolved and extended in one statement.
	//
	// The extension is the whole point: a session ends because its holder
	// stopped, not because of when they started. It is written only when the
	// idle window has actually moved by more than a minute, so an active tab
	// does not turn every request into a write — the mistake that makes people
	// blame Postgres for session storage.
	//
	// least() against absolute_expiry is what keeps the second clock honest:
	// sliding expiry without a cap means a stolen token is valid forever
	// provided it is used.
	var sess Session
	err := s.pool.QueryRow(ctx, `
		UPDATE sessions SET valid_period = tstzrange(
		         lower(valid_period),
		         least(now() + $2::interval, absolute_expiry))
		 WHERE token_hash = $1
		   AND valid_period @> now()
		   AND upper(valid_period) < least(now() + $2::interval, absolute_expiry) - interval '1 minute'
		RETURNING id, subject_id, lower(valid_period), upper(valid_period),
		          auth_method, auth_at, device_bound, credential_id, absolute_expiry`,
		sum[:], s.sessionLimits().Idle,
	).Scan(&sess.ID, &sess.SubjectID, &sess.ValidFrom, &sess.ValidUntil,
		&sess.AuthMethod, &sess.AuthAt, &sess.DeviceBound, &sess.CredentialID,
		&sess.AbsoluteExpiry)

	if errors.Is(err, pgx.ErrNoRows) {
		// Either the session is invalid, or it was extended less than a minute
		// ago and needs no write. Read it.
		err = s.pool.QueryRow(ctx, `
			SELECT id, subject_id, lower(valid_period), upper(valid_period),
			       auth_method, auth_at, device_bound, credential_id, absolute_expiry
			  FROM sessions
			 WHERE token_hash = $1 AND valid_period @> now()`,
			sum[:],
		).Scan(&sess.ID, &sess.SubjectID, &sess.ValidFrom, &sess.ValidUntil,
			&sess.AuthMethod, &sess.AuthAt, &sess.DeviceBound, &sess.CredentialID,
			&sess.AbsoluteExpiry)
	}

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

// ConstantTimeCompare is used where a secret is compared outside the database.
// Kept here so call sites cannot accidentally reach for ==.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RefreshSessionAuth records that a live session re-proved its credential.
//
// Updates auth_at and device_bound without minting a new session, so the
// browser keeps the cookie it has and policy sees a fresh authentication. The
// alternative — issuing a new session — would mean every step-up rotated the
// cookie, and anything holding the old one (another tab, an in-flight request)
// would be signed out by an action that was supposed to grant access.
//
// device_bound is taken from the credential actually presented, not carried
// over: someone may sign in with a synced passkey and step up with a hardware
// key, which is exactly the flow the freshness rule exists to allow.
func (s *Store) RefreshSessionAuth(ctx context.Context, sessionID uuid.UUID, deviceBound bool) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE sessions SET auth_at = now(), device_bound = $2
			 WHERE id = $1 AND valid_period @> now()`,
			sessionID, deviceBound)
		if err != nil {
			return fmt.Errorf("store: refreshing session authentication: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNoSuchSession
		}

		// Its own action, not session.created: a step-up is a distinct event
		// worth being able to find, and counting it as a sign-in would make
		// "how often does this person authenticate" meaningless.
		ev, err := event.New(event.ActionSessionReauthenticated, nil, nil,
			map[string]any{"session_id": sessionID, "device_bound": deviceBound})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// SessionSummary is a session as its owner sees it in a list.
//
// Deliberately not Session: that type carries Token, which is populated at
// creation and must never be reachable from a listing. A separate type makes
// that a compile-time fact rather than a habit.
type SessionSummary struct {
	ID uuid.UUID

	StartedAt      time.Time
	ExpiresAt      time.Time
	AbsoluteExpiry time.Time

	AuthMethod  string
	AuthAt      time.Time
	DeviceBound bool

	// Empty when the session predates these being recorded, or was created by
	// something with no request behind it.
	ClientIP  string
	UserAgent string
}

// ListSessions returns a subject's currently-valid sessions, newest first.
//
// Only live ones. An expired session cannot be used and cannot be revoked, so
// listing it would offer a button that does nothing next to a row nobody can
// act on — while burying the entry that matters among months of history.
//
// The composite GiST index on (subject_id, valid_period) exists for exactly
// this query; the comment in migration 0001 names it, years before anything
// called it.
func (s *Store) ListSessions(ctx context.Context, subjectID uuid.UUID) ([]SessionSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, lower(valid_period), upper(valid_period), absolute_expiry,
		       auth_method, auth_at, device_bound,
		       host(client_ip), user_agent
		  FROM sessions
		 WHERE subject_id = $1 AND valid_period @> now()
		 ORDER BY lower(valid_period) DESC`, subjectID)
	if err != nil {
		return nil, fmt.Errorf("store: listing sessions: %w", err)
	}
	defer rows.Close()

	var out []SessionSummary
	for rows.Next() {
		var summary SessionSummary
		var ip, agent *string
		if err := rows.Scan(&summary.ID, &summary.StartedAt, &summary.ExpiresAt,
			&summary.AbsoluteExpiry, &summary.AuthMethod, &summary.AuthAt,
			&summary.DeviceBound, &ip, &agent); err != nil {
			return nil, fmt.Errorf("store: reading session: %w", err)
		}
		if ip != nil {
			summary.ClientIP = *ip
		}
		if agent != nil {
			summary.UserAgent = *agent
		}
		out = append(out, summary)
	}
	return out, rows.Err()
}

// RevokeSessionFor ends one session belonging to a specific subject.
//
// The subject is part of the statement rather than checked beforehand, so
// somebody who has obtained a session id — from a log, a screenshot, a shared
// terminal — revokes nothing rather than signing a colleague out. RevokeSession
// takes an id alone and is for administrative and internal callers, where the
// authority to act has already been established by policy; this is the
// self-service door and it cannot be widened by knowing an identifier.
func (s *Store) RevokeSessionFor(ctx context.Context, id, subjectID uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE sessions
			   SET valid_period = tstzrange(lower(valid_period), now())
			 WHERE id = $1 AND subject_id = $2 AND upper(valid_period) > now()`,
			id, subjectID)
		if err != nil {
			return fmt.Errorf("store: revoking session: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNoSuchSession
		}

		ev, err := event.New(event.ActionSessionRevoked, &subjectID, actorID,
			map[string]any{"session_id": id})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// RevokeOtherSessions ends every session for a subject except one.
//
// The operation somebody actually wants after losing a laptop: sign out
// everywhere, stay signed in here. Revoking all of them including the current
// one is available too — that is RevokeAllSessions — but making it the only
// option means the person doing the panicking is also immediately locked out of
// the console they are panicking in.
func (s *Store) RevokeOtherSessions(ctx context.Context, subjectID, keep uuid.UUID, actorID *uuid.UUID) (int64, error) {
	var count int64
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE sessions
			   SET valid_period = tstzrange(lower(valid_period), now())
			 WHERE subject_id = $1 AND id <> $2 AND upper(valid_period) > now()`,
			subjectID, keep)
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

// lookupSessionByIDTx reads a session by its id, inside a transaction.
//
// By id rather than by token, because the caller here holds a reference to a
// session it is deriving from and never sees that session's token — which is
// the point: approving a terminal must not hand the terminal the browser's
// credential.
func lookupSessionByIDTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (*Session, error) {
	var s Session
	err := tx.QueryRow(ctx, `
		SELECT id, subject_id, lower(valid_period), upper(valid_period),
		       auth_method, auth_at, device_bound, credential_id, absolute_expiry
		  FROM sessions
		 WHERE id = $1
		   AND valid_period @> now()
		   AND absolute_expiry > now()`, id).
		Scan(&s.ID, &s.SubjectID, &s.ValidFrom, &s.ValidUntil,
			&s.AuthMethod, &s.AuthAt, &s.DeviceBound, &s.CredentialID, &s.AbsoluteExpiry)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading session: %w", err)
	}
	return &s, nil
}
