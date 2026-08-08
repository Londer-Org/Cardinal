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
	"golang.org/x/crypto/ssh"
)

var (
	// ErrEnrollmentTokenInvalid covers absent, expired, revoked and already
	// redeemed alike. One error on purpose: distinguishing them would let
	// anyone holding a wrong token learn whether a right one exists.
	ErrEnrollmentTokenInvalid = errors.New("store: host enrollment token is invalid")

	// ErrHostCredentialUnknown means no live credential matches. Returned for
	// an unknown fingerprint and for a retired one, for the same reason.
	ErrHostCredentialUnknown = errors.New("store: no such host credential")
)

// HostEnrollmentTTL is how long a token lives.
//
// Shorter than a person's twenty-four hours, because enrolling a host is
// something an operator does at a console *now* — usually in the same minute
// they generated it. A day-long window is a day-long opportunity for whoever
// finds it in a terminal scrollback.
const HostEnrollmentTTL = time.Hour

// HostEnrollment is a single-use invitation for a machine.
type HostEnrollment struct {
	ID       uuid.UUID
	HostID   uuid.UUID
	HostName string

	// Token is populated only at creation. Only its hash is stored.
	Token string

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// HostCredential is a key a host authenticates with.
type HostCredential struct {
	ID          uuid.UUID
	HostID      uuid.UUID
	HostName    string
	PublicKey   ssh.PublicKey
	Fingerprint string
	EnrolledAt  time.Time
	LastSeenAt  *time.Time

	// Live distinguishes the key a host authenticates with now from the ones it
	// used before. Both are listed, because "which key made that request last
	// month" is a question only the retired rows can answer.
	Live bool
}

// CreateHostEnrollment issues a token for a host to register a key with.
func (s *Store) CreateHostEnrollment(
	ctx context.Context, hostID uuid.UUID, actorID *uuid.UUID,
) (*HostEnrollment, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("store: generating enrollment token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))

	out := &HostEnrollment{HostID: hostID, Token: token}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // a rollback after a successful commit returns ErrTxClosed

	err = tx.QueryRow(ctx, `
		INSERT INTO host_enrollment_tokens (host_id, token_hash, issued_by, expires_at)
		VALUES ($1, $2, $3, now() + $4::interval)
		RETURNING id, issued_at, expires_at`,
		hostID, sum[:], actorID, HostEnrollmentTTL,
	).Scan(&out.ID, &out.IssuedAt, &out.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("store: creating host enrollment: %w", err)
	}

	ev, err := event.New(event.ActionHostEnrollmentIssued, &hostID, actorID, nil)
	if err != nil {
		return nil, err
	}
	if err := s.AppendEvent(ctx, tx, ev); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("store: committing host enrollment: %w", err)
	}
	return out, nil
}

// RedeemHostEnrollment spends a token and records the key the host generated.
//
// One transaction, and the token is marked spent by the same statement that
// reads it — so two machines racing the same token cannot both succeed and end
// up as the same host.
func (s *Store) RedeemHostEnrollment(
	ctx context.Context, token string, publicKey ssh.PublicKey, from netip.Addr,
) (*HostCredential, error) {
	sum := sha256.Sum256([]byte(token))

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // a rollback after a successful commit returns ErrTxClosed

	var (
		hostID   uuid.UUID
		hostName string
		ip       *netip.Addr
	)
	if from.IsValid() {
		ip = &from
	}

	// The disabled check is inside the UPDATE rather than after it, so a token
	// for a host somebody just cut off is refused without being spent. It has to
	// be here and not only in HostByCredential: enrolling successfully and then
	// being unable to authenticate is the kind of half-working state an operator
	// debugs for an hour before finding the real answer.
	err = tx.QueryRow(ctx, `
		UPDATE host_enrollment_tokens t
		   SET redeemed_at = now(), redeemed_ip = $2
		 WHERE t.token_hash = $1
		   AND t.redeemed_at IS NULL
		   AND t.revoked_at IS NULL
		   AND t.expires_at > now()
		   AND EXISTS (SELECT 1 FROM entities e
		                WHERE e.id = t.host_id AND e.disabled_at IS NULL)
		RETURNING t.host_id,
		          (SELECT e.name FROM entities e WHERE e.id = t.host_id)`,
		sum[:], ip).Scan(&hostID, &hostName)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEnrollmentTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("store: redeeming host enrollment: %w", err)
	}

	// Re-enrolling retires whatever the host used before. A machine rebuilt
	// with a new key should not leave its old one able to authenticate, and the
	// row survives so that a request made with it last week is still
	// explicable.
	if _, execErr := tx.Exec(ctx, `
		UPDATE host_credentials
		   SET valid_period = tstzrange(lower(valid_period), now())
		 WHERE host_id = $1 AND upper(valid_period) = 'infinity'::timestamptz`,
		hostID); execErr != nil {
		return nil, fmt.Errorf("store: retiring previous host credential: %w", execErr)
	}

	cred := &HostCredential{
		HostID:      hostID,
		HostName:    hostName,
		PublicKey:   publicKey,
		Fingerprint: ssh.FingerprintSHA256(publicKey),
		Live:        true,
	}
	authorized := string(ssh.MarshalAuthorizedKey(publicKey))

	err = tx.QueryRow(ctx, `
		INSERT INTO host_credentials
			(host_id, public_key, fingerprint, valid_period, enrolled_ip)
		VALUES ($1, $2, $3, tstzrange(now(), 'infinity'), $4)
		RETURNING id, enrolled_at`,
		hostID, authorized, cred.Fingerprint, ip,
	).Scan(&cred.ID, &cred.EnrolledAt)
	if err != nil {
		return nil, fmt.Errorf("store: storing host credential: %w", err)
	}

	ev, err := event.New(event.ActionHostEnrolled, &hostID, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := s.AppendEvent(ctx, tx, ev); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("store: committing host enrollment: %w", err)
	}
	return cred, nil
}

// HostByCredential resolves a host from the key it signed with.
//
// Throttled last-seen, like sessions and access tokens: writing it on every
// request is how a table becomes the busiest in the database, and the value is
// only read by a human wondering whether an agent is still alive.
func (s *Store) HostByCredential(ctx context.Context, fingerprint string) (*HostCredential, error) {
	var (
		cred      HostCredential
		publicKey string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT c.id, c.host_id, e.name, c.public_key, c.fingerprint,
		       c.enrolled_at, c.last_seen_at
		  FROM host_credentials c
		  JOIN entities e ON e.id = c.host_id
		 WHERE c.fingerprint = $1
		   AND c.valid_period @> now()
		   AND e.disabled_at IS NULL`,
		fingerprint,
	).Scan(&cred.ID, &cred.HostID, &cred.HostName, &publicKey, &cred.Fingerprint,
		&cred.EnrolledAt, &cred.LastSeenAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrHostCredentialUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("store: looking up host credential: %w", err)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return nil, fmt.Errorf("store: stored host key is unparseable: %w", err)
	}
	cred.PublicKey = parsed
	cred.Live = true // the query only matches live rows

	if _, err := s.pool.Exec(ctx, `
		UPDATE host_credentials SET last_seen_at = now()
		 WHERE id = $1 AND (last_seen_at IS NULL OR last_seen_at < now() - interval '1 minute')`,
		cred.ID); err != nil {
		// Not worth failing a request over.
		return &cred, nil //nolint:nilerr // last-seen is observability, not authorization
	}
	return &cred, nil
}

// ListHostCredentials returns a host's keys, live ones first.
func (s *Store) ListHostCredentials(ctx context.Context, hostID uuid.UUID) ([]HostCredential, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.host_id, e.name, c.fingerprint, c.enrolled_at, c.last_seen_at,
		       c.valid_period @> now() AS live
		  FROM host_credentials c
		  JOIN entities e ON e.id = c.host_id
		 WHERE c.host_id = $1
		 ORDER BY live DESC, c.enrolled_at DESC`, hostID)
	if err != nil {
		return nil, fmt.Errorf("store: listing host credentials: %w", err)
	}
	defer rows.Close()

	var out []HostCredential
	for rows.Next() {
		var c HostCredential
		if err := rows.Scan(&c.ID, &c.HostID, &c.HostName, &c.Fingerprint,
			&c.EnrolledAt, &c.LastSeenAt, &c.Live); err != nil {
			return nil, fmt.Errorf("store: scanning host credential: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
