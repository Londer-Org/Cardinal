package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/event"
)

// Signing a terminal in.
//
// A terminal cannot perform a WebAuthn ceremony: there is no browser in it and
// no way for it to reach a platform authenticator. So it borrows one. The
// person completes the ceremony where ceremonies happen — in the console — and
// what comes back is a session that *inherits* what that ceremony proved.
//
// Inherits, rather than being granted something weaker, is the whole point. An
// access token would have been far less work and is exactly wrong: it is not
// device-bound, so policy refuses it an SSH certificate (ADR 0018), and making
// it device-bound would put a credential that can reach every machine in the
// fleet into a file on disk with a ninety-day life.
//
// The exchange is two steps because the first one ends in a redirect, and a URL
// is the worst place to put a credential — it lands in shell history, in proxy
// logs, and in the browser's address bar. The redirect carries a code that is
// single-use, short-lived, and worthless without the verifier the terminal
// never sent anywhere.

// CLIAuthTTL is how long an unclaimed code lives.
//
// Ninety seconds: long enough to notice a browser window and press a button,
// short enough that one left behind on a shared machine is stale before anybody
// walks past it.
const CLIAuthTTL = 90 * time.Second

// CLISessionTTL is how long the session the terminal receives lasts.
//
// Deliberately far shorter than a browser session. It exists to fetch a
// certificate or two, and a certificate carries its own expiry from that point
// — so the session outliving the command that created it buys nothing and
// leaves a device-bound credential lying in a terminal.
const CLISessionTTL = 10 * time.Minute

// ErrCLIAuthNotFound reports a code that is unknown, already claimed, or
// expired. Deliberately one error: telling the difference would say whether a
// guess was close.
var ErrCLIAuthNotFound = errors.New("store: no such authorization")

// CreateCLIAuthorization records an approved terminal sign-in and returns the
// code to redirect with.
//
// verifierHash is the SHA-256 of a secret the terminal generated and has never
// transmitted. Whoever intercepts the redirect — a proxy log, somebody reading
// over a shoulder, a browser extension — holds a code they cannot exchange.
func (s *Store) CreateCLIAuthorization(
	ctx context.Context, sessionID uuid.UUID, verifierHash string,
) (string, error) {
	code, err := randomToken()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(code))

	_, err = s.pool.Exec(ctx, `
		INSERT INTO cli_authorizations (code_hash, verifier_hash, session_id, expires_at)
		VALUES ($1, $2, $3, now() + $4::interval)`,
		base64.RawURLEncoding.EncodeToString(sum[:]), verifierHash, sessionID,
		CLIAuthTTL.String())
	if err != nil {
		return "", fmt.Errorf("store: recording CLI authorization: %w", err)
	}
	return code, nil
}

// ClaimCLIAuthorization exchanges a code for a session, once.
//
// The parent session is read at claim time rather than at approval time, so a
// person who approves and then immediately signs out everywhere does not leave
// a code that still works. Revocation is enforced at read time here as it is
// everywhere else (ADR 0004).
func (s *Store) ClaimCLIAuthorization(
	ctx context.Context, code, verifier string, origin SessionOrigin,
) (*Session, error) {
	sum := sha256.Sum256([]byte(code))
	verifierSum := sha256.Sum256([]byte(verifier))

	var out *Session
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		// Claimed in the same statement that reads it, so two terminals racing
		// the same code cannot both win.
		var sessionID uuid.UUID
		err := tx.QueryRow(ctx, `
			UPDATE cli_authorizations
			   SET claimed_at = now()
			 WHERE code_hash = $1
			   AND verifier_hash = $2
			   AND claimed_at IS NULL
			   AND expires_at > now()
			RETURNING session_id`,
			base64.RawURLEncoding.EncodeToString(sum[:]),
			base64.RawURLEncoding.EncodeToString(verifierSum[:]),
		).Scan(&sessionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrCLIAuthNotFound
		}
		if err != nil {
			return fmt.Errorf("store: claiming CLI authorization: %w", err)
		}

		parent, err := lookupSessionByIDTx(ctx, tx, sessionID)
		if err != nil {
			// The approval was real and the session behind it is not any more.
			// Refusing is the only honest answer: the ceremony this would
			// inherit from has been withdrawn.
			return ErrCLIAuthNotFound
		}

		// Everything the ceremony proved, and nothing more. AuthAt is carried
		// across too, so a policy asking how recently somebody authenticated
		// gets the truth rather than a clock reset by the exchange.
		out, err = createSessionTx(ctx, tx, parent.SubjectID, SessionSpec{
			AuthMethod:    parent.AuthMethod,
			TTL:           CLISessionTTL,
			AbsoluteTTL:   CLISessionTTL,
			DeviceBound:   parent.DeviceBound,
			CredentialID:  parent.CredentialID,
			AuthAt:        parent.AuthAt,
			SessionOrigin: origin,
		}, s.sessionLimits())
		if err != nil {
			return err
		}

		ev, err := event.New(event.ActionCLISessionIssued, &parent.SubjectID, &parent.SubjectID,
			map[string]any{
				"session_id":   out.ID,
				"device_bound": out.DeviceBound,
			})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	return out, err
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: generating a token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
