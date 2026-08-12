package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/directory/event"
)

// Signing a terminal in from a device that is not this one.
//
// The loopback flow needs the browser and the CLI to share a loopback
// interface, which is false the moment the terminal is on a server you are
// SSH'd into. Here the terminal asks first, prints a short code, and polls; the
// person approves from whatever has a browser.
//
// The weakness of this shape is worth naming because it is well known: an
// attacker starts a flow and talks somebody into approving *their* code. Three
// things blunt it, and none of them is the code's length.
//
// The window is minutes rather than hours, so an attempt has to land while the
// victim is at their keyboard. The approval screen shows the address the
// request came from as the *server* saw it, never a name the terminal chose,
// because "approve the code from web-01" is exactly the sentence an attacker
// would like to be able to arrange. And approving requires a device-bound
// session, so the thing being handed over is never weaker than the ceremony
// that authorised it.

// DeviceCodeTTL is how long a pending request lives.
//
// Longer than the ninety seconds the loopback flow uses, and the difference is
// the point rather than an oversight. Ninety seconds is generous when the
// browser is already open on the same machine; this one may need somebody to
// find a phone and sign in first, and a window that routinely expires teaches
// people to re-run the command and approve faster without reading — which is
// worse for the attack above than a window that is long enough to think in.
const DeviceCodeTTL = 5 * time.Minute

// DevicePollInterval is how often a terminal should ask.
//
// Told to the client rather than assumed by it, so the server can slow a fleet
// of them down without shipping a new CLI.
const DevicePollInterval = 3 * time.Second

// ErrDevicePending means the request exists and nobody has approved it yet.
var ErrDevicePending = errors.New("store: authorization pending")

// DeviceRequest is a terminal waiting to be approved.
type DeviceRequest struct {
	UserCode    string
	ExpiresAt   time.Time
	RequestedIP string
}

// userCodeAlphabet excludes the characters people mistype when reading aloud:
// no 0/O, no 1/I/L, no U (which is heard as V often enough to matter).
const userCodeAlphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"

// CreateDeviceAuthorization records a request nobody has approved yet.
//
// The device code is the credential and never leaves the terminal's process
// except in the poll; the user code is an identifier and is expected to be read
// aloud. They are separate values so that shoulder-surfing the short one gains
// nothing.
func (s *Store) CreateDeviceAuthorization(
	ctx context.Context, verifierHash string, from netip.Addr,
) (deviceCode string, req *DeviceRequest, err error) {
	deviceCode, err = randomToken()
	if err != nil {
		return "", nil, err
	}
	userCode, err := randomUserCode()
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256([]byte(deviceCode))

	var ip *string
	if from.IsValid() {
		text := from.String()
		ip = &text
	}

	var expires time.Time
	err = s.pool.QueryRow(ctx, `
		INSERT INTO cli_authorizations
		    (code_hash, verifier_hash, user_code, requested_ip, expires_at)
		VALUES ($1, $2, $3, $4::inet, now() + $5::interval)
		RETURNING expires_at`,
		base64.RawURLEncoding.EncodeToString(sum[:]), verifierHash, userCode, ip,
		DeviceCodeTTL.String(),
	).Scan(&expires)
	if err != nil {
		return "", nil, fmt.Errorf("store: recording device authorization: %w", err)
	}

	out := &DeviceRequest{UserCode: userCode, ExpiresAt: expires}
	if ip != nil {
		out.RequestedIP = *ip
	}
	return deviceCode, out, nil
}

// PendingDeviceRequest describes what somebody is about to approve.
func (s *Store) PendingDeviceRequest(ctx context.Context, userCode string) (*DeviceRequest, error) {
	var (
		out DeviceRequest
		ip  *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT user_code, expires_at, host(requested_ip)
		  FROM cli_authorizations
		 WHERE user_code = $1
		   AND claimed_at IS NULL
		   AND approved_at IS NULL
		   AND expires_at > now()`, userCode).Scan(&out.UserCode, &out.ExpiresAt, &ip)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCLIAuthNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading device authorization: %w", err)
	}
	if ip != nil {
		out.RequestedIP = *ip
	}
	return &out, nil
}

// ApproveDeviceAuthorization attaches a session to a pending request.
//
// Approving and collecting stay separate: the terminal still has to present the
// device code and its verifier, so an approval on its own hands nothing to
// whoever guessed a user code.
func (s *Store) ApproveDeviceAuthorization(
	ctx context.Context, userCode string, sessionID, actorID uuid.UUID,
) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE cli_authorizations
			   SET session_id = $2, approved_at = now()
			 WHERE user_code = $1
			   AND claimed_at IS NULL
			   AND approved_at IS NULL
			   AND expires_at > now()`, userCode, sessionID)
		if err != nil {
			return fmt.Errorf("store: approving device authorization: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrCLIAuthNotFound
		}

		ev, err := event.New(event.ActionCLISessionIssued, nil, &actorID,
			map[string]any{"flow": "device"})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// CollectDeviceAuthorization exchanges an approved device code for a session.
//
// ErrDevicePending while nobody has approved, which is the ordinary answer and
// not an error the person should see: the terminal is polling.
func (s *Store) CollectDeviceAuthorization(
	ctx context.Context, deviceCode, verifier string, origin SessionOrigin,
) (*Session, error) {
	sum := sha256.Sum256([]byte(deviceCode))
	verifierSum := sha256.Sum256([]byte(verifier))

	var out *Session
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		// Read first to tell "not approved yet" from "no such request", which
		// are the same row state to a claiming UPDATE and mean different things
		// to whoever is waiting.
		var approved *time.Time
		err := tx.QueryRow(ctx, `
			SELECT approved_at FROM cli_authorizations
			 WHERE code_hash = $1
			   AND verifier_hash = $2
			   AND claimed_at IS NULL
			   AND expires_at > now()
			   FOR UPDATE`,
			base64.RawURLEncoding.EncodeToString(sum[:]),
			base64.RawURLEncoding.EncodeToString(verifierSum[:]),
		).Scan(&approved)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrCLIAuthNotFound
		}
		if err != nil {
			return fmt.Errorf("store: reading device authorization: %w", err)
		}
		if approved == nil {
			return ErrDevicePending
		}

		var sessionID uuid.UUID
		err = tx.QueryRow(ctx, `
			UPDATE cli_authorizations
			   SET claimed_at = now()
			 WHERE code_hash = $1 AND claimed_at IS NULL
			RETURNING session_id`,
			base64.RawURLEncoding.EncodeToString(sum[:]),
		).Scan(&sessionID)
		if err != nil {
			return fmt.Errorf("store: claiming device authorization: %w", err)
		}

		parent, err := lookupSessionByIDTx(ctx, tx, sessionID)
		if err != nil {
			// Approved, and the session behind it has since gone. Refusing is
			// the only honest answer: the ceremony this would inherit from has
			// been withdrawn.
			return ErrCLIAuthNotFound
		}

		out, err = createSessionTx(ctx, tx, parent.SubjectID, SessionSpec{
			AuthMethod:    parent.AuthMethod,
			TTL:           CLISessionTTL,
			AbsoluteTTL:   CLISessionTTL,
			DeviceBound:   parent.DeviceBound,
			CredentialID:  parent.CredentialID,
			AuthAt:        parent.AuthAt,
			SessionOrigin: origin,
		}, s.sessionLimits())
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// randomUserCode is eight characters in two groups, which is what people can
// hold in their head between one screen and another.
func randomUserCode() (string, error) {
	out := make([]byte, 0, 9)
	for i := range 8 {
		if i == 4 {
			out = append(out, '-')
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeAlphabet))))
		if err != nil {
			return "", fmt.Errorf("store: generating a user code: %w", err)
		}
		out = append(out, userCodeAlphabet[n.Int64()])
	}
	return string(out), nil
}
