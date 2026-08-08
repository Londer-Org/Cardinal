package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/event"
)

var (
	// ErrACMEAccountUnknown means no account matches that key.
	ErrACMEAccountUnknown = errors.New("store: no such ACME account")

	// ErrEABInvalid covers absent, expired, revoked and already redeemed alike.
	// One error, for the same reason host enrollment has one.
	ErrEABInvalid = errors.New("store: this external account binding cannot be used")

	// ErrNonceUnknown means the nonce was never issued, or has been used.
	ErrNonceUnknown = errors.New("store: unknown or replayed nonce")
)

// EABCredentialTTL is how long a binding credential lives before redemption.
//
// A day, against the hour a host enrollment token gets. The difference is what
// they are for: a host enrollment is typed at a console within the minute,
// where an ACME credential is put into configuration management and applied on
// whatever schedule that runs on.
const EABCredentialTTL = 24 * time.Hour

// EABCredential lets a machine create an ACME account bound to it.
type EABCredential struct {
	ID        uuid.UUID
	SubjectID uuid.UUID
	Subject   string

	KeyID string

	// HMACKey is populated only at creation, and base64url as every ACME client
	// expects to be given it.
	HMACKey string

	ExpiresAt time.Time
}

// CreateEABCredential issues one.
func (s *Store) CreateEABCredential(
	ctx context.Context, subjectID uuid.UUID, encryptionKey string, actorID *uuid.UUID,
) (*EABCredential, error) {
	seal, err := newSealer(encryptionKey)
	if err != nil {
		return nil, err
	}

	// The key id is not a secret — it travels in a JWS header in the clear —
	// but it must be unguessable anyway: a predictable one lets somebody probe
	// for which hosts exist.
	idBytes := make([]byte, 16)
	if _, readErr := rand.Read(idBytes); readErr != nil {
		return nil, fmt.Errorf("store: generating an EAB key id: %w", readErr)
	}
	macKey := make([]byte, 32)
	if _, readErr := rand.Read(macKey); readErr != nil {
		return nil, fmt.Errorf("store: generating an EAB key: %w", readErr)
	}

	sealed, err := seal.seal(macKey)
	if err != nil {
		return nil, err
	}

	out := &EABCredential{
		SubjectID: subjectID,
		KeyID:     base64.RawURLEncoding.EncodeToString(idBytes),
		HMACKey:   base64.RawURLEncoding.EncodeToString(macKey),
	}

	err = s.InTx(ctx, func(tx pgx.Tx) error {
		if queryErr := tx.QueryRow(ctx, `
			INSERT INTO acme_eab_credentials
				(subject_id, key_id, hmac_sealed, issued_by, expires_at)
			VALUES ($1, $2, $3, $4, now() + $5::interval)
			RETURNING id, expires_at`,
			subjectID, out.KeyID, sealed, actorID, EABCredentialTTL,
		).Scan(&out.ID, &out.ExpiresAt); queryErr != nil {
			return fmt.Errorf("store: storing the EAB credential: %w", queryErr)
		}

		ev, buildErr := event.New(event.ActionACMECredentialIssued, &subjectID, actorID, nil)
		if buildErr != nil {
			return buildErr
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RedeemEABCredential spends a binding and returns its MAC key.
//
// One statement marks it spent, so two clients racing the same credential
// cannot both bind an account to the host.
func (s *Store) RedeemEABCredential(
	ctx context.Context, keyID, encryptionKey string,
) (subjectID uuid.UUID, macKey []byte, err error) {
	seal, err := newSealer(encryptionKey)
	if err != nil {
		return uuid.Nil, nil, err
	}

	var sealed []byte
	err = s.pool.QueryRow(ctx, `
		UPDATE acme_eab_credentials c
		   SET redeemed_at = now()
		 WHERE c.key_id = $1
		   AND c.redeemed_at IS NULL
		   AND c.revoked_at IS NULL
		   AND c.expires_at > now()
		   AND EXISTS (SELECT 1 FROM entities e
		                WHERE e.id = c.subject_id AND e.disabled_at IS NULL)
		RETURNING c.subject_id, c.hmac_sealed`, keyID).Scan(&subjectID, &sealed)

	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil, ErrEABInvalid
	}
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("store: redeeming the EAB credential: %w", err)
	}

	macKey, err = seal.open(sealed)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return subjectID, macKey, nil
}

// ACMEAccount is a client key bound to a directory entity.
type ACMEAccount struct {
	ID         uuid.UUID
	SubjectID  uuid.UUID
	Subject    string
	Thumbprint string
	PublicJWK  json.RawMessage
	Contact    []string

	Deactivated bool
}

// CreateACMEAccount binds an account key to a subject.
func (s *Store) CreateACMEAccount(
	ctx context.Context, subjectID uuid.UUID, thumbprint string,
	publicJWK json.RawMessage, contact []string,
) (*ACMEAccount, error) {
	account := &ACMEAccount{
		SubjectID: subjectID, Thumbprint: thumbprint,
		PublicJWK: publicJWK, Contact: contact,
	}
	if contact == nil {
		account.Contact = []string{}
	}

	err := s.InTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO acme_accounts (subject_id, thumbprint, public_jwk, contact)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (thumbprint) DO UPDATE
			   SET contact = EXCLUDED.contact, deactivated_at = NULL
			RETURNING id`,
			subjectID, thumbprint, []byte(publicJWK), account.Contact,
		).Scan(&account.ID); err != nil {
			return fmt.Errorf("store: creating the ACME account: %w", err)
		}

		ev, err := event.New(event.ActionACMEAccountCreated, &subjectID, nil, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}
	return account, nil
}

// ACMEAccountByID resolves an account, with the entity it belongs to.
func (s *Store) ACMEAccountByID(ctx context.Context, id uuid.UUID) (*ACMEAccount, error) {
	var (
		a   ACMEAccount
		jwk []byte
		off *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT a.id, a.subject_id, e.name, a.thumbprint, a.public_jwk,
		       a.contact, a.deactivated_at
		  FROM acme_accounts a
		  JOIN entities e ON e.id = a.subject_id
		 WHERE a.id = $1 AND e.disabled_at IS NULL`, id,
	).Scan(&a.ID, &a.SubjectID, &a.Subject, &a.Thumbprint, &jwk, &a.Contact, &off)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrACMEAccountUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading the ACME account: %w", err)
	}
	a.PublicJWK = jwk
	a.Deactivated = off != nil
	return &a, nil
}

// NewACMENonce issues an anti-replay nonce.
func (s *Store) NewACMENonce(ctx context.Context) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: generating a nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO acme_nonces (nonce) VALUES ($1)`, nonce); err != nil {
		return "", fmt.Errorf("store: storing the nonce: %w", err)
	}
	return nonce, nil
}

// ConsumeACMENonce spends a nonce, once.
//
// The delete is the check: a nonce that was already used deletes no row, which
// is the same statement rather than a read followed by a write. Two requests
// replaying one nonce cannot both find it present.
func (s *Store) ConsumeACMENonce(ctx context.Context, nonce string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM acme_nonces WHERE nonce = $1 AND issued_at > now() - interval '1 hour'`,
		nonce)
	if err != nil {
		return fmt.Errorf("store: consuming the nonce: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNonceUnknown
	}
	return nil
}

// PurgeACMENonces clears nonces nobody will use.
func (s *Store) PurgeACMENonces(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM acme_nonces WHERE issued_at < now() - $1::interval`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("store: purging nonces: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ACMEOrder is a request for a certificate.
type ACMEOrder struct {
	ID          uuid.UUID
	AccountID   uuid.UUID
	Status      string
	Identifiers []string
	ExpiresAt   time.Time

	Certificate []byte
	Serial      string

	Authorizations []ACMEAuthorization
}

// ACMEAuthorization is one identifier's authorization.
type ACMEAuthorization struct {
	ID         uuid.UUID
	Identifier string
	Status     string
	ExpiresAt  time.Time
}

// OrderTTL is how long a client has to finalise.
const OrderTTL = time.Hour

// CreateACMEOrder records an order and its authorizations.
//
// Both born valid and ready. There is no challenge to wait for: control of the
// name was established when the host enrolled, so an order that arrived
// `pending` would be pending on nothing.
func (s *Store) CreateACMEOrder(
	ctx context.Context, accountID uuid.UUID, identifiers []string,
) (*ACMEOrder, error) {
	order := &ACMEOrder{
		AccountID: accountID, Status: "ready", Identifiers: identifiers,
	}

	err := s.InTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO acme_orders (account_id, status, identifiers, expires_at)
			VALUES ($1, 'ready', $2, now() + $3::interval)
			RETURNING id, expires_at`,
			accountID, identifiers, OrderTTL,
		).Scan(&order.ID, &order.ExpiresAt); err != nil {
			return fmt.Errorf("store: creating the order: %w", err)
		}

		for _, identifier := range identifiers {
			var authz ACMEAuthorization
			if err := tx.QueryRow(ctx, `
				INSERT INTO acme_authorizations (order_id, identifier, status, expires_at)
				VALUES ($1, $2, 'valid', now() + $3::interval)
				RETURNING id, identifier, status, expires_at`,
				order.ID, identifier, OrderTTL,
			).Scan(&authz.ID, &authz.Identifier, &authz.Status, &authz.ExpiresAt); err != nil {
				return fmt.Errorf("store: creating an authorization: %w", err)
			}
			order.Authorizations = append(order.Authorizations, authz)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return order, nil
}

// ACMEOrderByID reads an order and its authorizations.
func (s *Store) ACMEOrderByID(ctx context.Context, id uuid.UUID) (*ACMEOrder, error) {
	var order ACMEOrder
	err := s.pool.QueryRow(ctx, `
		SELECT id, account_id, status, identifiers, expires_at,
		       coalesce(certificate, ''::bytea), coalesce(serial, '')
		  FROM acme_orders WHERE id = $1`, id,
	).Scan(&order.ID, &order.AccountID, &order.Status, &order.Identifiers,
		&order.ExpiresAt, &order.Certificate, &order.Serial)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("store: no such order %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading the order: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, identifier, status, expires_at
		  FROM acme_authorizations WHERE order_id = $1 ORDER BY identifier`, id)
	if err != nil {
		return nil, fmt.Errorf("store: reading authorizations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var a ACMEAuthorization
		if err := rows.Scan(&a.ID, &a.Identifier, &a.Status, &a.ExpiresAt); err != nil {
			return nil, fmt.Errorf("store: scanning an authorization: %w", err)
		}
		order.Authorizations = append(order.Authorizations, a)
	}
	return &order, rows.Err()
}

// ACMEAuthorizationByID reads one authorization.
func (s *Store) ACMEAuthorizationByID(ctx context.Context, id uuid.UUID) (*ACMEAuthorization, uuid.UUID, error) {
	var (
		a       ACMEAuthorization
		orderID uuid.UUID
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, order_id, identifier, status, expires_at
		  FROM acme_authorizations WHERE id = $1`, id,
	).Scan(&a.ID, &orderID, &a.Identifier, &a.Status, &a.ExpiresAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, uuid.Nil, fmt.Errorf("store: no such authorization %s", id)
	}
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("store: reading the authorization: %w", err)
	}
	return &a, orderID, nil
}

// FinaliseACMEOrder records the issued certificate.
func (s *Store) FinaliseACMEOrder(
	ctx context.Context, orderID, caKeyID uuid.UUID, subjectID uuid.UUID,
	der []byte, serial string,
) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE acme_orders
			   SET status = 'valid', certificate = $2, ca_key_id = $3, serial = $4
			 WHERE id = $1 AND status = 'ready'`,
			orderID, der, caKeyID, serial)
		if err != nil {
			return fmt.Errorf("store: finalising the order: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Already finalised, or never ready. Either way the client should
			// re-read the order rather than be told this succeeded.
			return errors.New("store: the order is not ready to be finalised")
		}

		ev, err := event.New(event.ActionX509CertificateIssued, &subjectID, nil,
			map[string]any{"key_id": caKeyID})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}
