package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// signingKeyBits is 2048.
//
// RS256 with 2048-bit RSA is what every OIDC client library supports without
// negotiation. 4096 would be stronger and is not worth the interoperability
// risk here: the key rotates, and the tokens it signs live fifteen minutes.
const signingKeyBits = 2048

var (
	ErrNoSigningKey    = errors.New("store: no active signing key")
	ErrSealKeyMissing  = errors.New("store: signing key encryption key is not configured")
	ErrSealKeyMismatch = errors.New("store: signing key cannot be decrypted with the configured key")
)

// SigningKey signs ID tokens and JWT access tokens.
type SigningKey struct {
	ID        uuid.UUID
	KeyID     string
	Algorithm string

	Private *rsa.PrivateKey

	CreatedAt time.Time
	RetiredAt *time.Time
}

// sealer encrypts signing keys at rest.
//
// The encryption key comes from configuration, never the database — the same
// reasoning as the break-glass public key (ADR 0009). A database compromise
// alone therefore does not yield the ability to forge tokens for every
// application, which it would if the key were stored in the clear.
//
// This is an interim answer. Proper key management (KMS, HSM) remains an open
// question; what it buys today is that the attacker needs two things rather
// than one.
type sealer struct {
	aead cipher.AEAD
}

func newSealer(encryptionKey string) (*sealer, error) {
	if encryptionKey == "" {
		return nil, ErrSealKeyMissing
	}

	// The configured value is a passphrase of arbitrary length; SHA-256 gives
	// AES the 32 bytes it needs. Not a KDF, deliberately: this value is
	// generated, not chosen by a human, so it is not guessable and stretching
	// would only add startup latency.
	sum := sha256.Sum256([]byte(encryptionKey))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("store: creating cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("store: creating AEAD: %w", err)
	}
	return &sealer{aead: aead}, nil
}

func (s *sealer) seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("store: generating nonce: %w", err)
	}
	// Nonce prepended, so the ciphertext is self-describing and rotation of the
	// storage format does not need a separate column.
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *sealer) open(sealed []byte) ([]byte, error) {
	size := s.aead.NonceSize()
	if len(sealed) < size {
		return nil, ErrSealKeyMismatch
	}
	plaintext, err := s.aead.Open(nil, sealed[:size], sealed[size:], nil)
	if err != nil {
		// GCM authentication failing means the wrong key, or tampering. Both
		// warrant the same refusal, and neither should be papered over by
		// generating a fresh key — that would silently invalidate every token
		// and every client's trust in the JWKS.
		return nil, ErrSealKeyMismatch
	}
	return plaintext, nil
}

// NewSigningKey generates and stores a key.
func (s *Store) NewSigningKey(ctx context.Context, encryptionKey string) (*SigningKey, error) {
	seal, err := newSealer(encryptionKey)
	if err != nil {
		return nil, err
	}

	private, err := rsa.GenerateKey(rand.Reader, signingKeyBits)
	if err != nil {
		return nil, fmt.Errorf("store: generating signing key: %w", err)
	}

	sealed, err := seal.seal(x509.MarshalPKCS1PrivateKey(private))
	if err != nil {
		return nil, err
	}

	// The key ID is derived from the public key, so it is stable, verifiable
	// against the JWKS, and reveals nothing about when or why it was created.
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("store: encoding public key: %w", err)
	}
	sum := sha256.Sum256(publicDER)
	keyID := base64.RawURLEncoding.EncodeToString(sum[:16])

	key := &SigningKey{KeyID: keyID, Algorithm: "RS256", Private: private}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO oidc_signing_keys (key_id, algorithm, private_key_sealed, public_key)
		VALUES ($1, 'RS256', $2, $3)
		RETURNING id, created_at`,
		keyID, sealed, publicDER,
	).Scan(&key.ID, &key.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: storing signing key: %w", err)
	}
	return key, nil
}

// ActiveSigningKey returns the key currently used for signing.
func (s *Store) ActiveSigningKey(ctx context.Context, encryptionKey string) (*SigningKey, error) {
	seal, err := newSealer(encryptionKey)
	if err != nil {
		return nil, err
	}

	var (
		key    SigningKey
		sealed []byte
	)
	err = s.pool.QueryRow(ctx, `
		SELECT id, key_id, algorithm, private_key_sealed, created_at
		  FROM oidc_signing_keys
		 WHERE retired_at IS NULL
		 ORDER BY created_at DESC
		 LIMIT 1`,
	).Scan(&key.ID, &key.KeyID, &key.Algorithm, &sealed, &key.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoSigningKey
	}
	if err != nil {
		return nil, fmt.Errorf("store: loading signing key: %w", err)
	}

	plaintext, err := seal.open(sealed)
	if err != nil {
		return nil, err
	}
	private, err := x509.ParsePKCS1PrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("store: parsing signing key: %w", err)
	}
	key.Private = private
	return &key, nil
}

// VerificationKeys returns every key whose signatures should still verify.
//
// Retired keys stay here until they expire. Rotation removes a key from
// *signing* long before it stops *verifying*, or every token issued moments
// before the rotation would be rejected — which is how key rotation becomes an
// outage.
func (s *Store) VerificationKeys(ctx context.Context) ([]*SigningKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, key_id, algorithm, public_key, created_at, retired_at
		  FROM oidc_signing_keys
		 WHERE expires_at IS NULL OR expires_at > now()
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: listing verification keys: %w", err)
	}
	defer rows.Close()

	var out []*SigningKey
	for rows.Next() {
		var (
			key       SigningKey
			publicDER []byte
		)
		if err := rows.Scan(&key.ID, &key.KeyID, &key.Algorithm, &publicDER,
			&key.CreatedAt, &key.RetiredAt); err != nil {
			return nil, fmt.Errorf("store: scanning verification key: %w", err)
		}

		parsed, err := x509.ParsePKIXPublicKey(publicDER)
		if err != nil {
			return nil, fmt.Errorf("store: parsing public key %s: %w", key.KeyID, err)
		}
		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("store: key %s is not RSA", key.KeyID)
		}
		key.Private = &rsa.PrivateKey{PublicKey: *publicKey}
		out = append(out, &key)
	}
	return out, rows.Err()
}

// RotateSigningKey generates a new key and retires the current one.
//
// Retiring rather than deleting: the old key must keep verifying until the
// tokens it signed have expired. gracePeriod is how long that lasts, and should
// comfortably exceed the longest token lifetime.
func (s *Store) RotateSigningKey(ctx context.Context, encryptionKey string, gracePeriod time.Duration) (*SigningKey, error) {
	key, err := s.NewSigningKey(ctx, encryptionKey)
	if err != nil {
		return nil, err
	}

	if _, err := s.pool.Exec(ctx, `
		UPDATE oidc_signing_keys
		   SET retired_at = now(), expires_at = now() + $2::interval
		 WHERE retired_at IS NULL AND id <> $1`,
		key.ID, gracePeriod,
	); err != nil {
		return nil, fmt.Errorf("store: retiring previous signing key: %w", err)
	}
	return key, nil
}

// EnsureSigningKey returns the active key, generating one on first use.
func (s *Store) EnsureSigningKey(ctx context.Context, encryptionKey string) (*SigningKey, error) {
	key, err := s.ActiveSigningKey(ctx, encryptionKey)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, ErrNoSigningKey) {
		return nil, err
	}
	return s.NewSigningKey(ctx, encryptionKey)
}
