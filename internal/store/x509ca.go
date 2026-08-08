package store

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/event"
)

// ErrNoX509CA means no authority key is signing.
var ErrNoX509CA = errors.New("store: no X.509 certificate authority is active")

// clockSkew is subtracted from a certificate's start time.
//
// A machine whose clock is a minute fast would otherwise reject a certificate
// issued for it seconds ago, and "not yet valid" is the confusing half of a
// clock problem — the error names the certificate rather than the clock.
const clockSkew = 5 * time.Minute

// X509CAKey is one authority key and the certificate that names it.
type X509CAKey struct {
	ID          uuid.UUID
	Algorithm   string
	Certificate *x509.Certificate

	// Chain is everything above this key, leaf-to-root, excluding this
	// certificate and excluding the root. Empty when this key is the root.
	Chain []*x509.Certificate

	Fingerprint string
	Subject     string
	NotBefore   time.Time
	NotAfter    time.Time

	ActiveAt  *time.Time
	RetiredAt *time.Time

	signer crypto.Signer
}

// Signing reports whether this key is the one issuing today.
func (k *X509CAKey) Signing() bool { return k.ActiveAt != nil && k.RetiredAt == nil }

// Signer is the private half.
//
// Nil unless the key was read with the encryption key — so a listing, which
// needs none of this, cannot accidentally hold a signing key in memory.
func (k *X509CAKey) Signer() crypto.Signer { return k.signer }

// DefaultRootValidity is how long a generated root lasts.
//
// Ten years. Long for anything Cardinal issues, and short for a root: the whole
// difficulty of an internal CA is getting the root into every trust store, and
// a root that expires during a period nobody is thinking about it is the
// failure that takes a fleet down at once. Rotation of the *signing* key is the
// frequent operation; this is the thing it hangs from.
const DefaultRootValidity = 10 * 365 * 24 * time.Hour

// CreateX509CAKey generates an authority key and its certificate.
//
// Created inactive, like the SSH authority and for the same reason: a key that
// signs before anything trusts it issues certificates every client rejects,
// which looks like Cardinal being broken rather than a procedure run backwards.
func (s *Store) CreateX509CAKey(
	ctx context.Context, encryptionKey, subject string, validity time.Duration,
	actorID *uuid.UUID,
) (*X509CAKey, error) {
	seal, err := newSealer(encryptionKey)
	if err != nil {
		return nil, err
	}
	if validity <= 0 {
		validity = DefaultRootValidity
	}

	// P-256 rather than Ed25519, which is the one place this diverges from the
	// SSH authority. Ed25519 X.509 is still refused by enough clients — older
	// OpenSSL, several JVMs, some load balancers — that choosing it would make
	// "why does this certificate not work" a support burden rather than a
	// preference. P-256 is universally accepted and has no parameters to
	// misconfigure.
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("store: generating X.509 CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("store: generating serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(validity),

		IsCA:                  true,
		BasicConstraintsValid: true,
		// One level. This authority signs leaves, and nothing below it may sign
		// anything — so a leaf whose key is stolen cannot become a CA.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		KeyUsage:       x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template,
		&private.PublicKey, private)
	if err != nil {
		return nil, fmt.Errorf("store: signing the authority certificate: %w", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("store: parsing the authority certificate: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("store: encoding the authority key: %w", err)
	}
	sealed, err := seal.seal(pkcs8)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(der)
	key := &X509CAKey{
		Algorithm:   "ecdsa-p256",
		Certificate: certificate,
		Fingerprint: hex.EncodeToString(sum[:]),
		Subject:     subject,
		NotBefore:   certificate.NotBefore,
		NotAfter:    certificate.NotAfter,
		signer:      private,
	}

	err = s.InTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO x509_ca_keys
				(algorithm, private_key_sealed, certificate, fingerprint,
				 subject, not_before, not_after)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id`,
			key.Algorithm, sealed, der, key.Fingerprint,
			subject, key.NotBefore, key.NotAfter,
		).Scan(&key.ID); err != nil {
			return fmt.Errorf("store: storing the authority key: %w", err)
		}

		ev, err := event.New(event.ActionX509CAKeyCreated, nil, actorID,
			map[string]any{"key_id": key.ID})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

// ActivateX509CAKey makes a key the one that signs, retiring whatever did.
func (s *Store) ActivateX509CAKey(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		// Retired first, because the partial unique index forbids two signing
		// keys and would otherwise reject this rather than sequence it.
		if _, err := tx.Exec(ctx, `
			UPDATE x509_ca_keys SET retired_at = now()
			 WHERE active_at IS NOT NULL AND retired_at IS NULL AND id <> $1`,
			id); err != nil {
			return fmt.Errorf("store: retiring the previous authority key: %w", err)
		}

		tag, err := tx.Exec(ctx, `
			UPDATE x509_ca_keys SET active_at = now(), retired_at = NULL
			 WHERE id = $1 AND not_after > now()`, id)
		if err != nil {
			return fmt.Errorf("store: activating the authority key: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s (or it has expired)", ErrNoX509CA, id)
		}

		ev, err := event.New(event.ActionX509CAKeyActivated, nil, actorID,
			map[string]any{"key_id": id})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// ActiveX509CAKey returns the key that signs, with its private half.
func (s *Store) ActiveX509CAKey(ctx context.Context, encryptionKey string) (*X509CAKey, error) {
	seal, err := newSealer(encryptionKey)
	if err != nil {
		return nil, err
	}

	var (
		key    X509CAKey
		sealed []byte
		der    []byte
		chain  [][]byte
	)
	err = s.pool.QueryRow(ctx, `
		SELECT id, algorithm, private_key_sealed, certificate, chain, fingerprint,
		       subject, not_before, not_after, active_at, retired_at
		  FROM x509_ca_keys
		 WHERE active_at IS NOT NULL AND retired_at IS NULL AND not_after > now()`,
	).Scan(&key.ID, &key.Algorithm, &sealed, &der, &chain, &key.Fingerprint,
		&key.Subject, &key.NotBefore, &key.NotAfter, &key.ActiveAt, &key.RetiredAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoX509CA
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading the authority key: %w", err)
	}

	plaintext, err := seal.open(sealed)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("store: parsing the authority key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("store: the stored authority key cannot sign")
	}
	key.signer = signer

	if key.Certificate, err = x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("store: parsing the authority certificate: %w", err)
	}
	for _, above := range chain {
		parsed, err := x509.ParseCertificate(above)
		if err != nil {
			return nil, fmt.Errorf("store: parsing an intermediate: %w", err)
		}
		key.Chain = append(key.Chain, parsed)
	}

	return &key, nil
}

// TrustedX509CAKeys returns every key a client should still trust.
//
// Including retired ones, which is the whole reason rotation works: a
// certificate issued minutes before a rotation is valid for its whole life, and
// a trust store that dropped the old key the moment it stopped signing would
// break every one of them.
func (s *Store) TrustedX509CAKeys(ctx context.Context) ([]*X509CAKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, algorithm, certificate, chain, fingerprint, subject,
		       not_before, not_after, active_at, retired_at
		  FROM x509_ca_keys
		 WHERE not_after > now()
		 ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: listing authority keys: %w", err)
	}
	defer rows.Close()

	var out []*X509CAKey
	for rows.Next() {
		var (
			key   X509CAKey
			der   []byte
			chain [][]byte
		)
		if err := rows.Scan(&key.ID, &key.Algorithm, &der, &chain, &key.Fingerprint,
			&key.Subject, &key.NotBefore, &key.NotAfter,
			&key.ActiveAt, &key.RetiredAt); err != nil {
			return nil, fmt.Errorf("store: scanning an authority key: %w", err)
		}
		if key.Certificate, err = x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("store: parsing an authority certificate: %w", err)
		}
		for _, above := range chain {
			parsed, err := x509.ParseCertificate(above)
			if err != nil {
				return nil, fmt.Errorf("store: parsing an intermediate: %w", err)
			}
			key.Chain = append(key.Chain, parsed)
		}
		out = append(out, &key)
	}
	return out, rows.Err()
}
