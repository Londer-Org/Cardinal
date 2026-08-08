package store

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/directory/event"
	"golang.org/x/crypto/ssh"
)

var (
	// ErrNoSSHCA means no key has been created yet. Distinct from a failure:
	// a directory that has not been asked to do host access legitimately has
	// no certificate authority.
	ErrNoSSHCA = errors.New("store: no SSH certificate authority key exists")

	// ErrNoActiveSSHCA means keys exist but none is signing. Reachable during a
	// rotation, between publishing a new key and activating it.
	ErrNoActiveSSHCA = errors.New("store: no SSH CA key is currently signing")
)

// SSHCAKey is one certificate authority key.
//
// Several may be trusted by the fleet at once — `TrustedUserCAKeys` takes a
// file of them — and exactly one signs. That is what makes rotation possible
// without touching every host twice in the same instant (ADR 0021).
type SSHCAKey struct {
	ID          uuid.UUID
	Algorithm   string
	PublicKey   string
	Fingerprint string

	CreatedAt  time.Time
	ActiveAt   *time.Time
	RetiredAt  *time.Time
	ValidUntil *time.Time

	// signer is populated only when the key was read for signing. Nothing
	// reads the private half otherwise, and nothing stores it in this struct
	// when listing.
	signer crypto.Signer
}

// Signing reports whether this key is the one currently issuing certificates.
func (k *SSHCAKey) Signing() bool { return k.ActiveAt != nil && k.RetiredAt == nil }

// Signer returns the key material, for the CA to sign with.
//
// Returns a crypto.Signer rather than the raw bytes, so that a future PKCS#11
// or KMS implementation slots in without anything above this changing — the
// interface is the decision, the storage is configuration (ADR 0021).
func (k *SSHCAKey) Signer() crypto.Signer { return k.signer }

// CreateSSHCAKey generates a key and stores it sealed.
//
// Created inactive on purpose. A key that starts signing the moment it exists
// would be issuing certificates the fleet does not yet trust, so publication
// comes first and activation second — which is the whole rotation procedure,
// enforced by making the unsafe order awkward rather than by documenting it.
func (s *Store) CreateSSHCAKey(ctx context.Context, encryptionKey string, actorID *uuid.UUID) (*SSHCAKey, error) {
	seal, err := newSealer(encryptionKey)
	if err != nil {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("store: generating SSH CA key: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("store: encoding SSH CA public key: %w", err)
	}

	sealed, err := seal.seal(priv)
	if err != nil {
		return nil, err
	}

	key := &SSHCAKey{
		Algorithm:   sshPub.Type(),
		PublicKey:   string(ssh.MarshalAuthorizedKey(sshPub)),
		Fingerprint: ssh.FingerprintSHA256(sshPub),
		signer:      priv,
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // a rollback after a successful commit returns ErrTxClosed

	err = tx.QueryRow(ctx, `
		INSERT INTO ssh_ca_keys (algorithm, private_key_sealed, public_key, fingerprint)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at`,
		key.Algorithm, sealed, key.PublicKey, key.Fingerprint,
	).Scan(&key.ID, &key.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: storing SSH CA key: %w", err)
	}

	ev, err := event.New(event.ActionSSHCAKeyCreated, nil, actorID,
		map[string]any{"key_id": key.ID})
	if err != nil {
		return nil, err
	}
	if err := s.AppendEvent(ctx, tx, ev); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("store: committing SSH CA key: %w", err)
	}
	return key, nil
}

// ActivateSSHCAKey makes a key the one that signs, retiring whichever did.
//
// One statement, so there is never an instant with two signing keys or none.
// The retired key keeps its place in the trusted set until `valid_until`,
// because certificates it signed are still being presented.
func (s *Store) ActivateSSHCAKey(
	ctx context.Context, keyID uuid.UUID, grace time.Duration, actorID *uuid.UUID,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // a rollback after a successful commit returns ErrTxClosed

	if _, execErr := tx.Exec(ctx, `
		UPDATE ssh_ca_keys
		   SET retired_at = now(), valid_until = now() + $1::interval
		 WHERE active_at IS NOT NULL AND retired_at IS NULL AND id <> $2`,
		grace, keyID); execErr != nil {
		return fmt.Errorf("store: retiring previous SSH CA key: %w", execErr)
	}

	tag, err := tx.Exec(ctx, `
		UPDATE ssh_ca_keys SET active_at = now()
		 WHERE id = $1 AND retired_at IS NULL`, keyID)
	if err != nil {
		return fmt.Errorf("store: activating SSH CA key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSSHCA
	}

	ev, err := event.New(event.ActionSSHCAKeyActivated, nil, actorID,
		map[string]any{"key_id": keyID})
	if err != nil {
		return err
	}
	if err := s.AppendEvent(ctx, tx, ev); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ActiveSSHCAKey returns the key that signs, with its private half.
func (s *Store) ActiveSSHCAKey(ctx context.Context, encryptionKey string) (*SSHCAKey, error) {
	seal, err := newSealer(encryptionKey)
	if err != nil {
		return nil, err
	}

	var (
		key    SSHCAKey
		sealed []byte
	)
	err = s.pool.QueryRow(ctx, `
		SELECT id, algorithm, private_key_sealed, public_key, fingerprint,
		       created_at, active_at, retired_at, valid_until
		  FROM ssh_ca_keys
		 WHERE active_at IS NOT NULL AND retired_at IS NULL`,
	).Scan(&key.ID, &key.Algorithm, &sealed, &key.PublicKey, &key.Fingerprint,
		&key.CreatedAt, &key.ActiveAt, &key.RetiredAt, &key.ValidUntil)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoActiveSSHCA
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading SSH CA key: %w", err)
	}

	raw, err := seal.open(sealed)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("store: SSH CA key is %d bytes, expected %d",
			len(raw), ed25519.PrivateKeySize)
	}
	key.signer = ed25519.PrivateKey(raw)
	return &key, nil
}

// TrustedSSHCAKeys returns every key hosts should currently trust.
//
// Includes retired keys whose grace period has not passed, which is the point:
// a host that trusts only the signing key would reject every certificate issued
// minutes before a rotation.
func (s *Store) TrustedSSHCAKeys(ctx context.Context) ([]SSHCAKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, algorithm, public_key, fingerprint,
		       created_at, active_at, retired_at, valid_until
		  FROM ssh_ca_keys
		 WHERE retired_at IS NULL OR valid_until > now()
		 ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: listing SSH CA keys: %w", err)
	}
	defer rows.Close()

	var out []SSHCAKey
	for rows.Next() {
		var k SSHCAKey
		if err := rows.Scan(&k.ID, &k.Algorithm, &k.PublicKey, &k.Fingerprint,
			&k.CreatedAt, &k.ActiveAt, &k.RetiredAt, &k.ValidUntil); err != nil {
			return nil, fmt.Errorf("store: scanning SSH CA key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SSHCertificateRecord is the fact that a certificate was issued.
type SSHCertificateRecord struct {
	Serial     uint64
	SubjectID  uuid.UUID
	HostID     *uuid.UUID
	Principals []string
	CAKeyID    uuid.UUID
	KeyID      string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

// RecordSSHCertificate stores that a certificate was issued, not the
// certificate.
//
// Keeping the certificate would create somewhere to steal one from, and it
// expires in minutes anyway. What an audit needs is who got what, for which
// host, and under which CA key — which is what this holds.
func (s *Store) RecordSSHCertificate(ctx context.Context, r *SSHCertificateRecord) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // a rollback after a successful commit returns ErrTxClosed

	if _, execErr := tx.Exec(ctx, `
		INSERT INTO ssh_certificates
			(serial, subject_id, host_id, principals, ca_key_id, key_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		//nolint:gosec // newSerial() shifts right by one, so this always fits
		int64(r.Serial), r.SubjectID, r.HostID, orEmpty(r.Principals),
		r.CAKeyID, r.KeyID, r.ExpiresAt); execErr != nil {
		return fmt.Errorf("store: recording SSH certificate: %w", execErr)
	}

	ev, err := event.New(event.ActionSSHCertificateIssued, &r.SubjectID, nil,
		map[string]any{"key_id": r.CAKeyID, "until": r.ExpiresAt})
	if err != nil {
		return err
	}
	if err := s.AppendEvent(ctx, tx, ev); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
