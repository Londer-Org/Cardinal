package store_test

import (
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSealKey = "a-test-encryption-key-not-for-real-use"

// TestSigningKeyIsEncryptedAtRest is the property the whole arrangement exists
// for.
//
// The signing key can forge tokens for every registered application. Storing it
// in the clear would mean a database read is a complete compromise of every
// downstream system, which is a far worse outcome than losing the directory
// itself.
func TestSigningKeyIsEncryptedAtRest(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	key, err := s.NewSigningKey(ctx, testSealKey)
	require.NoError(t, err)

	var sealed []byte
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT private_key_sealed FROM oidc_signing_keys WHERE id = $1`,
		key.ID).Scan(&sealed))

	// PKCS#1 DER for an RSA private key starts with a SEQUENCE tag. Ciphertext
	// should not.
	assert.NotEqual(t, byte(0x30), sealed[0],
		"the stored key looks like unencrypted DER")

	t.Run("the wrong key cannot decrypt it", func(t *testing.T) {
		_, err := s.ActiveSigningKey(ctx, "a-different-encryption-key")
		require.ErrorIs(t, err, store.ErrSealKeyMismatch,
			"a database compromise alone must not yield the signing key")
	})

	t.Run("the right key round-trips", func(t *testing.T) {
		loaded, err := s.ActiveSigningKey(ctx, testSealKey)
		require.NoError(t, err)
		assert.Equal(t, key.KeyID, loaded.KeyID)
		assert.Equal(t, key.Private.N, loaded.Private.N)
	})
}

// TestMissingSealKeyIsRefused: silently generating an unencrypted key, or a
// fresh one, would be worse than failing — the first is insecure, the second
// invalidates every issued token.
func TestMissingSealKeyIsRefused(t *testing.T) {
	s := newStore(t)
	_, err := s.NewSigningKey(t.Context(), "")
	require.ErrorIs(t, err, store.ErrSealKeyMissing)
}

// TestTamperedKeyIsDetected: AES-GCM authenticates, so a modified ciphertext
// fails to open rather than decrypting to garbage.
func TestTamperedKeyIsDetected(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	key, err := s.NewSigningKey(ctx, testSealKey)
	require.NoError(t, err)

	_, err = s.Pool().Exec(ctx, `
		UPDATE oidc_signing_keys
		   SET private_key_sealed = private_key_sealed || '\x00'::bytea
		 WHERE id = $1`, key.ID)
	require.NoError(t, err)

	_, err = s.ActiveSigningKey(ctx, testSealKey)
	require.ErrorIs(t, err, store.ErrSealKeyMismatch)
}

// TestRotationKeepsVerifyingWithTheOldKey.
//
// Rotation removes a key from signing long before it stops verifying. Without
// that grace period, every token issued moments before a rotation would be
// rejected — which is how key rotation turns into an outage and then into
// something nobody does.
func TestRotationKeepsVerifyingWithTheOldKey(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	first, err := s.NewSigningKey(ctx, testSealKey)
	require.NoError(t, err)

	second, err := s.RotateSigningKey(ctx, testSealKey, time.Hour)
	require.NoError(t, err)
	assert.NotEqual(t, first.KeyID, second.KeyID)

	active, err := s.ActiveSigningKey(ctx, testSealKey)
	require.NoError(t, err)
	assert.Equal(t, second.KeyID, active.KeyID, "the new key signs")

	verification, err := s.VerificationKeys(ctx)
	require.NoError(t, err)

	ids := make([]string, 0, len(verification))
	for _, k := range verification {
		ids = append(ids, k.KeyID)
	}
	assert.Contains(t, ids, second.KeyID)
	assert.Contains(t, ids, first.KeyID,
		"the retired key must keep verifying until its tokens expire")
}

// TestKeyIDIsDerivedFromThePublicKey: stable, verifiable against the JWKS, and
// revealing nothing about when or why the key was created.
func TestKeyIDIsDerivedFromThePublicKey(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	key, err := s.NewSigningKey(ctx, testSealKey)
	require.NoError(t, err)

	assert.NotEmpty(t, key.KeyID)
	assert.NotContains(t, key.KeyID, key.ID.String(),
		"the key ID must not embed the database row ID")

	loaded, err := s.ActiveSigningKey(ctx, testSealKey)
	require.NoError(t, err)
	assert.Equal(t, key.KeyID, loaded.KeyID, "the key ID must be stable")
}

func TestEnsureSigningKeyIsIdempotent(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	first, err := s.EnsureSigningKey(ctx, testSealKey)
	require.NoError(t, err)

	second, err := s.EnsureSigningKey(ctx, testSealKey)
	require.NoError(t, err)

	assert.Equal(t, first.KeyID, second.KeyID,
		"a restart must not mint a new key, or every JWKS consumer re-fetches "+
			"and tokens signed moments earlier stop verifying")
}
