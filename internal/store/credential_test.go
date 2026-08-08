package store_test

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// fakeCredential builds a credential as the WebAuthn library would hand it
// over. No real authenticator is needed to test the storage layer's rules.
func fakeCredential(id string, signCount uint32, backupEligible bool) *webauthn.Credential {
	c := &webauthn.Credential{
		ID:        []byte(id),
		PublicKey: []byte("cose-public-key-" + id),
	}
	c.Authenticator.SignCount = signCount
	c.Authenticator.AAGUID = []byte("aaguid-0123456789ab")
	c.Flags.BackupEligible = backupEligible
	c.Flags.BackupState = backupEligible
	return c
}

func TestRegisterAndListCredentials(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")

	first, err := s.RegisterCredential(ctx, alice.ID, fakeCredential("key-1", 0, true), "laptop")
	require.NoError(t, err)
	assert.True(t, first.Active())

	creds, err := s.CredentialsFor(ctx, alice.ID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "laptop", creds[0].Name)

	t.Run("registering the same credential twice is refused", func(t *testing.T) {
		_, err := s.RegisterCredential(ctx, alice.ID, fakeCredential("key-1", 0, true), "again")
		require.ErrorIs(t, err, store.ErrCredentialExists)
	})

	t.Run("the public key is all that is stored", func(t *testing.T) {
		// Unlike TOTP, nothing here can impersonate the user. Worth asserting,
		// because it is the reason passkeys beat shared secrets.
		var pub []byte
		require.NoError(t, s.Pool().QueryRow(ctx,
			`SELECT public_key FROM webauthn_credentials WHERE id = $1`,
			first.ID).Scan(&pub))
		assert.Contains(t, string(pub), "cose-public-key")
	})
}

// TestFullEnrollmentRequiresTwoCredentials: one passkey on one laptop is one
// theft away from an account nobody can reach. Requiring a second is what makes
// lockout rare rather than merely recoverable.
func TestFullEnrollmentRequiresTwoCredentials(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")

	enrolled, err := s.FullyEnrolled(ctx, alice.ID)
	require.NoError(t, err)
	assert.False(t, enrolled, "an account with no credentials is not enrolled")

	_, err = s.RegisterCredential(ctx, alice.ID, fakeCredential("key-1", 0, true), "laptop")
	require.NoError(t, err)

	enrolled, err = s.FullyEnrolled(ctx, alice.ID)
	require.NoError(t, err)
	assert.False(t, enrolled, "a single credential leaves the account one loss from lockout")

	_, err = s.RegisterCredential(ctx, alice.ID, fakeCredential("key-2", 0, false), "yubikey")
	require.NoError(t, err)

	enrolled, err = s.FullyEnrolled(ctx, alice.ID)
	require.NoError(t, err)
	assert.True(t, enrolled)
}

// TestCannotRevokeLastCredential: revoking the only remaining passkey turns a
// routine action into a lockout. Disabling the account is the honest operation
// for that intent, so the store refuses and says so.
func TestCannotRevokeLastCredential(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	only, err := s.RegisterCredential(ctx, alice.ID, fakeCredential("key-1", 0, true), "laptop")
	require.NoError(t, err)

	err = s.RevokeCredential(ctx, only.ID, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lock the account out")

	// With a second credential present, revoking the first is fine.
	_, err = s.RegisterCredential(ctx, alice.ID, fakeCredential("key-2", 0, false), "yubikey")
	require.NoError(t, err)
	require.NoError(t, s.RevokeCredential(ctx, only.ID, &alice.ID))

	creds, err := s.CredentialsFor(ctx, alice.ID)
	require.NoError(t, err)
	assert.Len(t, creds, 1, "a revoked credential must not appear as active")
}

// TestSignCountCloneDetection.
//
// The counter exists to detect a duplicated authenticator: a genuine device
// only increments. A counter that stalls or regresses means two things are
// presenting the same credential.
func TestSignCountCloneDetection(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	cred := fakeCredential("counting-key", 5, false)
	_, err := s.RegisterCredential(ctx, alice.ID, cred, "yubikey")
	require.NoError(t, err)

	t.Run("increasing counter is accepted", func(t *testing.T) {
		require.NoError(t, s.UpdateSignCount(ctx, cred.ID, 6))
	})

	t.Run("regressing counter is a clone", func(t *testing.T) {
		err := s.UpdateSignCount(ctx, cred.ID, 3)
		require.ErrorIs(t, err, store.ErrCloneDetected)
	})

	t.Run("a repeated counter is a clone or replay", func(t *testing.T) {
		err := s.UpdateSignCount(ctx, cred.ID, 6)
		require.ErrorIs(t, err, store.ErrCloneDetected)
	})

	t.Run("dropping to zero after counting is a clone", func(t *testing.T) {
		// A device that was counting does not stop. Zero here means something
		// else is presenting the credential.
		err := s.UpdateSignCount(ctx, cred.ID, 0)
		require.ErrorIs(t, err, store.ErrCloneDetected)
	})
}

// TestZeroSignCountIsNotSuspicious is the subtlety that matters most in this
// file.
//
// Most synced passkeys always report 0 — they do not implement counters at all.
// Treating that as a regression would lock out a large fraction of ordinary
// users on their second login, which is exactly the kind of security control
// that gets switched off wholesale.
func TestZeroSignCountIsNotSuspicious(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	cred := fakeCredential("synced-passkey", 0, true)
	_, err := s.RegisterCredential(ctx, alice.ID, cred, "phone")
	require.NoError(t, err)

	// Repeated authentication, counter always zero — normal, not a clone.
	for range 5 {
		require.NoError(t, s.UpdateSignCount(ctx, cred.ID, 0),
			"an authenticator that does not implement counters must not be "+
				"mistaken for a cloned one")
	}

	creds, err := s.CredentialsFor(ctx, alice.ID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.NotNil(t, creds[0].LastUsedAt, "use should still be recorded")
}

// TestBackupEligibilityIsRecorded: policy may require a hardware-bound key for
// privileged roles, so the distinction must survive registration.
func TestBackupEligibilityIsRecorded(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")

	synced, err := s.RegisterCredential(ctx, alice.ID, fakeCredential("synced", 0, true), "phone")
	require.NoError(t, err)
	hardware, err := s.RegisterCredential(ctx, alice.ID, fakeCredential("hw", 1, false), "yubikey")
	require.NoError(t, err)

	assert.True(t, synced.BackupEligible, "a synced passkey is recoverable but not hardware-bound")
	assert.False(t, hardware.BackupEligible, "a hardware key is device-bound and can satisfy AAL3")
}

func TestCredentialLookupByAuthenticatorID(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	cred := fakeCredential("lookup-me", 0, false)
	_, err := s.RegisterCredential(ctx, alice.ID, cred, "key")
	require.NoError(t, err)

	got, err := s.CredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, alice.ID, got.EntityID)

	_, err = s.CredentialByID(ctx, []byte("never-registered"))
	require.ErrorIs(t, err, store.ErrCredentialNotFound)
}
