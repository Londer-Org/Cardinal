package store_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	return key
}

// TestHostEnrollmentIsSingleUse.
//
// The same property invitations have and for a stronger reason: an enrollment
// token that keeps working lets any machine that finds it claim to be a
// production host, and everything downstream — sudoers, POSIX identity,
// certificates for a name — trusts the answer to "which host is this".
func TestHostEnrollmentIsSingleUse(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")

	enrollment, err := s.CreateHostEnrollment(ctx, host.ID, nil)
	require.NoError(t, err)
	require.NotEmpty(t, enrollment.Token)

	cred, err := s.RedeemHostEnrollment(ctx, enrollment.Token, testKey(t), testIP)
	require.NoError(t, err)
	assert.Equal(t, host.ID, cred.HostID)
	assert.True(t, cred.Live)

	_, err = s.RedeemHostEnrollment(ctx, enrollment.Token, testKey(t), testIP)
	require.ErrorIs(t, err, store.ErrEnrollmentTokenInvalid,
		"a spent token must be worthless — otherwise a second machine can become this host")
}

// TestConcurrentHostEnrollment is why redemption is one statement.
//
// Two machines redeeming the same token would both hold a live credential for
// one host, and Cardinal could not tell which of them was the real one. The
// partial unique index would catch the duplicate fingerprint but not this: the
// keys differ, so nothing about the rows themselves is wrong.
func TestConcurrentHostEnrollment(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")
	enrollment, err := s.CreateHostEnrollment(ctx, host.ID, nil)
	require.NoError(t, err)

	const racers = 8
	keys := make([]ssh.PublicKey, racers)
	for i := range keys {
		keys[i] = testKey(t)
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	wg.Add(racers)
	for i := range racers {
		go func() {
			defer wg.Done()
			if _, redeemHostEnrollmentErr := s.RedeemHostEnrollment(ctx, enrollment.Token, keys[i], testIP); redeemHostEnrollmentErr == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, successes,
		"exactly one machine may become this host")

	creds, err := s.ListHostCredentials(ctx, host.ID)
	require.NoError(t, err)
	assert.Len(t, creds, 1)
}

// TestReEnrollingRetiresThePreviousKey.
//
// A rebuilt machine gets a new key. The old one must stop working the instant
// the new one starts, or a decommissioned disk pulled out of a bin still
// authenticates as a production host.
func TestReEnrollingRetiresThePreviousKey(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")

	first, err := s.CreateHostEnrollment(ctx, host.ID, nil)
	require.NoError(t, err)
	oldCred, err := s.RedeemHostEnrollment(ctx, first.Token, testKey(t), testIP)
	require.NoError(t, err)

	second, err := s.CreateHostEnrollment(ctx, host.ID, nil)
	require.NoError(t, err)
	newCred, err := s.RedeemHostEnrollment(ctx, second.Token, testKey(t), testIP)
	require.NoError(t, err)

	_, err = s.HostByCredential(ctx, oldCred.Fingerprint)
	require.ErrorIs(t, err, store.ErrHostCredentialUnknown,
		"the retired key must no longer authenticate")

	found, err := s.HostByCredential(ctx, newCred.Fingerprint)
	require.NoError(t, err)
	assert.Equal(t, host.ID, found.HostID)

	// The old row survives, so "which key made that request last month" stays
	// answerable. Erasing it would make the journal harder to read for no gain —
	// a public key is not personal data and reveals nothing on its own.
	creds, err := s.ListHostCredentials(ctx, host.ID)
	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.True(t, creds[0].Live, "live credentials sort first")
	assert.False(t, creds[1].Live)
}

// TestDisabledHostCannotAuthenticate.
//
// Disabling a host is the fast, reversible way to cut a compromised machine off.
// It has to be enough on its own — an operator reaching for it under pressure
// should not also have to remember to revoke credentials separately.
func TestDisabledHostCannotAuthenticate(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")
	enrollment, err := s.CreateHostEnrollment(ctx, host.ID, nil)
	require.NoError(t, err)
	cred, err := s.RedeemHostEnrollment(ctx, enrollment.Token, testKey(t), testIP)
	require.NoError(t, err)

	require.NoError(t, s.DisableEntity(ctx, host.ID, nil))

	_, err = s.HostByCredential(ctx, cred.Fingerprint)
	require.ErrorIs(t, err, store.ErrHostCredentialUnknown,
		"disabling a host must cut off the key it authenticates with")
}

// TestRedemptionNamesTheHost.
//
// The machine has to be told what it enrolled as. An operator running the join
// command at a console reads that line to confirm they ran it on the right box —
// and a blank there is worse than no line at all, because it looks like success.
func TestRedemptionNamesTheHost(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")
	enrollment, err := s.CreateHostEnrollment(ctx, host.ID, nil)
	require.NoError(t, err)

	cred, err := s.RedeemHostEnrollment(ctx, enrollment.Token, testKey(t), testIP)
	require.NoError(t, err)
	assert.Equal(t, "web-01.prod", cred.HostName)
}

// TestDisabledHostCannotEnroll.
//
// A token issued before an incident must stop working once the host is cut off.
// Checked at redemption rather than only afterwards, so the machine is told no
// instead of enrolling successfully and then failing every request it makes —
// which is the same outcome and takes an hour longer to understand.
//
// The other half of that WHERE clause, that a refusal here does not spend the
// token, is not asserted: the store has no way to re-enable an entity, so there
// is nothing to redeem it with afterwards. Worth having eventually, and a
// separate piece of work from this one.
func TestDisabledHostCannotEnroll(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	host := mustCreate(t, s, directory.TypeHost, "web-01.prod")
	enrollment, err := s.CreateHostEnrollment(ctx, host.ID, nil)
	require.NoError(t, err)

	require.NoError(t, s.DisableEntity(ctx, host.ID, nil))

	_, err = s.RedeemHostEnrollment(ctx, enrollment.Token, testKey(t), testIP)
	require.ErrorIs(t, err, store.ErrEnrollmentTokenInvalid)
}

// TestUnknownTokenIsRefused, and refused identically to every other failure.
func TestUnknownTokenIsRefused(t *testing.T) {
	s := newStore(t)

	_, err := s.RedeemHostEnrollment(t.Context(), "not-a-token", testKey(t), testIP)
	require.ErrorIs(t, err, store.ErrEnrollmentTokenInvalid)
}
