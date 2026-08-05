package store_test

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/breakglass"
	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBreakGlassHappyPath(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	kp, err := breakglass.Generate()
	require.NoError(t, err)
	pubConfig := breakglass.EncodePublic(kp.Public)

	challenge, err := s.IssueBreakGlassChallenge(ctx, netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)

	session, err := s.RedeemBreakGlassChallenge(ctx,
		challenge.Nonce, challenge.Sign(kp.Private), pubConfig, admin.ID)
	require.NoError(t, err)

	assert.True(t, session.Emergency(), "the session must be identifiable as emergency access")
	assert.False(t, session.Expired())
	assert.NotEmpty(t, session.Token)

	// Short by intent: break-glass exists to restore normal access, not to be
	// worked in.
	assert.InDelta(t, breakglass.SessionTTL.Seconds(),
		session.ValidUntil.Sub(session.ValidFrom).Seconds(), 2)

	t.Run("the session authenticates", func(t *testing.T) {
		got, err := s.LookupSession(ctx, session.Token)
		require.NoError(t, err)
		assert.Equal(t, session.ID, got.ID)
		assert.True(t, got.Emergency())
	})

	t.Run("use is recorded distinctly for alerting", func(t *testing.T) {
		var count int
		require.NoError(t, s.Pool().QueryRow(ctx,
			`SELECT count(*) FROM events WHERE action = 'breakglass.used'`).Scan(&count))
		assert.Equal(t, 1, count,
			"emergency access must be a distinct action, not buried in session.created")
	})
}

// TestBreakGlassChallengeIsSingleUse: a captured (challenge, signature) pair
// must be worthless. Without this, anyone who reads a terminal scrollback or a
// log could replay emergency access indefinitely.
func TestBreakGlassChallengeIsSingleUse(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	kp, _ := breakglass.Generate()
	pubConfig := breakglass.EncodePublic(kp.Public)

	challenge, err := s.IssueBreakGlassChallenge(ctx, netip.Addr{})
	require.NoError(t, err)
	signature := challenge.Sign(kp.Private)

	_, err = s.RedeemBreakGlassChallenge(ctx, challenge.Nonce, signature, pubConfig, admin.ID)
	require.NoError(t, err)

	_, err = s.RedeemBreakGlassChallenge(ctx, challenge.Nonce, signature, pubConfig, admin.ID)
	require.ErrorIs(t, err, store.ErrChallengeConsumed,
		"replaying a challenge with a valid signature must fail")
}

// TestBreakGlassWrongSignatureBurnsTheChallenge.
//
// A failed attempt consumes the challenge deliberately: an attacker guessing at
// signatures gets exactly one attempt per challenge, and every attempt leaves a
// record.
func TestBreakGlassWrongSignatureBurnsTheChallenge(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	real, _ := breakglass.Generate()
	attacker, _ := breakglass.Generate()
	pubConfig := breakglass.EncodePublic(real.Public)

	challenge, err := s.IssueBreakGlassChallenge(ctx, netip.Addr{})
	require.NoError(t, err)

	_, err = s.RedeemBreakGlassChallenge(ctx,
		challenge.Nonce, challenge.Sign(attacker.Private), pubConfig, admin.ID)
	require.ErrorIs(t, err, breakglass.ErrInvalidSignature)

	// Even the correct signature cannot rescue a burned challenge.
	_, err = s.RedeemBreakGlassChallenge(ctx,
		challenge.Nonce, challenge.Sign(real.Private), pubConfig, admin.ID)
	require.ErrorIs(t, err, store.ErrChallengeConsumed,
		"a failed attempt must burn the challenge, limiting attackers to one try each")
}

// TestBreakGlassConcurrentRedemption is why the challenge is consumed by a
// conditional UPDATE before the signature is verified.
//
// Verify-then-consume would leave a window in which several concurrent
// redemptions of one challenge all pass verification and all mint a session.
// Exactly one must win.
func TestBreakGlassConcurrentRedemption(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	kp, _ := breakglass.Generate()
	pubConfig := breakglass.EncodePublic(kp.Public)

	challenge, err := s.IssueBreakGlassChallenge(ctx, netip.Addr{})
	require.NoError(t, err)
	signature := challenge.Sign(kp.Private)

	const attempts = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		consumed  int
	)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.RedeemBreakGlassChallenge(ctx, challenge.Nonce, signature, pubConfig, admin.ID)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, store.ErrChallengeConsumed):
				consumed++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, succeeded, "exactly one concurrent redemption may succeed")
	assert.Equal(t, attempts-1, consumed)

	var sessions int
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE auth_method = 'break_glass'`).Scan(&sessions))
	assert.Equal(t, 1, sessions, "a single challenge must never mint two sessions")
}

func TestBreakGlassUnknownChallengeRejected(t *testing.T) {
	s := newStore(t)
	admin := mustCreate(t, s, directory.TypeUser, "admin")
	kp, _ := breakglass.Generate()

	_, err := s.RedeemBreakGlassChallenge(t.Context(),
		[]byte("a nonce that was never issued"), "AAAA",
		breakglass.EncodePublic(kp.Public), admin.ID)
	require.ErrorIs(t, err, store.ErrChallengeUnknown)
}

// TestPurgeKeepsConsumedChallenges: an unredeemed challenge is noise, but a
// consumed one is evidence that someone attempted emergency access.
func TestPurgeKeepsConsumedChallenges(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	kp, _ := breakglass.Generate()
	pubConfig := breakglass.EncodePublic(kp.Public)

	used, err := s.IssueBreakGlassChallenge(ctx, netip.Addr{})
	require.NoError(t, err)
	_, err = s.RedeemBreakGlassChallenge(ctx, used.Nonce, used.Sign(kp.Private), pubConfig, admin.ID)
	require.NoError(t, err)

	// An expired, never-redeemed challenge.
	stale, err := s.IssueBreakGlassChallenge(ctx, netip.Addr{})
	require.NoError(t, err)
	// Both timestamps move: the schema requires expires_at > issued_at, so
	// backdating only the expiry would violate the constraint.
	_, err = s.Pool().Exec(ctx, `
		UPDATE break_glass_challenges
		   SET issued_at  = now() - interval '2 hours',
		       expires_at = now() - interval '1 hour'
		 WHERE nonce = $1`, stale.Nonce)
	require.NoError(t, err)

	purged, err := s.PurgeExpiredChallenges(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1, purged)

	var consumedRemain int
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM break_glass_challenges WHERE consumed_at IS NOT NULL`).
		Scan(&consumedRemain))
	assert.Equal(t, 1, consumedRemain, "consumed challenges are evidence and must be kept")
}

// TestSessionRevocationIsEnforcedAtReadTime.
//
// NOTIFY is a hint, never a guarantee (ADR 0004). If revocation depended on
// cache invalidation, a dropped notification would become an authorization
// bypass rather than a latency problem.
func TestSessionRevocationIsEnforcedAtReadTime(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	kp, _ := breakglass.Generate()

	challenge, err := s.IssueBreakGlassChallenge(ctx, netip.Addr{})
	require.NoError(t, err)
	session, err := s.RedeemBreakGlassChallenge(ctx, challenge.Nonce,
		challenge.Sign(kp.Private), breakglass.EncodePublic(kp.Public), admin.ID)
	require.NoError(t, err)

	_, err = s.LookupSession(ctx, session.Token)
	require.NoError(t, err)

	require.NoError(t, s.RevokeSession(ctx, session.ID, &admin.ID))

	_, err = s.LookupSession(ctx, session.Token)
	require.ErrorIs(t, err, store.ErrSessionInvalid,
		"a revoked session must fail at lookup, independently of any cache")
}

func TestSessionTokenIsNotRecoverableFromTheDatabase(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	kp, _ := breakglass.Generate()
	challenge, _ := s.IssueBreakGlassChallenge(ctx, netip.Addr{})
	session, err := s.RedeemBreakGlassChallenge(ctx, challenge.Nonce,
		challenge.Sign(kp.Private), breakglass.EncodePublic(kp.Public), admin.ID)
	require.NoError(t, err)

	// Simulate an attacker who has read the sessions table.
	var stored []byte
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT token_hash FROM sessions WHERE id = $1`, session.ID).Scan(&stored))

	assert.NotContains(t, string(stored), session.Token,
		"the raw token must never be stored")
	_, err = s.LookupSession(ctx, string(stored))
	require.ErrorIs(t, err, store.ErrSessionInvalid,
		"the stored hash must not itself authenticate")
}

func TestExpiredSessionRejected(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	kp, _ := breakglass.Generate()
	challenge, _ := s.IssueBreakGlassChallenge(ctx, netip.Addr{})
	session, err := s.RedeemBreakGlassChallenge(ctx, challenge.Nonce,
		challenge.Sign(kp.Private), breakglass.EncodePublic(kp.Public), admin.ID)
	require.NoError(t, err)

	_, err = s.Pool().Exec(ctx, `
		UPDATE sessions
		   SET valid_period = tstzrange(now() - interval '2 hours', now() - interval '1 hour')
		 WHERE id = $1`, session.ID)
	require.NoError(t, err)

	_, err = s.LookupSession(ctx, session.Token)
	require.ErrorIs(t, err, store.ErrSessionInvalid)

	assert.True(t, (&store.Session{ValidUntil: time.Now().Add(-time.Minute)}).Expired())
}
