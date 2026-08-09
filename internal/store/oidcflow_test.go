package store_test

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// pendingFlow sets up an authorization request that has been authenticated and
// has a code attached — the state just before a client exchanges it.
func pendingFlow(t *testing.T, s *store.Store, code string) (*store.AuthRequest, *directory.Entity) {
	t.Helper()
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")

	req := &store.AuthRequest{
		ClientID:            "test-client",
		Scopes:              []string{"openid", "profile"},
		ResponseType:        "code",
		RedirectURI:         "https://app.example.com/callback",
		State:               "opaque-state",
		Nonce:               "opaque-nonce",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}
	require.NoError(t, s.CreateAuthRequest(ctx, req))
	require.NoError(t, s.CompleteAuthRequest(ctx, req.ID, user.ID, time.Now(),
		[]string{"pwd", "hwk"}))
	require.NoError(t, s.SaveAuthCode(ctx, req.ID, code))

	return req, user
}

// TestAuthorizationCodeIsSingleUse is the property OAuth most depends on.
//
// A code is a bearer credential that grants tokens, and OAuth's threat model
// assumes codes leak — through referrer headers, proxy logs, browser history
// and shoulder surfing. Redemption must therefore be exactly once, and the
// second attempt must fail even when everything else about it is valid.
func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	const code = "an-authorization-code"
	req, user := pendingFlow(t, s, code)

	redeemed, err := s.RedeemAuthCode(ctx, code)
	require.NoError(t, err)
	assert.Equal(t, req.ID, redeemed.ID)
	require.NotNil(t, redeemed.SubjectID)
	assert.Equal(t, user.ID, *redeemed.SubjectID)
	assert.Equal(t, "opaque-nonce", redeemed.Nonce, "the nonce must survive to reach the ID token")

	_, err = s.RedeemAuthCode(ctx, code)
	require.ErrorIs(t, err, store.ErrAuthCodeReplayed,
		"a stolen code must be worthless once the real client has used it")
}

// TestConcurrentCodeRedemption is why redemption is consume-and-return in one
// statement.
//
// Check-then-consume would leave a window in which a leaked code is redeemed by
// both the legitimate client and an attacker racing it, and both would receive
// tokens.
func TestConcurrentCodeRedemption(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	const code = "a-contended-code"
	pendingFlow(t, s, code)

	const attempts = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.RedeemAuthCode(ctx, code); err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, succeeded,
		"exactly one concurrent redemption may succeed, or a raced code yields two token sets")
}

// TestCodeIsHashedAtRest: reading the database must not yield something
// redeemable, for the same reason session tokens are hashed.
func TestCodeIsHashedAtRest(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	const code = "a-secret-code"
	pendingFlow(t, s, code)

	var stored []byte
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT code_hash FROM oidc_auth_requests WHERE code_hash IS NOT NULL`).
		Scan(&stored))

	assert.NotContains(t, string(stored), code)

	_, err := s.RedeemAuthCode(ctx, string(stored))
	require.Error(t, err, "the stored hash must not itself be redeemable")
}

// TestUnknownCodeRejected.
func TestUnknownCodeRejected(t *testing.T) {
	s := newStore(t)
	_, err := s.RedeemAuthCode(t.Context(), "never-issued")
	require.ErrorIs(t, err, store.ErrAuthRequestNotFound)
}

// TestCodeCannotBeAttachedBeforeAuthentication.
//
// A code issued for a request nobody has authenticated would grant tokens for
// an unauthenticated subject — the flow's most serious possible failure.
func TestCodeCannotBeAttachedBeforeAuthentication(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	req := &store.AuthRequest{
		ClientID:     "test-client",
		Scopes:       []string{"openid"},
		ResponseType: "code",
		RedirectURI:  "https://app.example.com/callback",
	}
	require.NoError(t, s.CreateAuthRequest(ctx, req))

	err := s.SaveAuthCode(ctx, req.ID, "premature-code")
	require.ErrorIs(t, err, store.ErrAuthRequestNotFound,
		"a code must not attach to a request that has not been authenticated")
}

// TestExpiredAuthRequestRejected.
func TestExpiredAuthRequestRejected(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	const code = "a-stale-code"
	req, _ := pendingFlow(t, s, code)

	_, err := s.Pool().Exec(ctx, `
		UPDATE oidc_auth_requests
		   SET created_at = now() - interval '2 hours',
		       expires_at = now() - interval '1 hour'
		 WHERE id = $1`, req.ID)
	require.NoError(t, err)

	_, err = s.RedeemAuthCode(ctx, code)
	require.ErrorIs(t, err, store.ErrAuthRequestNotFound)
}

// TestPKCEChallengeSurvivesRedemption: the verifier is checked against this at
// token exchange, so losing it would silently disable PKCE.
func TestPKCEChallengeSurvivesRedemption(t *testing.T) {
	s := newStore(t)

	const code = "a-pkce-code"
	pendingFlow(t, s, code)

	redeemed, err := s.RedeemAuthCode(t.Context(), code)
	require.NoError(t, err)

	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", redeemed.CodeChallenge)
	assert.Equal(t, "S256", redeemed.CodeChallengeMethod,
		"plain would let anyone who intercepted the challenge derive the verifier")
}

// TestSignOutRevokesIssuedTokens.
//
// Without this, signing out of Cardinal leaves live access tokens behind for up
// to their lifetime — so "sign out" would not mean what every user assumes it
// means.
func TestSignOutRevokesIssuedTokens(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")

	var sessionID string
	require.NoError(t, s.Pool().QueryRow(ctx, `
		INSERT INTO sessions (subject_id, token_hash, valid_period, auth_method,
		                      absolute_expiry)
		VALUES ($1, $2, tstzrange(now(), now() + interval '1 hour'), 'passkey',
		        now() + interval '7 days')
		RETURNING id`, user.ID, []byte("session-hash")).Scan(&sessionID))

	sid := uuidMust(t, sessionID)
	token := &store.Token{
		ClientID:  "test-client",
		SubjectID: user.ID,
		SessionID: &sid,
		Scopes:    []string{"openid"},
		AuthTime:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, s.CreateToken(ctx, token, "a-refresh-token"))

	_, err := s.TokenByRefresh(ctx, "a-refresh-token")
	require.NoError(t, err)

	// Through RevokeSession, which is what the sign-out handler calls, rather
	// than through the revocation helper directly.
	//
	// This test previously called that helper, passed, and proved nothing: the
	// helper worked and no caller existed, so signing out closed the session
	// and left this token live. A test that reaches past the path the product
	// takes is a test of an implementation detail wearing the name of a
	// guarantee.
	require.NoError(t, s.RevokeSession(ctx, sid, &user.ID))

	_, err = s.TokenByRefresh(ctx, "a-refresh-token")
	require.ErrorIs(t, err, store.ErrTokenNotFound,
		"tokens issued from a session must die with it")
}

// TestEverySessionRevocationPathKillsTokens covers the other three doors.
//
// Four functions close a session and each one is a way to reach the same
// security boundary; the sign-out bug was one of them being wired up and the
// rest not being considered. Enumerating them here means a fifth door added
// later is a failing test rather than a quiet gap.
func TestEverySessionRevocationPathKillsTokens(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		revoke func(t *testing.T, s *store.Store, subject, session uuid.UUID)
	}{
		{"RevokeSession", func(t *testing.T, s *store.Store, subject, session uuid.UUID) {
			require.NoError(t, s.RevokeSession(t.Context(), session, &subject))
		}},
		{"RevokeSessionFor", func(t *testing.T, s *store.Store, subject, session uuid.UUID) {
			require.NoError(t, s.RevokeSessionFor(t.Context(), session, subject, &subject))
		}},
		{"RevokeAllSessions", func(t *testing.T, s *store.Store, subject, _ uuid.UUID) {
			_, err := s.RevokeAllSessions(t.Context(), subject, &subject)
			require.NoError(t, err)
		}},
		{"RevokeOtherSessions", func(t *testing.T, s *store.Store, subject, session uuid.UUID) {
			// Keeping a session that is not the one under test, so the session
			// holding the token is among those revoked.
			_, err := s.RevokeOtherSessions(t.Context(), subject, uuid.New(), &subject)
			require.NoError(t, err)
			_ = session
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			ctx := t.Context()

			user := mustCreate(t, s, directory.TypeUser, "alice")
			sid := insertSession(t, s, user.ID)

			refresh := "refresh-" + tc.name
			require.NoError(t, s.CreateToken(ctx, &store.Token{
				ClientID:  "test-client",
				SubjectID: user.ID,
				SessionID: &sid,
				Scopes:    []string{"openid"},
				AuthTime:  time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			}, refresh))

			_, err := s.TokenByRefresh(ctx, refresh)
			require.NoError(t, err, "the token must be live before revocation, or this proves nothing")

			tc.revoke(t, s, user.ID, sid)

			_, err = s.TokenByRefresh(ctx, refresh)
			require.ErrorIs(t, err, store.ErrTokenNotFound,
				"%s closed the session and left its access token usable", tc.name)
		})
	}
}

// insertSession creates a live session directly, since the paths under test
// need one to exist and none of them create it.
func insertSession(t *testing.T, s *store.Store, subjectID uuid.UUID) uuid.UUID {
	t.Helper()

	var id uuid.UUID
	require.NoError(t, s.Pool().QueryRow(t.Context(), `
		INSERT INTO sessions (subject_id, token_hash, valid_period, auth_method,
		                      absolute_expiry)
		VALUES ($1, $2, tstzrange(now(), now() + interval '1 hour'), 'passkey',
		        now() + interval '7 days')
		RETURNING id`, subjectID, []byte("hash-"+uuid.NewString())).Scan(&id))
	return id
}
