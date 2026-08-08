package store_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// hashOf is what the terminal sends through the browser: the hash of a secret
// it keeps.
func hashOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// parentSession stands in for the console: somebody signed in with a passkey.
func parentSession(t *testing.T, s *store.Store) *store.Session {
	t.Helper()
	user := mustCreate(t, s, directory.TypeUser, "alice")
	sess, err := s.CreateSession(t.Context(), user.ID, store.SessionSpec{
		AuthMethod:  "passkey",
		DeviceBound: true,
	})
	require.NoError(t, err)
	return sess
}

// TestATerminalInheritsTheCeremonyRatherThanSomethingWeaker.
//
// The reason this flow exists at all. Policy refuses an access token an SSH
// certificate (ADR 0018), correctly — so a terminal that received anything less
// than what the passkey proved would be unable to do the one thing it is for,
// and the tempting fix would have been to weaken the rule instead.
func TestATerminalInheritsTheCeremonyRatherThanSomethingWeaker(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	parent := parentSession(t, s)

	code, err := s.CreateCLIAuthorization(ctx, parent.ID, hashOf("secret"))
	require.NoError(t, err)

	issued, err := s.ClaimCLIAuthorization(ctx, code, "secret", store.SessionOrigin{})
	require.NoError(t, err)

	assert.True(t, issued.DeviceBound,
		"a terminal session that is not device-bound cannot obtain a certificate, "+
			"which is the only thing it exists to do")
	assert.Equal(t, parent.SubjectID, issued.SubjectID)
	assert.NotEqual(t, parent.Token, issued.Token,
		"the terminal must never receive the browser's own credential")

	_ = parent

	// And it is short. The certificate it fetches carries its own expiry from
	// that point, so a long-lived device-bound session in a terminal buys
	// nothing.
	assert.LessOrEqual(t, time.Until(issued.ValidUntil), store.CLISessionTTL+time.Second)
}

// TestTheInheritedSessionCarriesTheAgeOfTheCeremony.
//
// A rule demanding authentication within five minutes must not be satisfied by
// an approval clicked on top of a session from this morning.
//
// The parent is backdated deliberately. Asserting this against a session created
// moments earlier proves nothing at all — inheriting the timestamp and resetting
// it to now produce the same answer, and the first version of this test passed
// with the inheritance deleted.
func TestTheInheritedSessionCarriesTheAgeOfTheCeremony(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	parent := parentSession(t, s)

	// Four hours ago: well past any freshness rule, and still a live session.
	_, err := s.Pool().Exec(ctx,
		`UPDATE sessions SET auth_at = now() - interval '4 hours' WHERE id = $1`, parent.ID)
	require.NoError(t, err)

	code, err := s.CreateCLIAuthorization(ctx, parent.ID, hashOf("secret"))
	require.NoError(t, err)
	issued, err := s.ClaimCLIAuthorization(ctx, code, "secret", store.SessionOrigin{})
	require.NoError(t, err)

	age := time.Since(issued.AuthAt)
	assert.Greater(t, age, 3*time.Hour,
		"the terminal reports authenticating %s ago, but the ceremony it borrowed "+
			"was four hours old — a freshness rule would be satisfied by nothing", age)
}

// TestACodeIsWorthlessWithoutTheVerifier.
//
// The property that makes it safe to put the code in a redirect. Whoever reads
// it out of shell history, a proxy log or the address bar holds something they
// cannot exchange.
func TestACodeIsWorthlessWithoutTheVerifier(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	parent := parentSession(t, s)

	code, err := s.CreateCLIAuthorization(ctx, parent.ID, hashOf("the real secret"))
	require.NoError(t, err)

	_, err = s.ClaimCLIAuthorization(ctx, code, "a guess", store.SessionOrigin{})
	assert.ErrorIs(t, err, store.ErrCLIAuthNotFound)

	// And the failed attempt did not spend it: somebody guessing must not be
	// able to lock the legitimate terminal out of its own exchange.
	issued, err := s.ClaimCLIAuthorization(ctx, code, "the real secret", store.SessionOrigin{})
	require.NoError(t, err)
	assert.NotNil(t, issued)
}

// TestACodeIsSingleUse.
//
// Two terminals racing one code must not both win, and a code recovered from a
// log after the fact must be spent.
func TestACodeIsSingleUse(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	parent := parentSession(t, s)

	code, err := s.CreateCLIAuthorization(ctx, parent.ID, hashOf("secret"))
	require.NoError(t, err)

	_, err = s.ClaimCLIAuthorization(ctx, code, "secret", store.SessionOrigin{})
	require.NoError(t, err)

	_, err = s.ClaimCLIAuthorization(ctx, code, "secret", store.SessionOrigin{})
	assert.ErrorIs(t, err, store.ErrCLIAuthNotFound,
		"a spent code must not be exchangeable a second time")
}

// TestApprovingThenSigningOutLeavesNothingBehind.
//
// The parent session is read when the code is claimed, not when it is approved.
// Somebody who approves a terminal and then immediately signs out everywhere —
// which is what a person does when they realise they have approved the wrong
// thing — must not leave a code that still works.
func TestApprovingThenSigningOutLeavesNothingBehind(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	parent := parentSession(t, s)

	code, err := s.CreateCLIAuthorization(ctx, parent.ID, hashOf("secret"))
	require.NoError(t, err)

	require.NoError(t, s.RevokeSession(ctx, parent.ID, &parent.SubjectID))

	_, err = s.ClaimCLIAuthorization(ctx, code, "secret", store.SessionOrigin{})
	assert.ErrorIs(t, err, store.ErrCLIAuthNotFound,
		"revoking the session behind an approval must withdraw the approval with it")
}
