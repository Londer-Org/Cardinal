package store_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// TestConsentCoversRequestedScopes.
//
// The question consent has to answer is not "has this user seen this
// application before" but "have they agreed to everything it is asking for
// now". An application that quietly widens its request must be asked again —
// that is the only moment where a second prompt carries any information.
func TestConsentCoversRequestedScopes(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")
	const client = "reporting-tool"

	covered, err := s.ConsentCovers(ctx, user.ID, client, []string{"openid"})
	require.NoError(t, err)
	assert.False(t, covered, "nothing has been agreed to yet")

	require.NoError(t, s.RecordConsent(ctx, user.ID, client,
		[]string{"openid", "profile"}))

	cases := []struct {
		name      string
		requested []string
		covered   bool
		because   string
	}{
		{
			name: "exactly what was agreed", requested: []string{"openid", "profile"},
			covered: true,
		},
		{
			name: "a subset", requested: []string{"openid"},
			covered: true,
			because: "asking for less than was agreed needs no new decision",
		},
		{
			name: "order does not matter", requested: []string{"profile", "openid"},
			covered: true,
		},
		{
			name: "one new scope", requested: []string{"openid", "profile", "email"},
			covered: false,
			because: "an application that widens its request must ask again",
		},
		{
			name: "an entirely different scope", requested: []string{"offline_access"},
			covered: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, consentCoversErr := s.ConsentCovers(ctx, user.ID, client, tc.requested)
			require.NoError(t, consentCoversErr)
			assert.Equal(t, tc.covered, got, tc.because)
		})
	}

	// Another user's agreement is not this user's.
	bob := mustCreate(t, s, directory.TypeUser, "bob")
	covered, err = s.ConsentCovers(ctx, bob.ID, client, []string{"openid"})
	require.NoError(t, err)
	assert.False(t, covered, "consent is per person, not per application")
}

// TestConsentScopesMerge.
//
// Agreeing to something new must not silently withdraw an earlier agreement the
// application is still relying on — that would log the user out of a feature
// they never asked to lose, with no event saying why.
func TestConsentScopesMerge(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")
	const client = "reporting-tool"

	require.NoError(t, s.RecordConsent(ctx, user.ID, client, []string{"openid", "profile"}))
	require.NoError(t, s.RecordConsent(ctx, user.ID, client, []string{"openid", "email"}))

	covered, err := s.ConsentCovers(ctx, user.ID, client,
		[]string{"openid", "profile", "email"})
	require.NoError(t, err)
	assert.True(t, covered, "the second agreement must widen the first, not replace it")

	consents, err := s.ConsentsFor(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, consents, 1, "widening an agreement must not create a second record")
	assert.ElementsMatch(t, []string{"openid", "profile", "email"}, consents[0].Scopes)
}

// TestRevokeConsentKillsTokens.
//
// Withdrawing consent while leaving live tokens behind would make the action
// meaningless for the rest of their lifetime: the application keeps working,
// which is exactly what the user just asked it not to do.
func TestRevokeConsentKillsTokens(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")
	const client = "reporting-tool"

	require.NoError(t, s.RecordConsent(ctx, user.ID, client, []string{"openid", "profile"}))

	const refresh = "a-refresh-token"
	token := &store.Token{
		ClientID:  client,
		SubjectID: user.ID,
		Scopes:    []string{"openid", "profile"},
		AuthTime:  time.Now(),
		AMR:       []string{"hwk"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, s.CreateToken(ctx, token, refresh))

	// A token issued to a different application must survive, or withdrawing
	// access to one thing would sign the user out of everything.
	other := &store.Token{
		ClientID:  "unrelated-app",
		SubjectID: user.ID,
		Scopes:    []string{"openid"},
		AuthTime:  time.Now(),
		AMR:       []string{"hwk"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	const otherRefresh = "another-refresh-token"
	require.NoError(t, s.CreateToken(ctx, other, otherRefresh))

	require.NoError(t, s.RevokeConsent(ctx, user.ID, client))

	covered, err := s.ConsentCovers(ctx, user.ID, client, []string{"openid"})
	require.NoError(t, err)
	assert.False(t, covered, "withdrawn consent must no longer cover anything")

	_, err = s.TokenByRefresh(ctx, refresh)
	require.Error(t, err, "the application's refresh token must die with the consent")

	survivor, err := s.TokenByRefresh(ctx, otherRefresh)
	require.NoError(t, err, "another application's token is not part of this decision")
	assert.Equal(t, "unrelated-app", survivor.ClientID)

	consents, err := s.ConsentsFor(ctx, user.ID)
	require.NoError(t, err)
	assert.Empty(t, consents, "a withdrawn agreement must leave the visible list")

	// Withdrawing something already withdrawn is an error rather than a silent
	// success, so a UI cannot report a revocation that did not happen.
	require.ErrorIs(t, s.RevokeConsent(ctx, user.ID, client), store.ErrConsentNotFound)
}

// TestConsentAfterRevocationStartsFresh.
//
// Re-granting must reset the record rather than resurrect the old scope list,
// otherwise "withdraw" would be a pause and the next agreement would silently
// carry scopes the user never saw the second time.
func TestConsentAfterRevocationStartsFresh(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")
	const client = "reporting-tool"

	require.NoError(t, s.RecordConsent(ctx, user.ID, client, []string{"openid", "profile"}))
	require.NoError(t, s.RevokeConsent(ctx, user.ID, client))
	require.NoError(t, s.RecordConsent(ctx, user.ID, client, []string{"openid"}))

	consents, err := s.ConsentsFor(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, consents, 1)
	assert.Equal(t, []string{"openid"}, consents[0].Scopes,
		"re-granting must not silently restore scopes from before the withdrawal")

	covered, err := s.ConsentCovers(ctx, user.ID, client, []string{"profile"})
	require.NoError(t, err)
	assert.False(t, covered)
}
