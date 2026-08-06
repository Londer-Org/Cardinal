package store_test

import (
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDisablingAClientRevokesWhatItHolds.
//
// Disabling the entity alone stops new authorizations, because OIDCClientByID
// excludes disabled entities. It would leave every issued token working until
// it expired — an application you have just retired continuing to reach your
// API for the next fortnight is not what anyone means by "disable".
func TestDisablingAClientRevokesWhatItHolds(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	registered, err := s.RegisterOIDCClient(ctx, store.RegisterClientInput{
		Name:         "retiring-app",
		AuthMethod:   store.AuthNone,
		RedirectURIs: []string{"https://retiring.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
	}, nil, nil)
	require.NoError(t, err)
	clientID := registered.Client.ClientID

	user := mustCreate(t, s, directory.TypeUser, "alice")
	require.NoError(t, s.RecordConsent(ctx, user.ID, clientID, []string{"openid"}))

	const refresh = "a-refresh-token-for-the-retiring-app"
	require.NoError(t, s.CreateToken(ctx, &store.Token{
		ClientID:  clientID,
		SubjectID: user.ID,
		Scopes:    []string{"openid", "profile"},
		AuthTime:  time.Now(),
		AMR:       []string{"hwk"},
		ExpiresAt: time.Now().Add(time.Hour),
	}, refresh))

	// A second application must be untouched, or disabling one thing would be
	// indistinguishable from an outage.
	other, err := s.RegisterOIDCClient(ctx, store.RegisterClientInput{
		Name:         "unaffected-app",
		AuthMethod:   store.AuthNone,
		RedirectURIs: []string{"https://unaffected.example.com/callback"},
		Scopes:       []string{"openid"},
	}, nil, nil)
	require.NoError(t, err)

	const otherRefresh = "a-refresh-token-for-the-other-app"
	require.NoError(t, s.CreateToken(ctx, &store.Token{
		ClientID:  other.Client.ClientID,
		SubjectID: user.ID,
		Scopes:    []string{"openid"},
		AuthTime:  time.Now(),
		AMR:       []string{"hwk"},
		ExpiresAt: time.Now().Add(time.Hour),
	}, otherRefresh))

	stats, err := s.StatsForClient(ctx, clientID)
	require.NoError(t, err)
	assert.Equal(t, 1, stats.ActiveTokens)
	assert.Equal(t, 1, stats.StandingGrants)
	require.NotNil(t, stats.LastIssuedAt)

	require.NoError(t, s.DisableOIDCClient(ctx, clientID, &user.ID))

	_, err = s.OIDCClientByID(ctx, clientID)
	require.ErrorIs(t, err, store.ErrClientNotFound,
		"a disabled application must not be able to start a new authorization")

	_, err = s.TokenByRefresh(ctx, refresh)
	require.Error(t, err, "the retired application's refresh token must die with it")

	covered, err := s.ConsentCovers(ctx, user.ID, clientID, []string{"openid"})
	require.NoError(t, err)
	assert.False(t, covered,
		"standing consent for a retired application must not survive to greet its replacement")

	survivor, err := s.TokenByRefresh(ctx, otherRefresh)
	require.NoError(t, err, "another application's tokens are not part of this decision")
	assert.Equal(t, other.Client.ClientID, survivor.ClientID)

	clients, err := s.ListOIDCClients(ctx)
	require.NoError(t, err)
	for _, c := range clients {
		assert.NotEqual(t, clientID, c.ClientID, "a disabled application must leave the list")
	}

	// Disabling twice is an error rather than a silent success, so a UI cannot
	// report retiring something that was already gone.
	require.Error(t, s.DisableOIDCClient(ctx, clientID, &user.ID))
}

// TestStatsForUnknownClientIsZeroNotAnError.
//
// Stats are read for display. A client with no tokens is the normal state of
// every freshly registered application, and erroring there would make the
// inspect view fail exactly when it has nothing interesting to say.
func TestStatsForUnknownClientIsZeroNotAnError(t *testing.T) {
	s := newStore(t)

	stats, err := s.StatsForClient(t.Context(), "no-such-client")
	require.NoError(t, err)
	assert.Zero(t, stats.ActiveTokens)
	assert.Zero(t, stats.StandingGrants)
	assert.Nil(t, stats.LastIssuedAt)
}
