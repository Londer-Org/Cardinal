package store_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
)

// TestCreatingATokenReportsItsScopes.
//
// The first version set the column and left the returned struct's field empty,
// so `cardinal token create` printed a blank scope list for a token that had
// them — at the one moment somebody reads what they just made. Asserted on the
// value the caller receives rather than on a later read, because a later read
// was already correct while this was broken.
func TestCreatingATokenReportsItsScopes(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	owner := mustCreate(t, s, directory.TypeUser, "scripted")
	want := []string{"identity", "applications"}

	created, err := s.CreateAccessToken(ctx, owner.ID, "nightly", time.Hour, want, nil)
	require.NoError(t, err)
	assert.Equal(t, want, created.Scopes)
}

// TestAuthenticatingCarriesTheScopes.
//
// The scopes have to survive the round trip to be checkable at all: the
// middleware reads them off the session it builds from this, so a token that
// authenticated with an empty list would be refused everything it was issued
// for — and the refusal would name a scope the token visibly has.
func TestAuthenticatingCarriesTheScopes(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	owner := mustCreate(t, s, directory.TypeUser, "scripted")
	want := []string{"identity", "decisions"}

	created, err := s.CreateAccessToken(ctx, owner.ID, "reader", time.Hour, want, nil)
	require.NoError(t, err)

	authenticated, err := s.LookupAccessToken(ctx, created.Token)
	require.NoError(t, err)
	assert.Equal(t, want, authenticated.Scopes)

	// And again, because the second read takes a different branch: the first
	// updates last_used_at and returns from the UPDATE, the second is throttled
	// and falls through to a plain SELECT. Both scan the row, and only one of
	// them was written first.
	again, err := s.LookupAccessToken(ctx, created.Token)
	require.NoError(t, err)
	assert.Equal(t, want, again.Scopes,
		"the throttled read path returned different scopes from the first")
}

// TestListingCarriesTheScopes: the answer to "what is this token allowed to do"
// when deciding whether the one in a pipeline is the one that was meant.
func TestListingCarriesTheScopes(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	owner := mustCreate(t, s, directory.TypeUser, "scripted")
	want := []string{"applications"}

	_, err := s.CreateAccessToken(ctx, owner.ID, "deployer", time.Hour, want, nil)
	require.NoError(t, err)

	listed, err := s.ListAccessTokens(ctx, owner.ID)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, want, listed[0].Scopes)
}
