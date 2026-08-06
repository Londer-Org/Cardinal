package store_test

import (
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionSlidesWhileItIsUsed.
//
// A session should end because its holder stopped, not because of when they
// started. Before this, twelve hours ran from sign-in regardless of activity,
// so somebody halfway through a morning's work was signed out mid-task — and
// the only signal was the page they were on emptying itself.
func TestSessionSlidesWhileItIsUsed(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")

	// A short idle window, so the first lookup has something to extend.
	created, err := s.CreateSession(ctx, user.ID, store.SessionSpec{
		AuthMethod: "passkey", TTL: 2 * time.Minute, DeviceBound: true,
	})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(2*time.Minute), created.ValidUntil, time.Minute)

	used, err := s.LookupSession(ctx, created.Token)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(store.DefaultIdleSessionTTL), used.ValidUntil,
		time.Minute, "using a session must push its idle window forward")
	assert.Equal(t, created.ID, used.ID, "extending must not mint a new session")
}

// TestSessionIsNotRewrittenOnEveryRequest.
//
// The plan is explicit that writing on every request is how people make
// Postgres session storage slow and then blame Postgres. Extension happens only
// once the window has actually moved by more than a minute.
func TestSessionIsNotRewrittenOnEveryRequest(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")
	created, err := s.CreateSession(ctx, user.ID, store.SessionSpec{
		AuthMethod: "passkey", TTL: store.DefaultIdleSessionTTL,
	})
	require.NoError(t, err)

	first, err := s.LookupSession(ctx, created.Token)
	require.NoError(t, err)
	second, err := s.LookupSession(ctx, created.Token)
	require.NoError(t, err)

	assert.Equal(t, first.ValidUntil, second.ValidUntil,
		"a second lookup moments later must not rewrite the row")
}

// TestSessionCannotOutliveItsAbsoluteCap.
//
// Sliding expiry without a cap means a stolen token is valid indefinitely
// provided it is used. The cap is what makes "everyone re-authenticates
// eventually" true rather than aspirational.
func TestSessionCannotOutliveItsAbsoluteCap(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")

	created, err := s.CreateSession(ctx, user.ID, store.SessionSpec{
		AuthMethod:  "passkey",
		TTL:         time.Minute,
		AbsoluteTTL: 30 * time.Minute,
	})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(30*time.Minute), created.AbsoluteExpiry,
		time.Minute)

	used, err := s.LookupSession(ctx, created.Token)
	require.NoError(t, err)

	assert.False(t, used.ValidUntil.After(created.AbsoluteExpiry),
		"the idle window was pushed past the absolute cap, so the session could "+
			"be kept alive indefinitely by using it")
	assert.WithinDuration(t, created.AbsoluteExpiry, used.ValidUntil, time.Second,
		"it should extend right up to the cap rather than stopping short")
}

// TestDefaultSessionCarriesACap.
//
// A session created without one must not get an unbounded life by omission —
// that is the value the column exists to prevent.
func TestDefaultSessionCarriesACap(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")
	created, err := s.CreateSession(ctx, user.ID, store.SessionSpec{
		AuthMethod: "passkey", TTL: store.DefaultIdleSessionTTL,
	})
	require.NoError(t, err)

	assert.WithinDuration(t, time.Now().Add(store.DefaultAbsoluteSessionTTL),
		created.AbsoluteExpiry, time.Minute)
	assert.True(t, created.AbsoluteExpiry.After(created.ValidUntil),
		"the cap must sit beyond the idle window, or a session ends at sign-in")
}
