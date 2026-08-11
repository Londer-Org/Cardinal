package store_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// How much of the directory an application is told about.
//
// The behaviour these hold is a disclosure boundary, so the tests are about
// what an application can and cannot be told rather than about the shape of the
// tables underneath.

// TestANewApplicationStartsNarrow.
//
// Migration 0033 wrote `all` for every application that already existed, so an
// upgrade changes nothing; anything created afterwards starts owned. Both
// halves of that asymmetry matter, and only this half is reachable from Go.
func TestANewApplicationStartsNarrow(t *testing.T) {
	s := newStore(t)

	app := mustCreate(t, s, directory.TypeApplication, "billing")

	projection, err := s.GroupProjectionFor(t.Context(), app.ID)
	require.NoError(t, err)
	assert.Equal(t, store.ProjectionOwned, projection.Mode,
		"a newly created application should be narrow by default; wide is the "+
			"behaviour migration 0033 preserved for applications that predate it")
}

// TestAnApplicationSeesTheGroupsItOwns.
func TestAnApplicationSeesTheGroupsItOwns(t *testing.T) {
	s := newStore(t)

	app := mustCreate(t, s, directory.TypeApplication, "aura")
	owned := ownedGroup(t, s, "aura-admins", app.ID)
	somebodyElses := mustCreate(t, s, directory.TypeGroup, "hr-investigations")

	projection, err := s.GroupProjectionFor(t.Context(), app.ID)
	require.NoError(t, err)

	assert.True(t, projection.Visible[owned.ID], "an application should see a group it owns")
	assert.False(t, projection.Visible[somebodyElses.ID],
		"an application should not be told about a group that has nothing to do "+
			"with it — that is the disclosure this exists to stop")
}

// TestSightOfAnotherGroupIsGrantedExplicitly is the escape hatch.
func TestSightOfAnotherGroupIsGrantedExplicitly(t *testing.T) {
	s := newStore(t)

	app := mustCreate(t, s, directory.TypeApplication, "grafana")
	shared := mustCreate(t, s, directory.TypeGroup, "engineering")

	before, err := s.GroupProjectionFor(t.Context(), app.ID)
	require.NoError(t, err)
	require.False(t, before.Visible[shared.ID])

	require.NoError(t, s.AllowGroupSight(t.Context(), app.ID, shared.ID, nil))

	after, err := s.GroupProjectionFor(t.Context(), app.ID)
	require.NoError(t, err)
	assert.True(t, after.Visible[shared.ID])

	// And it can be taken back, which is the half that makes it administration
	// rather than a one-way door.
	require.NoError(t, s.DenyGroupSight(t.Context(), app.ID, shared.ID))
	revoked, err := s.GroupProjectionFor(t.Context(), app.ID)
	require.NoError(t, err)
	assert.False(t, revoked.Visible[shared.ID])
}

// TestASystemGroupIsNeverProjected.
//
// Membership of directory-admins is authority inside Cardinal. An application
// branching on it would be reading a Cardinal internal as though it were one of
// its own roles — and an application that could be *granted* sight of it would
// make that a supported integration.
func TestASystemGroupIsNeverProjected(t *testing.T) {
	s := newStore(t)

	app := mustCreate(t, s, directory.TypeApplication, "wiki")

	// Created here rather than relying on the seeded one: newStore truncates
	// every table, so migration 0008's directory-admins is not there.
	admins, err := directory.NewEntity(directory.TypeGroup, "directory-admins", "")
	require.NoError(t, err)
	require.NoError(t, s.CreateEntity(t.Context(), admins, nil))
	// Marked through the pool because nothing creates a system group at runtime:
	// the three that exist are written by migrations, which is the point of them.
	_, err = s.Pool().Exec(t.Context(),
		`UPDATE entities SET system = true WHERE id = $1`, admins.ID)
	require.NoError(t, err)

	err = s.AllowGroupSight(t.Context(), app.ID, admins.ID, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authority inside Cardinal")
}

// TestWideModeTellsAnApplicationEverything, because that is what every
// deployment had before this existed and what an upgrade must preserve.
func TestWideModeTellsAnApplicationEverything(t *testing.T) {
	s := newStore(t)

	app := mustCreate(t, s, directory.TypeApplication, "legacy")
	require.NoError(t, s.SetGroupProjection(t.Context(), app.ID, store.ProjectionAll, nil))

	projection, err := s.GroupProjectionFor(t.Context(), app.ID)
	require.NoError(t, err)
	assert.Equal(t, store.ProjectionAll, projection.Mode)
	assert.Empty(t, projection.Visible,
		"wide mode reads no set at all; a populated one here would mean the "+
			"filter had something to apply and might")
}

// TestAMissingRowFailsClosed.
//
// Every application created through the store gets a row, so absence means one
// failed to be written or was deleted by hand. The comment on
// GroupProjectionFor argues that such an application should see too little
// rather than too much — somebody reports the first and nobody notices the
// second — and this is what holds that, because the ordinary paths never reach
// it. Written after sabotaging the behaviour and finding the other tests
// unmoved.
func TestAMissingRowFailsClosed(t *testing.T) {
	s := newStore(t)

	app := mustCreate(t, s, directory.TypeApplication, "orphaned")
	_, err := s.Pool().Exec(t.Context(),
		`DELETE FROM application_group_projection WHERE entity_id = $1`, app.ID)
	require.NoError(t, err)

	projection, err := s.GroupProjectionFor(t.Context(), app.ID)
	require.NoError(t, err)
	assert.Equal(t, store.ProjectionOwned, projection.Mode,
		"an application with no projection row must see less rather than "+
			"everything: a disclosure control that fails open is not one")
}

// ownedGroup creates a group belonging to an application.
func ownedGroup(t *testing.T, s *store.Store, name string, owner uuid.UUID) *directory.Entity {
	t.Helper()
	e, err := directory.NewEntity(directory.TypeGroup, name, "")
	require.NoError(t, err)
	e.OwnerID = &owner
	require.NoError(t, s.CreateEntity(t.Context(), e, nil))
	return e
}
