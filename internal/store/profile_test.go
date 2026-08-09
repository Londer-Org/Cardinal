package store_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

func ptr(s string) *string { return &s }

// TestUpdateProfileChangesOnlyWhatWasSent.
//
// ADR 0002 rests on names being mutable attributes rather than identifiers.
// Until UpdateProfile existed there was no UPDATE at all — entities could be
// created and disabled and nothing in between — so the claim was true of the
// schema and not of the software.
func TestUpdateProfileChangesOnlyWhatWasSent(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")

	updated, err := s.UpdateProfile(ctx, user.ID, store.ProfileUpdate{
		DisplayName: ptr("Alice Example"),
		Email:       ptr("alice@example.com"),
	}, &user.ID)
	require.NoError(t, err)
	assert.Equal(t, "Alice Example", updated.DisplayName)
	assert.Equal(t, "alice@example.com", updated.Attrs["email"])

	// A form that submits one field must not blank the other.
	updated, err = s.UpdateProfile(ctx, user.ID, store.ProfileUpdate{
		DisplayName: ptr("Alice E."),
	}, &user.ID)
	require.NoError(t, err)
	assert.Equal(t, "Alice E.", updated.DisplayName)
	assert.Equal(t, "alice@example.com", updated.Attrs["email"],
		"an untouched field must survive an update to another one")

	// The immutable identity is exactly that.
	assert.Equal(t, user.ID, updated.ID)
	assert.Equal(t, "alice", updated.Name, "UpdateProfile must never touch the login")

	// Empty string clears rather than storing "".
	updated, err = s.UpdateProfile(ctx, user.ID, store.ProfileUpdate{
		Email: ptr(""),
	}, &user.ID)
	require.NoError(t, err)
	_, present := updated.Attrs["email"]
	assert.False(t, present, "clearing an email must remove it, not store an empty string")
}

// TestUpdateProfileIsAudited, and audited without personal data.
//
// The journal is append-only, so anything written into a payload cannot later
// be deleted to satisfy an erasure request (ADR 0010). The record says which
// fields moved; the values live in the entities table, where erasure reaches.
func TestUpdateProfileIsAudited(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")
	_, err := s.UpdateProfile(ctx, user.ID, store.ProfileUpdate{
		DisplayName: ptr("Alice Example"),
	}, &user.ID)
	require.NoError(t, err)

	events, err := s.ListEvents(ctx, store.EventFilter{Subject: &user.ID}, 10)
	require.NoError(t, err)

	var found bool
	for _, ev := range events {
		if ev.Action != "entity.updated" {
			continue
		}
		found = true
		assert.Equal(t, true, ev.Payload["display_name_changed"])
		assert.Equal(t, false, ev.Payload["email_changed"])
		for _, value := range ev.Payload {
			assert.NotEqual(t, "Alice Example", value,
				"the new value must never enter the append-only journal")
		}
	}
	require.True(t, found, "a profile update must be recorded")
}

// TestUpdateProfileRefusesDisabledEntities.
func TestUpdateProfileRefusesDisabledEntities(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "alice")
	require.NoError(t, s.DisableEntity(ctx, user.ID, &user.ID))

	_, err := s.UpdateProfile(ctx, user.ID, store.ProfileUpdate{
		DisplayName: ptr("Should Not Apply"),
	}, &user.ID)
	require.Error(t, err, "a disabled account must not be editable")
}
