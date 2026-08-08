package store_test

import (
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/temporal"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedactionErasesPersonalDataAndKeepsChainValid is the resolution of the
// tension between ADR 0003 (append-only, hash-chained) and GDPR Article 17.
//
// Erasure must remove the personal data while leaving the journal provable.
// If either half fails, the design fails: an unverifiable chain is not
// evidence, and an unerasable record is not lawful.
func TestRedactionErasesPersonalDataAndKeepsChainValid(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	group := mustCreate(t, s, directory.TypeGroup, "engineers")

	alice, err := directory.NewEntity(directory.TypeUser, "alonfils", "Arthur Lonfils")
	require.NoError(t, err)
	alice.Attrs = map[string]any{"employee_number": "12345"}
	require.NoError(t, s.CreateEntity(ctx, alice, nil))

	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: group.ID, MemberID: alice.ID, GrantedBy: alice.ID,
		Period: temporal.Between(jan1, dec1),
		Reason: "covering for Jan while he is off sick",
	}, nil))

	before, err := s.ValidateChain(ctx)
	require.NoError(t, err)
	require.True(t, before.Valid)

	require.NoError(t, s.RedactEntity(ctx, alice.ID, nil))

	t.Run("personal data is gone", func(t *testing.T) {
		got, err := s.GetEntity(ctx, alice.ID)
		require.NoError(t, err)

		assert.True(t, got.Redacted())
		assert.NotContains(t, got.Name, "alonfils", "the username must not survive")
		assert.Empty(t, got.DisplayName, "the display name must not survive")
		assert.Empty(t, got.Attrs, "extension attributes must not survive")

		history, err := s.GrantHistory(ctx, group.ID, alice.ID)
		require.NoError(t, err)
		require.Len(t, history, 1)
		assert.Empty(t, history[0].Reason,
			"free-text justifications attract personal data and must be cleared")
	})

	t.Run("the audit chain still validates", func(t *testing.T) {
		after, err := s.ValidateChain(ctx)
		require.NoError(t, err)
		assert.True(t, after.Valid, "reason: %s", after.Reason)
		assert.Greater(t, after.EventsChecked, before.EventsChecked,
			"the redaction itself must be audited")
	})

	t.Run("the shape of history survives", func(t *testing.T) {
		// This is the point of redacting rather than deleting: it remains
		// provable that *someone* held this access during this period, which
		// is what an auditor needs. Only the link to a person is severed.
		wasMember, err := s.IsMemberAt(ctx, alice.ID, group.ID, mar1)
		require.NoError(t, err)
		assert.True(t, wasMember,
			"membership history must survive erasure; only attribution is removed")
	})
}

// TestRedactionIsIrreversible: a reversible erasure is not an erasure.
func TestRedactionIsIrreversible(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alonfils")
	require.NoError(t, s.RedactEntity(ctx, alice.ID, nil))

	err := s.RedactEntity(ctx, alice.ID, nil)
	require.ErrorIs(t, err, directory.ErrNotFound,
		"a second redaction is a no-op, not a way to observe prior state")

	redacted, err := s.Redacted(ctx, alice.ID)
	require.NoError(t, err)
	assert.True(t, redacted)
}

// TestRedactionRemovesSessions: sessions carry IP addresses and user agents —
// personal data with no audit value once the account is erased. Unlike the
// journal, this table has no append-only rule, so the rows are deleted.
func TestRedactionRemovesSessions(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alonfils")

	_, err := s.Pool().Exec(ctx, `
		INSERT INTO sessions (subject_id, token_hash, valid_period,
		                      auth_method, client_ip, user_agent, absolute_expiry)
		VALUES ($1, $2, tstzrange(now(), now() + interval '1 hour'),
		        'passkey', '192.0.2.10', 'Mozilla/5.0', now() + interval '7 days')`,
		alice.ID, []byte("not-a-real-token-hash"))
	require.NoError(t, err)

	require.NoError(t, s.RedactEntity(ctx, alice.ID, nil))

	var remaining int
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE subject_id = $1`, alice.ID).Scan(&remaining))
	assert.Zero(t, remaining, "sessions hold IPs and user agents and must not survive erasure")
}

// TestRedactionConstraintCatchesIncompleteErasure: the database refuses to
// record an erasure that did not actually erase.
//
// Without this, an application bug could stamp redacted_at while leaving the
// data in place — producing a system that *reports* compliance it has not
// achieved, which is worse than one that fails honestly.
func TestRedactionConstraintCatchesIncompleteErasure(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice, err := directory.NewEntity(directory.TypeUser, "alonfils", "Arthur Lonfils")
	require.NoError(t, err)
	require.NoError(t, s.CreateEntity(ctx, alice, nil))

	_, err = s.Pool().Exec(ctx,
		`UPDATE entities SET redacted_at = $2 WHERE id = $1`, alice.ID, time.Now())
	require.Error(t, err,
		"marking an entity redacted without clearing its personal data must be rejected")
	assert.Contains(t, err.Error(), "entities_redaction_is_complete")
}

// TestTwoErasuresOfTheSameTypeBothSucceed.
//
// The tombstone has to be unique per type, and it used to be built from the
// first eight characters of the entity's id. For a UUIDv7 those are the high 32
// bits of a millisecond timestamp: they change roughly every seven weeks, so
// every entity of a type created in the same window shared them.
//
// The consequence was that the *second* erasure of a user failed on
// entities_name_unique_per_type — a GDPR request refused by a constraint
// violation, with nothing suggesting the reason. On a real directory the two
// people would almost certainly have been created within seven weeks of each
// other, so this was the common case rather than the corner.
//
// Two accounts created back to back is the whole test, which is the point: it
// needs no contrivance, and nothing had ever tried it.
func TestTwoErasuresOfTheSameTypeBothSucceed(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	first := mustCreate(t, s, directory.TypeUser, "first-to-go")
	second := mustCreate(t, s, directory.TypeUser, "second-to-go")

	require.NoError(t, s.RedactEntity(ctx, first.ID, nil))
	require.NoError(t, s.RedactEntity(ctx, second.ID, nil),
		"the second erasure of the same type must not collide with the first")

	// And the tombstones differ, which is what the constraint was protecting.
	var names []string
	rows, err := s.Pool().Query(ctx,
		`SELECT name FROM entities WHERE id = ANY($1)`,
		[]uuid.UUID{first.ID, second.ID})
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		names = append(names, name)
	}
	require.NoError(t, rows.Err())

	require.Len(t, names, 2)
	assert.NotEqual(t, names[0], names[1], "two erasures produced one tombstone")
	for _, name := range names {
		assert.NotContains(t, name, "first-to-go")
		assert.NotContains(t, name, "second-to-go")
	}
}
