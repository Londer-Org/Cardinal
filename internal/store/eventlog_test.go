package store_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/temporal"
)

// TestAppendOnlyEnforcedByDatabase: the journal's immutability must not depend
// on application discipline. Rules in the schema make UPDATE and DELETE
// no-ops, so even a compromised application — or a careless migration — cannot
// rewrite history through the normal path.
func TestAppendOnlyEnforcedByDatabase(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	mustCreate(t, s, directory.TypeUser, "alice")

	var before int
	require.NoError(t, s.Pool().QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&before))
	require.Positive(t, before, "creating an entity must write an audit event")

	tag, err := s.Pool().Exec(ctx, `UPDATE events SET action = 'tampered'`)
	require.NoError(t, err)
	assert.Zero(t, tag.RowsAffected(), "UPDATE on the journal must affect no rows")

	tag, err = s.Pool().Exec(ctx, `DELETE FROM events`)
	require.NoError(t, err)
	assert.Zero(t, tag.RowsAffected(), "DELETE on the journal must affect no rows")

	var after int
	require.NoError(t, s.Pool().QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&after))
	assert.Equal(t, before, after, "the journal must be unchanged")

	report, err := s.ValidateChain(ctx)
	require.NoError(t, err)
	assert.True(t, report.Valid)
}

// TestChainValidatesAcrossManyEvents establishes the baseline: a journal built
// through normal operation validates cleanly.
func TestChainValidatesAcrossManyEvents(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	group := mustCreate(t, s, directory.TypeGroup, "engineers")
	admin := mustCreate(t, s, directory.TypeUser, "admin")

	for i := range 10 {
		u, err := directory.NewEntity(directory.TypeUser, userName(i), "")
		require.NoError(t, err)
		require.NoError(t, s.CreateEntity(ctx, u, &admin.ID))

		require.NoError(t, s.Grant(ctx, temporal.Grant{
			GroupID: group.ID, MemberID: u.ID, GrantedBy: admin.ID,
			Period: temporal.Forever(),
		}, &admin.ID))
	}

	report, err := s.ValidateChain(ctx)
	require.NoError(t, err)
	assert.True(t, report.Valid, "reason: %s", report.Reason)
	// 2 entities + 10 users + 10 grants
	assert.EqualValues(t, 22, report.EventsChecked)
}

// TestTamperingIsDetected is the property that makes the journal worth having.
//
// The rules block the normal write path, so tampering is simulated the way a
// real attacker would have to do it: with direct privileged access, bypassing
// the rules via ALTER TABLE ... DISABLE RULE. If the chain cannot catch that,
// it provides no assurance at all.
func TestTamperingIsDetected(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	for i := range 5 {
		u, err := directory.NewEntity(directory.TypeUser, userName(i), "")
		require.NoError(t, err)
		require.NoError(t, s.CreateEntity(ctx, u, &admin.ID))
	}

	report, err := s.ValidateChain(ctx)
	require.NoError(t, err)
	require.True(t, report.Valid, "chain must be sound before tampering")

	t.Run("modifying a record in place is detected", func(t *testing.T) {
		// Rules live on the partitioned parent; writes land in the partition,
		// so that is where they must be suspended.
		_, err := s.Pool().Exec(ctx, `ALTER TABLE events_2026 DISABLE RULE events_no_update`)
		if err != nil {
			// Rules are inherited rather than duplicated on partitions; fall
			// back to disabling on the parent.
			_, err = s.Pool().Exec(ctx, `ALTER TABLE events DISABLE RULE events_no_update`)
		}
		require.NoError(t, err)

		_, err = s.Pool().Exec(ctx,
			`UPDATE events SET action = 'entity.deleted'
			  WHERE seq = (SELECT min(seq) + 2 FROM events)`)
		require.NoError(t, err)

		report, err := s.ValidateChain(ctx)
		require.NoError(t, err)
		assert.False(t, report.Valid, "an altered record must break validation")
		assert.Contains(t, report.Reason, "modified")
		t.Logf("detected: %s", report.Reason)
	})
}

// TestDeletionIsDetected covers the other half: removing a record entirely.
// The survivors' prev_hash pointers no longer match their actual predecessor,
// which is precisely what the chain exists to reveal.
func TestDeletionIsDetected(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	for i := range 5 {
		u, err := directory.NewEntity(directory.TypeUser, userName(i), "")
		require.NoError(t, err)
		require.NoError(t, s.CreateEntity(ctx, u, &admin.ID))
	}

	_, err := s.Pool().Exec(ctx, `ALTER TABLE events_2026 DISABLE RULE events_no_delete`)
	if err != nil {
		_, err = s.Pool().Exec(ctx, `ALTER TABLE events DISABLE RULE events_no_delete`)
	}
	require.NoError(t, err)

	// Excise a record from the middle — the subtlest case, and the one a
	// naive "does every row hash correctly?" check would miss entirely.
	_, err = s.Pool().Exec(ctx,
		`DELETE FROM events WHERE seq = (SELECT min(seq) + 2 FROM events)`)
	require.NoError(t, err)

	report, err := s.ValidateChain(ctx)
	require.NoError(t, err)
	assert.False(t, report.Valid, "a deleted record must break validation")
	assert.Contains(t, report.Reason, "deleted or reordered")
	t.Logf("detected: %s", report.Reason)
}

func userName(i int) string {
	return "user-" + string(rune('a'+i))
}
