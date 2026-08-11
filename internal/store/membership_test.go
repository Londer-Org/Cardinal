package store_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/directory/temporal"
)

// TestOverlappingGrantsRejected is the invariant the whole temporal model rests
// on: two contradictory grants for the same pair cannot coexist. This is
// enforced by the WITHOUT OVERLAPS primary key, so it holds regardless of what
// application code does — including code written years from now by someone who
// hasn't read ADR 0001.
func TestOverlappingGrantsRejected(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	group := mustCreate(t, s, directory.TypeGroup, "prod-access")
	alice := mustCreate(t, s, directory.TypeUser, "alice")
	admin := mustCreate(t, s, directory.TypeUser, "admin")

	base := temporal.Grant{
		GroupID: group.ID, MemberID: alice.ID, GrantedBy: admin.ID,
		Period: temporal.Between(jan1, jun1),
		Reason: "incident #42",
	}
	require.NoError(t, s.Grant(ctx, base, &admin.ID))

	t.Run("overlapping period is rejected", func(t *testing.T) {
		overlapping := base
		overlapping.Period = temporal.Between(mar1, sep1)
		err := s.Grant(ctx, overlapping, &admin.ID)
		require.ErrorIs(t, err, temporal.ErrOverlappingGrant)
	})

	t.Run("adjacent period is accepted", func(t *testing.T) {
		// Half-open ranges mean [jan1, jun1) and [jun1, dec1) meet exactly
		// without overlapping. Revoking and re-granting at the same instant
		// must not conflict.
		adjacent := base
		adjacent.Period = temporal.Between(jun1, dec1)
		require.NoError(t, s.Grant(ctx, adjacent, &admin.ID))
	})

	t.Run("a different member may overlap in time", func(t *testing.T) {
		bob := mustCreate(t, s, directory.TypeUser, "bob")
		other := base
		other.MemberID = bob.ID
		other.Period = temporal.Between(mar1, sep1)
		require.NoError(t, s.Grant(ctx, other, &admin.ID))
	})
}

func TestSelfMembershipRejected(t *testing.T) {
	s := newStore(t)
	group := mustCreate(t, s, directory.TypeGroup, "recursive")

	err := s.Grant(t.Context(), temporal.Grant{
		GroupID: group.ID, MemberID: group.ID, GrantedBy: group.ID,
		Period: temporal.Forever(),
	}, nil)
	require.ErrorIs(t, err, temporal.ErrSelfMembership)
}

// TestRevocationPreservesHistory is the property that distinguishes Cardinal
// from a boolean membership model. Revoking access must not destroy the
// evidence that it was granted, by whom, or why.
func TestRevocationPreservesHistory(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	group := mustCreate(t, s, directory.TypeGroup, "prod-access")
	alice := mustCreate(t, s, directory.TypeUser, "alice")
	admin := mustCreate(t, s, directory.TypeUser, "admin")

	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: group.ID, MemberID: alice.ID, GrantedBy: admin.ID,
		Period: temporal.FromTime(jan1),
		Reason: "incident #42",
	}, &admin.ID))

	// The incident closed early.
	require.NoError(t, s.Revoke(ctx, group.ID, alice.ID, jun1, &admin.ID))

	history, err := s.GrantHistory(ctx, group.ID, alice.ID)
	require.NoError(t, err)
	require.Len(t, history, 1, "revocation must truncate the grant, not delete it")

	got := history[0]
	assert.Equal(t, jan1, got.Period.From.UTC())
	require.NotNil(t, got.Period.Until, "an open-ended grant must become bounded")
	assert.Equal(t, jun1, got.Period.Until.UTC())

	// The whole point: the audit trail outlives the access.
	assert.Equal(t, "incident #42", got.Reason)
	assert.Equal(t, admin.ID, got.GrantedBy)

	t.Run("point-in-time queries respect the revocation", func(t *testing.T) {
		before, err := s.IsMemberAt(ctx, alice.ID, group.ID, mar1)
		require.NoError(t, err)
		assert.True(t, before, "alice had access in March")

		after, err := s.IsMemberAt(ctx, alice.ID, group.ID, sep1)
		require.NoError(t, err)
		assert.False(t, after, "alice lost access in June")
	})
}

// TestRevokeMidPeriodSplitsTheRange exercises FOR PORTION OF's more surprising
// behaviour: revoking inside an existing period leaves the earlier portion
// intact rather than removing the whole grant.
func TestRevokeMidPeriodSplitsTheRange(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	group := mustCreate(t, s, directory.TypeGroup, "staging")
	alice := mustCreate(t, s, directory.TypeUser, "alice")

	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: group.ID, MemberID: alice.ID, GrantedBy: alice.ID,
		Period: temporal.Between(jan1, dec1),
	}, nil))

	require.NoError(t, s.Revoke(ctx, group.ID, alice.ID, jun1, nil))

	history, err := s.GrantHistory(ctx, group.ID, alice.ID)
	require.NoError(t, err)
	require.Len(t, history, 1)
	assert.Equal(t, jan1, history[0].Period.From.UTC())
	assert.Equal(t, jun1, history[0].Period.Until.UTC())
}

func TestRevokeNonexistentGrant(t *testing.T) {
	s := newStore(t)
	group := mustCreate(t, s, directory.TypeGroup, "empty")
	alice := mustCreate(t, s, directory.TypeUser, "alice")

	err := s.Revoke(t.Context(), group.ID, alice.ID, time.Now(), nil)
	require.ErrorIs(t, err, temporal.ErrNoSuchGrant)
}

// TestTransitiveResolution covers nested groups: alice → engineers → staff.
func TestTransitiveResolution(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	staff := mustCreate(t, s, directory.TypeGroup, "staff")
	engineers := mustCreate(t, s, directory.TypeGroup, "engineers")
	alice := mustCreate(t, s, directory.TypeUser, "alice")

	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: engineers.ID, MemberID: alice.ID, GrantedBy: alice.ID,
		Period: temporal.Forever(),
	}, nil))
	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: staff.ID, MemberID: engineers.ID, GrantedBy: alice.ID,
		Period: temporal.Forever(),
	}, nil))

	memberships, err := s.ResolveMemberships(ctx, alice.ID, time.Time{})
	require.NoError(t, err)
	require.Len(t, memberships, 2)

	assert.Equal(t, "engineers", memberships[0].GroupName)
	assert.True(t, memberships[0].Direct(), "engineers is a direct membership")

	assert.Equal(t, "staff", memberships[1].GroupName)
	assert.Equal(t, 2, memberships[1].Depth, "staff is inherited via engineers")
}

// TestExpiredLinkBreaksInheritance is the subtle one, and the most important
// test in this file. Inherited access must not outlive the membership that
// grants it: if alice's membership of engineers expires, her inherited access
// to staff must vanish even though engineers→staff is still valid.
//
// Getting this wrong would mean expired access silently persisting through
// nesting — an authorization bypass that no amount of direct-membership testing
// would reveal.
func TestExpiredLinkBreaksInheritance(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	staff := mustCreate(t, s, directory.TypeGroup, "staff")
	engineers := mustCreate(t, s, directory.TypeGroup, "engineers")
	alice := mustCreate(t, s, directory.TypeUser, "alice")

	// Alice is an engineer only for the first half of the year.
	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: engineers.ID, MemberID: alice.ID, GrantedBy: alice.ID,
		Period: temporal.Between(jan1, jun1),
	}, nil))
	// Engineers are staff indefinitely.
	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: staff.ID, MemberID: engineers.ID, GrantedBy: alice.ID,
		Period: temporal.FromTime(jan1),
	}, nil))

	inMarch, err := s.ResolveMemberships(ctx, alice.ID, mar1)
	require.NoError(t, err)
	assert.Len(t, inMarch, 2, "in March alice is an engineer and therefore staff")

	inSeptember, err := s.ResolveMemberships(ctx, alice.ID, sep1)
	require.NoError(t, err)
	assert.Empty(t, inSeptember,
		"once the engineers membership expired, inherited staff access must go too")
}

// TestDisabledGroupGrantsNothing: soft-deleting a group must stop it conferring
// access, even though its memberships still exist for audit purposes.
func TestDisabledGroupGrantsNothing(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	group := mustCreate(t, s, directory.TypeGroup, "deprecated")
	alice := mustCreate(t, s, directory.TypeUser, "alice")

	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: group.ID, MemberID: alice.ID, GrantedBy: alice.ID,
		Period: temporal.Forever(),
	}, nil))

	before, err := s.ResolveMemberships(ctx, alice.ID, time.Time{})
	require.NoError(t, err)
	require.Len(t, before, 1)

	require.NoError(t, s.DisableEntity(ctx, group.ID, nil))

	after, err := s.ResolveMemberships(ctx, alice.ID, time.Time{})
	require.NoError(t, err)
	assert.Empty(t, after, "a disabled group must confer nothing")
}

// TestCyclicGroupsTerminate: nothing stops A→B and B→A, and resolution must
// terminate rather than recursing forever. UNION's duplicate elimination is
// what guarantees this.
func TestCyclicGroupsTerminate(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	a := mustCreate(t, s, directory.TypeGroup, "group-a")
	b := mustCreate(t, s, directory.TypeGroup, "group-b")
	alice := mustCreate(t, s, directory.TypeUser, "alice")

	for _, g := range []temporal.Grant{
		{GroupID: a.ID, MemberID: b.ID},
		{GroupID: b.ID, MemberID: a.ID},
		{GroupID: a.ID, MemberID: alice.ID},
	} {
		g.GrantedBy = alice.ID
		g.Period = temporal.Forever()
		require.NoError(t, s.Grant(ctx, g, nil))
	}

	done := make(chan struct{})
	var memberships []temporal.Membership
	var err error
	go func() {
		defer close(done)
		memberships, err = s.ResolveMemberships(ctx, alice.ID, time.Time{})
	}()

	select {
	case <-done:
		require.NoError(t, err)
		assert.Len(t, memberships, 2, "alice reaches both groups, each exactly once")
	case <-time.After(10 * time.Second):
		t.Fatal("resolution did not terminate on a cyclic group graph")
	}
}

// TestConcurrentGrantsDoNotCorrupt hammers the same (group, member) pair from
// several goroutines with overlapping periods. Exactly one must win; the
// database must not end up holding two overlapping grants.
//
// The exclusion constraint prevents corruption on its own. What it does not
// cover is the retry and error classification around it, which is this
// package's own and is only observable under real concurrency.
func TestConcurrentGrantsDoNotCorrupt(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	group := mustCreate(t, s, directory.TypeGroup, "contended")
	alice := mustCreate(t, s, directory.TypeUser, "alice")

	const attempts = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		conflicts int
	)

	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Staggered starts, all overlapping the same window, so every pair
			// genuinely conflicts.
			from := jan1.AddDate(0, 0, i)
			err := s.Grant(ctx, temporal.Grant{
				GroupID: group.ID, MemberID: alice.ID, GrantedBy: alice.ID,
				Period: temporal.Between(from, dec1),
			}, nil)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, temporal.ErrOverlappingGrant):
				conflicts++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, succeeded, "exactly one concurrent grant may win")
	assert.Equal(t, attempts-1, conflicts, "every other attempt must be a clean conflict")

	history, err := s.GrantHistory(ctx, group.ID, alice.ID)
	require.NoError(t, err)
	assert.Len(t, history, 1, "the database must never hold overlapping grants")
}
