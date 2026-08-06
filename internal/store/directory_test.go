package store_test

import (
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/temporal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListUsersCountsWhatTheConsoleShows.
//
// The counts are the point: an account with no passkeys is one nobody can sign
// in to, and an administrator scanning a list needs to see that without opening
// each row.
func TestListUsersCountsWhatTheConsoleShows(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	mustCreate(t, s, directory.TypeUser, "bob")
	engineers := mustCreate(t, s, directory.TypeGroup, "engineers")

	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: engineers.ID, MemberID: alice.ID,
		Period: temporal.FromTime(time.Now()), GrantedBy: alice.ID,
	}, &alice.ID))

	issued, err := s.IssueInvitation(ctx, alice.ID, &alice.ID, 0)
	require.NoError(t, err)

	users, err := s.ListUsers(ctx)
	require.NoError(t, err)

	byLogin := map[string]int{}
	for _, u := range users {
		byLogin[u.Login] = u.Groups
		switch u.Login {
		case "alice":
			assert.Equal(t, 1, u.Groups)
			assert.True(t, u.InvitationPending, "an outstanding invitation must be visible")
			assert.False(t, u.FullyEnrolled(), "an account with no passkeys is not enrolled")
		case "bob":
			assert.Zero(t, u.Groups)
			assert.False(t, u.InvitationPending)
		}
	}
	require.Contains(t, byLogin, "alice")
	require.Contains(t, byLogin, "bob")

	// Redeeming clears the pending flag, so the list stops advertising a link
	// that no longer works.
	_, err = s.RedeemInvitation(ctx, issued.Token, testIP)
	require.NoError(t, err)

	users, err = s.ListUsers(ctx)
	require.NoError(t, err)
	for _, u := range users {
		if u.Login == "alice" {
			assert.False(t, u.InvitationPending, "a spent invitation is not pending")
		}
	}
}

// TestExpiredGrantsLeaveTheMemberList.
//
// The temporal model's whole claim: membership is a fact about a moment, not a
// flag. A grant that has run out must stop counting without anything running.
func TestExpiredGrantsLeaveTheMemberList(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	contractors := mustCreate(t, s, directory.TypeGroup, "contractors")

	// Started in the past and already over: no sleeping, and no cron job had a
	// chance to run, which is exactly the point.
	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID:  contractors.ID,
		MemberID: alice.ID,
		Period: temporal.Between(
			time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)),
		GrantedBy: alice.ID,
		Reason:    "a fortnight that ended",
	}, &alice.ID))

	members, err := s.MembersOfGroup(ctx, contractors.ID)
	require.NoError(t, err)
	assert.Empty(t, members, "an expired grant must not appear as membership")

	groups, err := s.ListGroups(ctx)
	require.NoError(t, err)
	for _, g := range groups {
		if g.Name == "contractors" {
			assert.Zero(t, g.Members, "the count must agree with the member list")
		}
	}
}

// TestMemberListResolvesNamesAndPeriods.
//
// The console shows people, not UUIDs, and an administrator deciding whether to
// revoke needs to see when a grant ends and why it was made.
func TestMemberListResolvesNamesAndPeriods(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	admin := mustCreate(t, s, directory.TypeUser, "admin")
	prod := mustCreate(t, s, directory.TypeGroup, "prod-access")

	until := time.Now().Add(14 * 24 * time.Hour)
	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: prod.ID, MemberID: alice.ID,
		Period:    temporal.Between(time.Now(), until),
		GrantedBy: admin.ID,
		Reason:    "incident 4412",
	}, &admin.ID))

	members, err := s.MembersOfGroup(ctx, prod.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)

	m := members[0]
	assert.Equal(t, "alice", m.MemberName)
	assert.Equal(t, "user", m.MemberType)
	assert.Equal(t, "prod-access", m.GroupName)
	assert.Equal(t, "admin", m.GrantedByAs, "who granted it must survive for the auditor")
	assert.Equal(t, "incident 4412", m.Reason)
	require.True(t, m.Expiring(), "a bounded grant must report its end")
	assert.WithinDuration(t, until, *m.Until, time.Second)

	// And from the other side.
	memberships, err := s.GroupsOfMember(ctx, alice.ID)
	require.NoError(t, err)
	require.Len(t, memberships, 1)
	assert.Equal(t, "prod-access", memberships[0].GroupName)

	// An unbounded grant reports no end rather than a sentinel date.
	other := mustCreate(t, s, directory.TypeGroup, "staff")
	require.NoError(t, s.Grant(ctx, temporal.Grant{
		GroupID: other.ID, MemberID: alice.ID,
		Period: temporal.FromTime(time.Now()), GrantedBy: admin.ID,
	}, &admin.ID))

	memberships, err = s.GroupsOfMember(ctx, alice.ID)
	require.NoError(t, err)
	for _, g := range memberships {
		if g.GroupName == "staff" {
			assert.False(t, g.Expiring())
			assert.Nil(t, g.Until, "unbounded must be nil, not a far-future date")
		}
	}
}
