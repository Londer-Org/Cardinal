package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
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

	users, total, err := s.ListUsers(ctx, store.Page{})
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
	assert.Equal(t, len(users), total, "an unpaged listing must report its own size")

	// Redeeming clears the pending flag, so the list stops advertising a link
	// that no longer works.
	_, err = s.RedeemInvitation(ctx, issued.Token, testIP)
	require.NoError(t, err)

	users, _, err = s.ListUsers(ctx, store.Page{})
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

	groups, _, err := s.ListGroups(ctx, store.Page{})
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

// TestListUsersPagesAndSearches.
//
// Client-side paging over a full payload still ships every row, which misses
// the point of paginating a directory that grows. So the page is a real one,
// and the total is what lets a console say "25 of 412" rather than only showing
// what it was handed.
func TestListUsersPagesAndSearches(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	for _, name := range []string{"anna", "bob", "carol", "dave", "erin"} {
		mustCreate(t, s, directory.TypeUser, name)
	}

	first, total, err := s.ListUsers(ctx, store.Page{Limit: 2})
	require.NoError(t, err)
	require.Len(t, first, 2)
	assert.Equal(t, 5, total, "the total must count everything, not the page")
	assert.Equal(t, "anna", first[0].Login, "ordering must be stable across pages")

	second, _, err := s.ListUsers(ctx, store.Page{Limit: 2, Offset: 2})
	require.NoError(t, err)
	require.Len(t, second, 2)
	assert.Equal(t, "carol", second[0].Login)

	last, _, err := s.ListUsers(ctx, store.Page{Limit: 2, Offset: 4})
	require.NoError(t, err)
	assert.Len(t, last, 1, "the final page is short, not empty")

	beyond, _, err := s.ListUsers(ctx, store.Page{Limit: 2, Offset: 99})
	require.NoError(t, err)
	assert.Empty(t, beyond, "reading past the end is empty, not an error")

	// Search narrows the total too, or the console would report a count that
	// disagrees with what it is showing.
	found, foundTotal, err := s.ListUsers(ctx, store.Page{Search: "ar"})
	require.NoError(t, err)
	assert.Equal(t, foundTotal, len(found))
	logins := make([]string, 0, len(found))
	for _, u := range found {
		logins = append(logins, u.Login)
	}
	assert.ElementsMatch(t, []string{"carol"}, logins)

	// A prefix must match, because an administrator typing "ann" expects anna.
	prefix, _, err := s.ListUsers(ctx, store.Page{Search: "ann"})
	require.NoError(t, err)
	require.Len(t, prefix, 1)
	assert.Equal(t, "anna", prefix[0].Login)
}

// TestUnboundedListingIsStillPaged.
//
// A caller asking for everything gets a page anyway: an unbounded list endpoint
// is a denial of service with a friendly name.
func TestUnboundedListingIsStillPaged(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	for i := range 40 {
		mustCreate(t, s, directory.TypeUser, fmt.Sprintf("user-%02d", i))
	}

	users, total, err := s.ListUsers(ctx, store.Page{Limit: 0})
	require.NoError(t, err)
	assert.Equal(t, 40, total)
	assert.LessOrEqual(t, len(users), 25, "a limit of zero must not mean no limit")

	huge, _, err := s.ListUsers(ctx, store.Page{Limit: 100_000})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(huge), 25, "an absurd limit must be clamped")
}
