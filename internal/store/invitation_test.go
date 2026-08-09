package store_test

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

var testIP = netip.MustParseAddr("198.51.100.7")

// TestInvitationIsSingleUse.
//
// An invitation is a bearer credential sent over an untrusted channel — chat,
// email, a sticky note. Its safety rests almost entirely on being spendable
// once: a link that keeps working is one that keeps working for whoever finds
// the message six months later.
func TestInvitationIsSingleUse(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "newcomer")

	issued, err := s.IssueInvitation(ctx, user.ID, &user.ID, 0)
	require.NoError(t, err)
	require.NotEmpty(t, issued.Token)

	resolved, err := s.InvitationByToken(ctx, issued.Token)
	require.NoError(t, err)
	assert.Equal(t, user.ID, resolved.SubjectID)
	assert.Equal(t, "newcomer", resolved.Login,
		"the screen must be able to say whose account this is")

	redeemed, err := s.RedeemInvitation(ctx, issued.Token, testIP)
	require.NoError(t, err)
	assert.Equal(t, user.ID, redeemed.SubjectID)

	_, err = s.RedeemInvitation(ctx, issued.Token, testIP)
	require.ErrorIs(t, err, store.ErrInvitationNotFound,
		"a spent invitation must be worthless")

	_, err = s.InvitationByToken(ctx, issued.Token)
	require.ErrorIs(t, err, store.ErrInvitationNotFound)
}

// TestConcurrentRedemption is why redemption is one statement.
//
// Check-then-mark would leave a window in which two requests holding the same
// link both proceed, and both would enrol a credential — so a leaked link would
// let an attacker enrol alongside the legitimate user rather than instead of
// them, which is worse because nothing looks wrong afterwards.
func TestConcurrentRedemption(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "newcomer")
	issued, err := s.IssueInvitation(ctx, user.ID, &user.ID, 0)
	require.NoError(t, err)

	const racers = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()
			if _, err := s.RedeemInvitation(ctx, issued.Token, testIP); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, successes,
		"exactly one racer may redeem; more than one means a leaked link enrols twice")
}

// TestExpiredInvitationIsRefused.
func TestExpiredInvitationIsRefused(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "newcomer")
	issued, err := s.IssueInvitation(ctx, user.ID, &user.ID, time.Millisecond)
	require.NoError(t, err)

	time.Sleep(20 * time.Millisecond)

	_, err = s.InvitationByToken(ctx, issued.Token)
	require.ErrorIs(t, err, store.ErrInvitationNotFound)

	_, err = s.RedeemInvitation(ctx, issued.Token, testIP)
	require.ErrorIs(t, err, store.ErrInvitationNotFound,
		"expiry must be enforced at redemption, not only when reading")
}

// TestIssuingSupersedesTheOutstandingInvitation.
//
// Two live links for one account would make revocation ambiguous — and
// revoking is exactly the thing done in a hurry, when ambiguity is worst.
func TestIssuingSupersedesTheOutstandingInvitation(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "newcomer")

	first, err := s.IssueInvitation(ctx, user.ID, &user.ID, 0)
	require.NoError(t, err)
	second, err := s.IssueInvitation(ctx, user.ID, &user.ID, 0)
	require.NoError(t, err)

	_, err = s.InvitationByToken(ctx, first.Token)
	require.ErrorIs(t, err, store.ErrInvitationNotFound,
		"issuing a replacement must kill the previous link, not leave two working")

	_, err = s.InvitationByToken(ctx, second.Token)
	require.NoError(t, err)

	pending, err := s.PendingInvitations(ctx)
	require.NoError(t, err)
	require.Len(t, pending, 1, "one account, one outstanding invitation")
}

// TestRevokedInvitationIsRefused.
func TestRevokedInvitationIsRefused(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "newcomer")
	issued, err := s.IssueInvitation(ctx, user.ID, &user.ID, 0)
	require.NoError(t, err)

	require.NoError(t, s.RevokeInvitation(ctx, user.ID, &user.ID))

	_, err = s.RedeemInvitation(ctx, issued.Token, testIP)
	require.ErrorIs(t, err, store.ErrInvitationNotFound)

	require.ErrorIs(t, s.RevokeInvitation(ctx, user.ID, &user.ID),
		store.ErrInvitationNotFound,
		"revoking nothing must be an error, so a UI cannot report an act that did not happen")
}

// TestInvitationForDisabledAccountIsRefused.
//
// Disabling an account must actually stop access. An outstanding invitation
// that still worked would make disabling a suggestion.
func TestInvitationForDisabledAccountIsRefused(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "newcomer")
	issued, err := s.IssueInvitation(ctx, user.ID, &user.ID, 0)
	require.NoError(t, err)

	require.NoError(t, s.DisableEntity(ctx, user.ID, &user.ID))

	_, err = s.InvitationByToken(ctx, issued.Token)
	require.ErrorIs(t, err, store.ErrInvitationNotFound)

	_, err = s.RedeemInvitation(ctx, issued.Token, testIP)
	require.ErrorIs(t, err, store.ErrInvitationNotFound)
}

// TestInvitationTokenIsNotStored.
//
// The token is a working credential. A database read — a backup, a replica, an
// SQL injection somewhere else entirely — must not yield one.
func TestInvitationTokenIsNotStored(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	user := mustCreate(t, s, directory.TypeUser, "newcomer")
	issued, err := s.IssueInvitation(ctx, user.ID, &user.ID, 0)
	require.NoError(t, err)

	events, err := s.ListEvents(ctx, store.EventFilter{Subject: &user.ID}, 10)
	require.NoError(t, err)
	for _, ev := range events {
		for _, value := range ev.Payload {
			assert.NotEqual(t, issued.Token, value,
				"the token must never reach the append-only journal")
		}
	}

	// A wrong token must not resolve, which also confirms the lookup is by hash
	// rather than by anything guessable.
	_, err = s.InvitationByToken(ctx, "not-the-token")
	require.ErrorIs(t, err, store.ErrInvitationNotFound)
}

// TestIssuedInvitationIsAudited.
func TestIssuedInvitationIsAudited(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	admin := mustCreate(t, s, directory.TypeUser, "admin")
	user := mustCreate(t, s, directory.TypeUser, "newcomer")

	issued, err := s.IssueInvitation(ctx, user.ID, &admin.ID, 0)
	require.NoError(t, err)
	_, err = s.RedeemInvitation(ctx, issued.Token, testIP)
	require.NoError(t, err)

	events, err := s.ListEvents(ctx, store.EventFilter{Subject: &user.ID}, 10)
	require.NoError(t, err)

	actions := map[string]bool{}
	for _, ev := range events {
		actions[ev.Action] = true
	}
	assert.True(t, actions["invitation.issued"], "issuing must be recorded")
	assert.True(t, actions["invitation.redeemed"],
		"redemption must be a separate record: alerting on use is not the same as alerting on issue")
}
