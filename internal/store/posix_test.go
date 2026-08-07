package store_test

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRange is deliberately not the default, so a test that accidentally
// depended on the default's exact value would fail rather than pass.
var testRange = store.POSIXRange{Low: 200000, High: 200005}

// TestNumbersAreUniqueAcrossUsersAndGroups.
//
// One allocator for both, which is the whole reason this table has a single
// id_number column rather than separate uid and gid ones. The two namespaces are
// distinct to the kernel and not to the people reading `ls -l`, and a uid that
// happens to equal an unrelated gid is a confusion that surfaces years later as
// a permissions bug nobody can explain.
func TestNumbersAreUniqueAcrossUsersAndGroups(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	sre := mustCreate(t, s, directory.TypeGroup, "sre")

	aliceID, err := s.AssignPOSIXIdentity(ctx, alice.ID, testRange, nil)
	require.NoError(t, err)
	sreID, err := s.AssignPOSIXIdentity(ctx, sre.ID, testRange, nil)
	require.NoError(t, err)

	assert.NotEqual(t, aliceID.Number, sreID.Number,
		"a uid and a gid from one directory must never be the same number")
	assert.GreaterOrEqual(t, aliceID.Number, testRange.Low)
}

// TestUserGetsHomeAndShellAndAGroupDoesNot.
func TestUserGetsHomeAndShellAndAGroupDoesNot(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	sre := mustCreate(t, s, directory.TypeGroup, "sre")

	aliceID, err := s.AssignPOSIXIdentity(ctx, alice.ID, testRange, nil)
	require.NoError(t, err)
	assert.Equal(t, "/home/alice", aliceID.HomeDirectory)
	assert.Equal(t, store.DefaultLoginShell, aliceID.LoginShell)

	// A user's primary group is their own number — user-private groups, which
	// is what useradd has done on every mainstream distribution for twenty
	// years. The alternative, one shared primary group, makes every file
	// group-readable by the whole company by default.
	name, gid := aliceID.PrimaryGroup()
	assert.Equal(t, "alice", name)
	assert.Equal(t, aliceID.Number, gid)

	sreID, err := s.AssignPOSIXIdentity(ctx, sre.ID, testRange, nil)
	require.NoError(t, err)
	assert.Empty(t, sreID.HomeDirectory, "a group has nowhere to log in to")
	assert.Empty(t, sreID.LoginShell)
}

// TestOnlyUsersAndGroupsGetNumbers.
//
// An application with a uid is a category error that a Unix machine will
// cheerfully act on. Refused here rather than filtered later, because the
// number would be permanent once handed out.
func TestOnlyUsersAndGroupsGetNumbers(t *testing.T) {
	s := newStore(t)

	app := mustCreate(t, s, directory.TypeApplication, "billing")

	_, err := s.AssignPOSIXIdentity(t.Context(), app.ID, testRange, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only users and groups")
}

// TestNumbersAreNeverReused.
//
// The property the whole design turns on. A released number handed to somebody
// new gives them every file the previous holder ever created — silently,
// because the kernel only ever knew the number.
func TestNumbersAreNeverReused(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	first := mustCreate(t, s, directory.TypeUser, "alice")
	firstID, err := s.AssignPOSIXIdentity(ctx, first.ID, testRange, nil)
	require.NoError(t, err)

	// Disabling and redacting is the strongest form of "this person is gone"
	// Cardinal has. The number must survive both.
	require.NoError(t, s.DisableEntity(ctx, first.ID, nil))
	require.NoError(t, s.RedactEntity(ctx, first.ID, nil))

	second := mustCreate(t, s, directory.TypeUser, "bob")
	secondID, err := s.AssignPOSIXIdentity(ctx, second.ID, testRange, nil)
	require.NoError(t, err)

	assert.Greater(t, secondID.Number, firstID.Number,
		"the next number must be above the last, never filling a gap")

	// And the erased account keeps its number, so "who was uid 200000" remains
	// answerable. The home directory is the field that carried a name, and it
	// is the field redaction rewrites.
	kept, err := s.POSIXIdentityFor(ctx, first.ID)
	require.NoError(t, err)
	assert.Equal(t, firstID.Number, kept.Number)
	assert.NotContains(t, kept.HomeDirectory, "alice",
		"the home directory carries the login and must be erased with it")
}

// TestConcurrentAssignmentCannotCollide.
//
// max + 1 read in one statement rather than read-then-write. Two administrators
// creating accounts at the same moment is ordinary, and two accounts sharing a
// uid is not a race that shows up in testing — it shows up when one person can
// read the other's files.
func TestConcurrentAssignmentCannotCollide(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	const racers = 6
	wide := store.POSIXRange{Low: 300000, High: 399999}

	users := make([]*directory.Entity, racers)
	for i := range users {
		users[i] = mustCreate(t, s, directory.TypeUser,
			"racer-"+string(rune('a'+i)))
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		numbers = map[int]int{}
		failed  []error
	)
	wg.Add(racers)
	for i := range racers {
		go func() {
			defer wg.Done()
			// No retry. An advisory lock serialises allocation, so every caller
			// must succeed on its first attempt — retrying here would hide
			// exactly the contention this test exists to detect.
			id, err := s.AssignPOSIXIdentity(ctx, users[i].ID, wide, nil)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, err)
				return
			}
			numbers[id.Number]++
		}()
	}
	wg.Wait()

	// Asserted first, and it is the assertion that makes the rest mean
	// anything: "no two numbers collided" is trivially true of a run where
	// nothing was allocated at all.
	require.Empty(t, failed, "every racer must get a number")
	require.Len(t, numbers, racers, "%d racers produced %d distinct numbers",
		racers, len(numbers))

	for number, count := range numbers {
		assert.Equal(t, 1, count, "two accounts were given uid %d", number)
	}
}

// TestExhaustedRangeIsDistinguishable.
//
// A configuration change, not an incident — and the two need different
// responses, so they must not look the same to whoever is reading the error.
func TestExhaustedRangeIsDistinguishable(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	tiny := store.POSIXRange{Low: 400000, High: 400001}

	for _, name := range []string{"one", "two"} {
		e := mustCreate(t, s, directory.TypeUser, name)
		_, err := s.AssignPOSIXIdentity(ctx, e.ID, tiny, nil)
		require.NoError(t, err)
	}

	third := mustCreate(t, s, directory.TypeUser, "three")
	_, err := s.AssignPOSIXIdentity(ctx, third.ID, tiny, nil)
	require.ErrorIs(t, err, store.ErrPOSIXRangeExhausted)
}

// TestAllocationRangeBelowTheFloorIsRefused.
//
// Below 1000 is the distribution's own accounts and 61184–65519 is systemd's
// DynamicUser reservation. Colliding with either is an outage, so it is refused
// before a number is handed out rather than reported afterwards.
func TestAllocationRangeBelowTheFloorIsRefused(t *testing.T) {
	s := newStore(t)

	alice := mustCreate(t, s, directory.TypeUser, "alice")

	_, err := s.AssignPOSIXIdentity(t.Context(), alice.ID,
		store.POSIXRange{Low: 500, High: 600}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "system's own accounts")
}

// TestHomeAndShellAreChangeableAndTheNumberIsNot.
//
// SetPOSIXAttributes takes no number parameter, which is the point: changing a
// uid is not an edit, it is a new identity, and every file already on disk still
// carries the old one.
func TestHomeAndShellAreChangeableAndTheNumberIsNot(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	original, err := s.AssignPOSIXIdentity(ctx, alice.ID, testRange, nil)
	require.NoError(t, err)

	require.NoError(t, s.SetPOSIXAttributes(ctx, alice.ID,
		"/srv/home/alice", "/usr/bin/fish", nil))

	updated, err := s.POSIXIdentityFor(ctx, alice.ID)
	require.NoError(t, err)
	assert.Equal(t, "/srv/home/alice", updated.HomeDirectory)
	assert.Equal(t, "/usr/bin/fish", updated.LoginShell)
	assert.Equal(t, original.Number, updated.Number, "the number must be immutable")
}

// TestRelativePathsAreRefused.
//
// A relative home directory or shell is meaningless to the kernel and dangerous
// to a shell: whatever "bin/bash" resolves to depends on the working directory
// of whichever process happened to read it.
func TestRelativePathsAreRefused(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	_, err := s.AssignPOSIXIdentity(ctx, alice.ID, testRange, nil)
	require.NoError(t, err)

	err = s.SetPOSIXAttributes(ctx, alice.ID, "home/alice", "bin/bash", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

// TestGroupHasNoAttributesToSet.
func TestGroupHasNoAttributesToSet(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	sre := mustCreate(t, s, directory.TypeGroup, "sre")
	_, err := s.AssignPOSIXIdentity(ctx, sre.ID, testRange, nil)
	require.NoError(t, err)

	err = s.SetPOSIXAttributes(ctx, sre.ID, "/home/sre", "/bin/bash", nil)
	require.ErrorIs(t, err, store.ErrNoPOSIXIdentity,
		"a group has no home directory to change")
}

// TestAnUnservedNumberCanBeAdopted.
//
// The window that makes migration possible. A number no host has been told
// about has reattributed nothing, so changing it costs exactly nothing — and
// without this, a machine that already calls alice 1234 can only be reconciled
// by moving every file she owns.
func TestAnUnservedNumberCanBeAdopted(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	assigned, err := s.AssignPOSIXIdentity(ctx, alice.ID, testRange, nil)
	require.NoError(t, err)
	require.NotEqual(t, 70001, assigned.Number)

	require.NoError(t, s.AdoptPOSIXNumber(ctx, alice.ID, 70001, nil))

	after, err := s.POSIXIdentityFor(ctx, alice.ID)
	require.NoError(t, err)
	assert.Equal(t, 70001, after.Number)
	assert.True(t, after.Adoptable(), "adopting must not itself count as serving")
}

// TestAServedNumberCannotBeAdopted.
//
// The guard the whole design turns on, and the reason it is a column rather
// than a warning in a runbook: an operator adopting after cutover would see
// success and find out weeks later, from the files.
func TestAServedNumberCannotBeAdopted(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	assigned, err := s.AssignPOSIXIdentity(ctx, alice.ID, testRange, nil)
	require.NoError(t, err)

	require.NoError(t, s.MarkPOSIXNumbersServed(ctx, []uuid.UUID{alice.ID}))

	err = s.AdoptPOSIXNumber(ctx, alice.ID, 70002, nil)
	require.ErrorIs(t, err, store.ErrNumberAlreadyServed)

	unchanged, err := s.POSIXIdentityFor(ctx, alice.ID)
	require.NoError(t, err)
	assert.Equal(t, assigned.Number, unchanged.Number)
	assert.False(t, unchanged.Adoptable())
}

// TestServingIsStampedOnceAndNeverMoves.
//
// The stamp records when the number left Cardinal for the first time. A second
// fetch must not push it forward, or the window it bounds would reopen every
// time an agent polled.
func TestServingIsStampedOnceAndNeverMoves(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	_, err := s.AssignPOSIXIdentity(ctx, alice.ID, testRange, nil)
	require.NoError(t, err)

	require.NoError(t, s.MarkPOSIXNumbersServed(ctx, []uuid.UUID{alice.ID}))
	first, err := s.POSIXIdentityFor(ctx, alice.ID)
	require.NoError(t, err)
	require.NotNil(t, first.FirstServedAt)

	time.Sleep(10 * time.Millisecond)
	require.NoError(t, s.MarkPOSIXNumbersServed(ctx, []uuid.UUID{alice.ID}))

	second, err := s.POSIXIdentityFor(ctx, alice.ID)
	require.NoError(t, err)
	assert.Equal(t, first.FirstServedAt.UnixNano(), second.FirstServedAt.UnixNano(),
		"a later fetch moved the stamp, which would reopen the adoption window")
}

// TestAdoptingTheSameNumberTwiceIsNotAnError.
//
// Re-running a migration command must be safe. An operator who applies the same
// set of reports twice — because they are not sure the first run worked — has to
// get the same answer, not a failure that suggests something is wrong.
func TestAdoptingTheSameNumberTwiceIsNotAnError(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	_, err := s.AssignPOSIXIdentity(ctx, alice.ID, testRange, nil)
	require.NoError(t, err)

	require.NoError(t, s.AdoptPOSIXNumber(ctx, alice.ID, 70003, nil))
	require.NoError(t, s.AdoptPOSIXNumber(ctx, alice.ID, 70003, nil))

	// And still safe once served, because nothing is being changed.
	require.NoError(t, s.MarkPOSIXNumbersServed(ctx, []uuid.UUID{alice.ID}))
	require.NoError(t, s.AdoptPOSIXNumber(ctx, alice.ID, 70003, nil),
		"re-adopting the number already in place must not trip the served guard")
}

// TestAdoptingANumberSomebodyElseHoldsIsRefused.
//
// Two people cannot share a uid in one directory, and the report that proposed
// it is describing two machines that disagree — which is a problem to resolve
// rather than one to write into the database.
func TestAdoptingANumberSomebodyElseHoldsIsRefused(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	bob := mustCreate(t, s, directory.TypeUser, "bob")
	_, err := s.AssignPOSIXIdentity(ctx, alice.ID, testRange, nil)
	require.NoError(t, err)
	bobs, err := s.AssignPOSIXIdentity(ctx, bob.ID, testRange, nil)
	require.NoError(t, err)

	err = s.AdoptPOSIXNumber(ctx, alice.ID, bobs.Number, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already held by somebody else")
}

// TestAdoptingAReservedNumberIsRefused, and only a reserved one.
//
// The distinction this test exists to pin down. uid 1234 is a person on a
// machine using the distribution's own UID_MIN, and refusing it means refusing
// to migrate the ordinary case — which the allocation floor did, until adoption
// existed to expose the difference.
func TestAdoptingAReservedNumberIsRefused(t *testing.T) {
	s := newStore(t)

	for _, tc := range []struct {
		name    string
		number  int
		refused bool
		because string
	}{
		{"a system account", 40, true, "distribution"},
		{"just below the system ceiling", 999, true, "distribution"},
		{"systemd's DynamicUser range", 61200, true, "DynamicUser"},
		{"the top of it", 65519, true, "DynamicUser"},

		// The ones that must work, and the reason this feature exists.
		{"the distribution's first human uid", 1000, false, ""},
		{"an ordinary existing person", 1234, false, ""},
		{"just above DynamicUser", 65520, false, ""},
		{"inside Cardinal's own range", 100500, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The subtest's own context, so mustCreate and the calls below use
			// one lifetime rather than two.
			ctx := t.Context()

			user := mustCreate(t, s, directory.TypeUser, "u"+strconv.Itoa(tc.number))
			_, err := s.AssignPOSIXIdentity(ctx, user.ID,
				store.POSIXRange{Low: 900000, High: 999999}, nil)
			require.NoError(t, err)

			err = s.AdoptPOSIXNumber(ctx, user.ID, tc.number, nil)
			if !tc.refused {
				require.NoError(t, err, "%d is a legitimate number for a person", tc.number)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.because)
		})
	}
}

// TestAdoptedNumbersDoNotDisturbTheAllocator.
//
// Allocation is max + 1 within the configured range, and an adopted number can
// be anywhere. A number adopted below the range must not make the next
// assignment collide, and one adopted inside it must be skipped over.
func TestAdoptedNumbersDoNotDisturbTheAllocator(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	wide := store.POSIXRange{Low: 500000, High: 599999}

	alice := mustCreate(t, s, directory.TypeUser, "alice")
	_, err := s.AssignPOSIXIdentity(ctx, alice.ID, wide, nil)
	require.NoError(t, err)
	// Below the range entirely, which is the common migration case: an existing
	// fleet numbering people from 1000 upwards.
	require.NoError(t, s.AdoptPOSIXNumber(ctx, alice.ID, 70010, nil))

	bob := mustCreate(t, s, directory.TypeUser, "bob")
	bobs, err := s.AssignPOSIXIdentity(ctx, bob.ID, wide, nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, bobs.Number, wide.Low,
		"an adopted number outside the range must not drag the allocator out of it")
	assert.NotEqual(t, 70010, bobs.Number)
}
