package directory_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
)

// TestValidateNameRefusesWhatWouldEscapeItsContext is the reason this package
// had tests written for it before anything else.
//
// An entity name is not merely a label. It is interpolated into a sudoers file,
// used as an SSH certificate principal, and used as a Cedar entity identifier —
// three grammars, none of which Cardinal escapes for, because the name is
// constrained instead. That makes the pattern a security boundary and this the
// test of it: every case below is a character that means something in at least
// one of those three places.
func TestValidateNameRefusesWhatWouldEscapeItsContext(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		why  string
	}{
		{"alice bob", "a space separates fields in sudoers and in an authorized_keys line"},
		{"alice\tbob", "so does a tab"},
		{"alice\nroot ALL=(ALL) NOPASSWD: ALL", "a newline appends a rule of the attacker's choosing"},
		{"alice,bob", "a comma separates users in a sudoers User_List"},
		{"alice=bob", "= separates the user from the host specification"},
		{"%wheel", "%% names a group in sudoers, so this would grant through one"},
		{"#0", "#uid is how sudoers names a user numerically, and 0 is root"},
		{"!alice", "! negates a sudoers list entry"},
		{"alice:bob", ": separates fields in passwd, which the POSIX provider serves"},
		{"-alice", "a leading hyphen is read as a flag by nearly every command"},
		{"alice/../root", "path traversal, for anything that builds a path from a name"},
		{"alice*", "* is a wildcard in sudoers host and command specifications"},
		{`alice"bob`, "a quote changes where a sudoers token ends"},
		{"alice$(id)", "command substitution, if a name ever reaches a shell"},
		{"alice`id`", "the older spelling of the same thing"},
		{"alice\x00bob", "a NUL truncates the name for any C consumer, and every one of these is"},
		{"ALICE", "uppercase, which would let two names differ only by case"},
		{"Alice", "the same, and the common way somebody types it"},
		{"", "empty"},
		{".alice", "must start with a letter or digit, not punctuation"},
		{"_alice", "the same"},
		{"alice@example.com", "@ separates a principal from its realm"},
		{"alice+admin", "+ is a netgroup marker in some NSS grammars"},
		{"älice", "not ASCII: the POSIX and SSH consumers are byte-oriented"},
		{"аlice", "Cyrillic а — a homoglyph, and two entities that look identical"},
		{"0", "getent passwd 0 returns root, and shadow mode runs exactly that"},
		{"1000", "the same, for the first ordinary uid on most distributions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := directory.ValidateName(tc.name)
			require.ErrorIs(t, err, directory.ErrInvalidName,
				"%q must be refused: %s", tc.name, tc.why)
		})
	}
}

// TestValidateNameAcceptsOrdinaryNames guards the other direction.
//
// A pattern that refuses everything would pass the test above and be useless,
// so these are the names people actually have.
func TestValidateNameAcceptsOrdinaryNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"alice", "alonfils", "a", "a0",
		"alice.bob", "alice-bob", "alice_bob",
		"web-01", "web-01.prod", "svc.backup",
		"staff-apps", "group2", "0x", "0-team",
		strings.Repeat("a", 63),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, directory.ValidateName(name))
		})
	}
}

// TestNameLengthIsBoundedAtSixtyThree pins the boundary rather than trusting
// two rules to agree.
//
// The length is checked twice — once explicitly and once by the pattern's
// {0,62} repetition — and the two could disagree without anything noticing.
// 63 is not arbitrary: it is the traditional limit for a POSIX login name and
// for a DNS label, and a host entity's name becomes both.
func TestNameLengthIsBoundedAtSixtyThree(t *testing.T) {
	t.Parallel()

	require.NoError(t, directory.ValidateName(strings.Repeat("a", 63)))

	err := directory.ValidateName(strings.Repeat("a", 64))
	require.ErrorIs(t, err, directory.ErrInvalidName)
	assert.Contains(t, err.Error(), "maximum is 63",
		"the message reaches a human at a prompt, so it should say the limit")
}

func TestNewEntityRefusesAnUnknownType(t *testing.T) {
	t.Parallel()

	_, err := directory.NewEntity(directory.Type("administrator"), "alice", "")
	require.ErrorIs(t, err, directory.ErrInvalidType,
		"a type not in the enum would fail at the database with a far worse message")
}

func TestNewEntityValidatesTheName(t *testing.T) {
	t.Parallel()

	_, err := directory.NewEntity(directory.TypeUser, "Alice Smith", "")
	require.ErrorIs(t, err, directory.ErrInvalidName,
		"validation must happen here, not only in the store: this constructor is "+
			"the one path every caller shares")
}

// TestNewEntityIDsAreTimeOrdered checks the property UUIDv7 was chosen for.
//
// The comment on NewEntity says v7 rather than v4 keeps index locality good and
// makes rows roughly sortable by creation time. Both of those are consequences
// of the ids increasing, which is a claim worth holding to.
func TestNewEntityIDsAreTimeOrdered(t *testing.T) {
	t.Parallel()

	previous, err := directory.NewEntity(directory.TypeUser, "first", "")
	require.NoError(t, err)

	for i := range 50 {
		next, err := directory.NewEntity(directory.TypeUser, "later", "")
		require.NoError(t, err)
		require.Greater(t, next.ID.String(), previous.ID.String(),
			"id %d sorted before its predecessor: %s then %s", i, previous.ID, next.ID)
		previous = next
	}
}

func TestNewEntityStartsWithAnEmptyAttributeMap(t *testing.T) {
	t.Parallel()

	e, err := directory.NewEntity(directory.TypeUser, "alice", "Alice")
	require.NoError(t, err)

	assert.NotNil(t, e.Attrs,
		"a nil map would panic on first write, and every caller assumes it can assign")
	assert.Empty(t, e.Attrs)
	assert.Equal(t, "Alice", e.DisplayName,
		"the display name is deliberately unconstrained: it is never interpolated anywhere")
}

// TestEveryTypeInAllTypesIsValid keeps the list and the predicate honest about
// each other; Valid is implemented in terms of AllTypes, so this is really
// asserting that AllTypes matches the constants declared beside it.
func TestEveryTypeInAllTypesIsValid(t *testing.T) {
	t.Parallel()

	for _, ty := range directory.AllTypes {
		assert.True(t, ty.Valid(), "%s", ty)
		assert.Equal(t, string(ty), ty.String())

		_, err := directory.NewEntity(ty, "example", "")
		assert.NoError(t, err, "%s is listed as a type but cannot be constructed", ty)
	}

	assert.Len(t, directory.AllTypes, 7,
		"AllTypes must stay in step with the entity_type enum in migration 0001; "+
			"a type added here and not there fails at insert time")
	assert.False(t, directory.Type("").Valid())
}

func TestActiveAndRedactedReadTheirTimestamps(t *testing.T) {
	t.Parallel()

	e, err := directory.NewEntity(directory.TypeUser, "alice", "")
	require.NoError(t, err)

	assert.True(t, e.Active())
	assert.False(t, e.Redacted())

	now := e.CreatedAt
	e.DisabledAt = &now
	assert.False(t, e.Active(), "a disabled entity must not be usable as a principal")

	e.RedactedAt = &now
	assert.True(t, e.Redacted(),
		"the WebAuthn login path refuses a redacted entity, so this predicate is a gate")
}
