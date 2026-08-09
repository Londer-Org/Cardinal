package temporal_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory/temporal"
)

// The temporal model is the feature Cardinal is built around, and until now it
// was only ever exercised through SQL — every assertion about half-open bounds
// went through a database that implements them correctly, which proves
// PostgreSQL works rather than that this package agrees with it.
//
// These tests are the Go half of that agreement. Where a case exists because
// PostgreSQL behaves a particular way, the comment says so.

func mustParse(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	require.NoError(t, err)
	return parsed
}

// TestPeriodIsHalfOpen is the property everything else rests on.
//
// [From, Until): the start instant is inside, the end instant is not. It is
// what makes revoking at noon and re-granting at noon leave no gap and trigger
// no overlap — the two operations meet exactly, and a closed interval would
// make them collide on the WITHOUT OVERLAPS primary key.
func TestPeriodIsHalfOpen(t *testing.T) {
	t.Parallel()

	start := mustParse(t, "2026-03-01T12:00:00Z")
	end := mustParse(t, "2026-03-08T12:00:00Z")
	p := temporal.Between(start, end)

	assert.True(t, p.Contains(start), "the first instant is inside a half-open period")
	assert.False(t, p.Contains(end), "the last instant is not")
	assert.True(t, p.Contains(end.Add(-time.Nanosecond)), "but everything before it is")
	assert.False(t, p.Contains(start.Add(-time.Nanosecond)))
}

// TestAdjacentPeriodsMeetWithoutOverlapping is the half-open property stated as
// the operation it exists for: revoke at an instant, re-grant from the same
// instant.
func TestAdjacentPeriodsMeetWithoutOverlapping(t *testing.T) {
	t.Parallel()

	noon := mustParse(t, "2026-03-01T12:00:00Z")
	before := temporal.Between(noon.Add(-24*time.Hour), noon)
	after := temporal.Between(noon, noon.Add(24*time.Hour))

	assert.False(t, before.Contains(noon))
	assert.True(t, after.Contains(noon),
		"the instant belongs to exactly one of two adjacent periods, never both and never neither")
}

func TestValidateRejectsWhatTheDatabaseWouldReject(t *testing.T) {
	t.Parallel()

	start := mustParse(t, "2026-03-01T12:00:00Z")

	t.Run("inverted", func(t *testing.T) {
		t.Parallel()
		err := temporal.Between(start, start.Add(-time.Hour)).Validate()
		require.ErrorIs(t, err, temporal.ErrInvertedRange)
		assert.Contains(t, err.Error(), "2026-03-01",
			"the message should name the instants, since it reaches a human")
	})

	t.Run("zero length", func(t *testing.T) {
		t.Parallel()
		// [t, t) contains no instant. PostgreSQL rejects it through the
		// isempty() check constraint, so catching it here only changes which
		// error the caller sees, not whether it is allowed.
		err := temporal.Between(start, start).Validate()
		require.ErrorIs(t, err, temporal.ErrEmptyPeriod)
	})

	t.Run("unbounded is always valid", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, temporal.FromTime(start).Validate())
		require.NoError(t, temporal.Forever().Validate())
	})

	t.Run("bounded and ordered is valid", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, temporal.Between(start, start.Add(time.Microsecond)).Validate())
	})

	t.Run("shorter than a microsecond is empty", func(t *testing.T) {
		t.Parallel()
		// Not a quirk of the test: the constructors truncate to microseconds
		// because that is what timestamptz stores, so a period shorter than one
		// has no instants left after truncation. Asking for a nanosecond of
		// access is refused rather than silently rounded up to something, which
		// is the right way round for a grant.
		err := temporal.Between(start, start.Add(time.Nanosecond)).Validate()
		require.ErrorIs(t, err, temporal.ErrEmptyPeriod)
	})
}

// TestUnboundedPeriodsHaveNoEnd covers the nil-Until branch of every predicate.
//
// Unbounded is stored as PostgreSQL's 'infinity' rather than NULL so range
// operators behave; in Go it is a nil pointer, and the two representations
// meeting at the driver is where a "grant that never expires expired" bug would
// live.
func TestUnboundedPeriodsHaveNoEnd(t *testing.T) {
	t.Parallel()

	start := mustParse(t, "2026-03-01T12:00:00Z")
	p := temporal.FromTime(start)

	require.Nil(t, p.Until)
	assert.True(t, p.Contains(start))
	assert.True(t, p.Contains(start.Add(100*365*24*time.Hour)),
		"a century later is still inside an unbounded grant")
	assert.False(t, p.Contains(start.Add(-time.Nanosecond)),
		"unbounded at the end does not mean unbounded at the start")
}

func TestActiveReadsTheCurrentInstant(t *testing.T) {
	t.Parallel()

	now := time.Now()

	assert.True(t, temporal.For(time.Hour).Active())
	assert.True(t, temporal.Forever().Active())
	assert.False(t, temporal.Between(now.Add(-2*time.Hour), now.Add(-time.Hour)).Active(),
		"a period that has ended is not active")
	assert.False(t, temporal.Between(now.Add(time.Hour), now.Add(2*time.Hour)).Active(),
		"nor is one that has not started")
}

// TestActiveAtIsContains pins the two names to one behaviour.
//
// ActiveAt exists only so call sites asking "was this grant live then" read
// well. If the two ever diverge, one of the two vocabularies is lying.
func TestActiveAtIsContains(t *testing.T) {
	t.Parallel()

	start := mustParse(t, "2026-03-01T12:00:00Z")
	p := temporal.Between(start, start.Add(time.Hour))

	for _, at := range []time.Time{
		start.Add(-time.Hour), start, start.Add(30 * time.Minute),
		start.Add(time.Hour), start.Add(2 * time.Hour),
	} {
		assert.Equal(t, p.Contains(at), p.ActiveAt(at), "at %s", at)
	}
}

// TestConstructorsTruncateToMicroseconds keeps Go and PostgreSQL agreeing.
//
// timestamptz stores microseconds; Go's time.Time carries nanoseconds. Without
// truncation a period built here and one read back differ in a way no test
// comparing them would explain, and a boundary instant could land on the wrong
// side of a comparison after a round trip.
func TestConstructorsTruncateToMicroseconds(t *testing.T) {
	t.Parallel()

	ragged := time.Date(2026, 3, 1, 12, 0, 0, 123456789, time.UTC)

	for name, p := range map[string]temporal.Period{
		"FromTime": temporal.FromTime(ragged),
		"Between":  temporal.Between(ragged, ragged.Add(time.Hour)),
		"Forever":  temporal.Forever(),
		"For":      temporal.For(time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Zero(t, p.From.Nanosecond()%1000,
				"From keeps sub-microsecond precision that timestamptz cannot store")
			if p.Until != nil {
				assert.Zero(t, p.Until.Nanosecond()%1000, "and so does Until")
			}
		})
	}
}

// TestConstructorsNormaliseToUTC: a period built in one zone and compared in
// another must not depend on where the process was running.
func TestConstructorsNormaliseToUTC(t *testing.T) {
	t.Parallel()

	brussels, err := time.LoadLocation("Europe/Brussels")
	require.NoError(t, err)

	local := time.Date(2026, 3, 1, 12, 0, 0, 0, brussels)
	p := temporal.Between(local, local.Add(time.Hour))

	assert.Equal(t, time.UTC, p.From.Location())
	assert.Equal(t, time.UTC, p.Until.Location())
	assert.True(t, p.From.Equal(local), "normalising the zone must not move the instant")
}

func TestStringNamesTheBoundsItUses(t *testing.T) {
	t.Parallel()

	start := mustParse(t, "2026-03-01T12:00:00Z")

	assert.Equal(t, "[2026-03-01T12:00:00Z, ∞)", temporal.FromTime(start).String())
	assert.Equal(t, "[2026-03-01T12:00:00Z, 2026-03-01T13:00:00Z)",
		temporal.Between(start, start.Add(time.Hour)).String(),
		"the bracket and parenthesis are the notation for half-open, and are the point")
}

func TestDirectMembershipIsDepthOne(t *testing.T) {
	t.Parallel()

	assert.True(t, temporal.Membership{Depth: 1}.Direct())
	assert.False(t, temporal.Membership{Depth: 2}.Direct(),
		"depth 2 is inherited through a nested group")
	assert.False(t, temporal.Membership{Depth: 0}.Direct(),
		"depth 0 is not a membership at all, and must not read as a direct one")
}

// TestMaxResolutionDepthIsAboveAnyRealHierarchy: the cap is a second line of
// defence behind UNION's duplicate elimination, so it must sit well above any
// nesting a person would model rather than acting as a functional limit.
func TestMaxResolutionDepthIsAboveAnyRealHierarchy(t *testing.T) {
	t.Parallel()

	assert.GreaterOrEqual(t, temporal.MaxResolutionDepth, 16)
}
