package store_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The journal keeps accepting rows past the last dated partition.
//
// This is the regression test for a date on which Cardinal stopped working.
// events and decisions are partitioned by range on time and their partitions
// were created by hand in 0001 and 0005, covering 2026 and 2027 and nothing
// else. Every mutation writes its journal entry in the same transaction as the
// change it records, so once the calendar passed the last partition, a row that
// routed nowhere failed — and took the grant, the credential or the session
// with it.
//
// Written against the database rather than against the migration text, because
// what matters is where a row lands and only PostgreSQL can answer that.
func TestTheJournalAcceptsRowsBeyondTheDatedPartitions(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	// Inside the runway 0034 added, and then past the end of it. The second is
	// the one the DEFAULT partition exists for: a deployment carried past 2036
	// should slow down, not stop.
	for _, when := range []string{"2028-03-01", "2035-06-01", "2099-01-01"} {
		_, err := s.Pool().Exec(ctx, `
			INSERT INTO events (occurred_at, action, hash)
			VALUES ($1::timestamptz, 'test.partition', '\x00'::bytea)`, when)
		assert.NoError(t, err, "an event dated %s did not route to any partition, "+
			"which fails the transaction that was recording a real change", when)
	}

	for _, when := range []string{"2028-03-01", "2035-06-01", "2099-01-01"} {
		_, err := s.Pool().Exec(ctx, `
			INSERT INTO decisions (decided_at, decision_point, action, resource, allowed)
			VALUES ($1::timestamptz, 'test', 'Test', 'test', true)`, when)
		assert.NoError(t, err, "a decision dated %s did not route to any partition", when)
	}
}

// TestTheRunwayIsReported.
//
// The DEFAULT partition means running out of dated partitions no longer fails
// loudly, so something has to say it quietly. This asserts the reading is real:
// the runway comes back as a date in the future, and it is the one the
// migration created rather than whatever the parser happened to produce.
func TestTheRunwayIsReported(t *testing.T) {
	s := newStore(t)

	runways, err := s.PartitionRunways(t.Context())
	require.NoError(t, err)
	require.Len(t, runways, 2, "both partitioned tables should be reported")

	for _, runway := range runways {
		assert.False(t, runway.Until.IsZero(),
			"%s reported no dated partitions at all", runway.Table)
		assert.Equal(t, 2036, runway.Until.Year(),
			"%s should be covered to the end of 2035; the bound parser may be "+
				"reading something other than what PostgreSQL rendered", runway.Table)
		assert.True(t, runway.Until.After(time.Now()),
			"%s is already out of dated partitions", runway.Table)
	}
}

// TestOverflowIsNoticed.
//
// A row in the DEFAULT partition is the state the warning exists for, and it is
// worth proving the detection works rather than trusting that an empty table
// stays empty. 2099 is past every dated partition, so this row can only be in
// the backstop.
func TestOverflowIsNoticed(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	runways, err := s.PartitionRunways(ctx)
	require.NoError(t, err)
	for _, runway := range runways {
		require.False(t, runway.Overflowing,
			"%s was already overflowing before this test wrote anything", runway.Table)
	}

	_, err = s.Pool().Exec(ctx, `
		INSERT INTO events (occurred_at, action, hash)
		VALUES ('2099-01-01'::timestamptz, 'test.overflow', '\x00'::bytea)`)
	require.NoError(t, err)

	runways, err = s.PartitionRunways(ctx)
	require.NoError(t, err)

	found := false
	for _, runway := range runways {
		if runway.Table == "events" {
			found = true
			assert.True(t, runway.Overflowing,
				"a row landed in the events backstop and nothing reported it")
		}
	}
	assert.True(t, found, "events was not among the reported tables")
}
