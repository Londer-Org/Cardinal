package store

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// How much runway the time-partitioned tables have left.
//
// Migration 0034 explains why this matters: every mutation appends its journal
// entry in the same transaction as the change, so a row that routes to no
// partition fails the whole transaction. The DEFAULT partition added there
// means that can no longer happen — which is exactly why something has to
// report the situation, because the failure it replaced was loud and the one it
// leaves is silent.

// PartitionRunway reports the state of one partitioned table.
type PartitionRunway struct {
	Table string

	// Until is the end of the last dated partition. Zero if there are none,
	// which would mean somebody removed them.
	Until time.Time

	// Overflowing reports rows in the DEFAULT partition: the dated ones no
	// longer cover the present, and writes are only succeeding because of the
	// backstop. Creating the proper partition now requires moving these first.
	Overflowing bool
}

// partitionedTables are the ones this checks. Named rather than discovered:
// a table appearing here should be a decision somebody made, and a query for
// "every partitioned table" would silently start covering one added for an
// unrelated reason.
var partitionedTables = []string{"events", "decisions"}

// upperBound extracts the TO value from a range partition's bound expression.
//
// PostgreSQL renders these as
//
//	FOR VALUES FROM ('2028-01-01 00:00:00+00') TO ('2029-01-01 00:00:00+00')
//
// and there is no catalogue column holding the parsed value — relpartbound is
// an internal node tree, and pg_get_expr is the supported way to read it. So
// this parses text, and the test asserts it against bounds a real PostgreSQL
// produced rather than against a string written here.
var upperBound = regexp.MustCompile(`TO \('([^']+)'`)

// PartitionRunways reports how much time each partitioned table still covers.
func (s *Store) PartitionRunways(ctx context.Context) ([]PartitionRunway, error) {
	out := make([]PartitionRunway, 0, len(partitionedTables))

	for _, table := range partitionedTables {
		rows, err := s.pool.Query(ctx, `
			SELECT pg_get_expr(child.relpartbound, child.oid),
			       coalesce(pg_catalog.pg_relation_size(child.oid), 0)
			  FROM pg_class parent
			  JOIN pg_inherits i    ON i.inhparent = parent.oid
			  JOIN pg_class child   ON child.oid = i.inhrelid
			 WHERE parent.relname = $1
			   AND parent.relnamespace = 'public'::regnamespace`, table)
		if err != nil {
			return nil, fmt.Errorf("store: listing partitions of %s: %w", table, err)
		}

		runway := PartitionRunway{Table: table}
		for rows.Next() {
			var bound string
			var size int64
			if err := rows.Scan(&bound, &size); err != nil {
				rows.Close()
				return nil, fmt.Errorf("store: reading a partition of %s: %w", table, err)
			}

			if bound == "DEFAULT" {
				// Size rather than a count: this runs at startup on every node,
				// and counting rows in a partition that is supposed to be empty
				// is a sequential scan to learn a number nobody wants. An empty
				// table is zero pages, and one with rows is not.
				runway.Overflowing = size > 0
				continue
			}

			match := upperBound.FindStringSubmatch(bound)
			if match == nil {
				// Not a range partition, or a rendering this does not know.
				// Skipped rather than guessed at: reporting a runway from a
				// bound that was not understood is worse than reporting none.
				continue
			}
			until, err := parsePartitionBound(match[1])
			if err != nil {
				continue
			}
			if until.After(runway.Until) {
				runway.Until = until
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: listing partitions of %s: %w", table, err)
		}
		rows.Close()

		out = append(out, runway)
	}

	return out, nil
}

// parsePartitionBound reads the timestamp PostgreSQL rendered.
//
// The layout depends on the session's DateStyle and on whether the value has a
// fractional part, so both forms are tried rather than one being assumed.
func parsePartitionBound(value string) (time.Time, error) {
	layouts := []string{
		"2006-01-02 15:04:05.999999-07",
		"2006-01-02 15:04:05.999999-07:00",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("store: unrecognised partition bound %q", value)
}
