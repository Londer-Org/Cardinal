-- Give the partitioned tables a runway, and a floor to land on.
--
-- events and decisions are partitioned by range on time, and 0001 and 0005
-- created partitions for 2026 and 2027 and nothing else. Nothing creates more.
--
-- That is not a maintenance chore that comes due, it is a date on which
-- Cardinal stops working. Every mutation appends its journal entry in the same
-- transaction as the change it records, so an event that routes to no partition
-- fails the whole transaction: no grants, no credentials, no sessions, no
-- policy activation. Measured against a running instance rather than reasoned
-- about:
--
--   INSERT INTO events (occurred_at) VALUES ('2028-03-01T00:00:00Z');
--   ERROR:  no partition of relation "events" found for row
--   DETAIL:  Partition key of the failing row contains
--            (occurred_at) = (2028-03-01 00:00:00+00).
--
-- Two changes, because either alone is insufficient.
--
-- Yearly partitions through 2035 are the runway. Ten years is long enough that
-- nobody meets the edge by accident, and yearly keeps retention a partition
-- drop rather than a mass DELETE, which is why these tables are partitioned at
-- all.
--
-- A DEFAULT partition on each is the floor. It is what turns running out of
-- runway from an outage into a slow problem: rows land somewhere, writes keep
-- succeeding, and the cost is that creating the proper partition later has to
-- move them first. Availability beats tidiness here — an identity system that
-- refuses every write is worse than one whose partition layout needs an
-- afternoon.
--
-- The startup check warns while the default is still empty, which is the point
-- at which the afternoon is cheap.

CREATE TABLE events_2028 PARTITION OF events
    FOR VALUES FROM ('2028-01-01') TO ('2029-01-01');
CREATE TABLE events_2029 PARTITION OF events
    FOR VALUES FROM ('2029-01-01') TO ('2030-01-01');
CREATE TABLE events_2030 PARTITION OF events
    FOR VALUES FROM ('2030-01-01') TO ('2031-01-01');
CREATE TABLE events_2031 PARTITION OF events
    FOR VALUES FROM ('2031-01-01') TO ('2032-01-01');
CREATE TABLE events_2032 PARTITION OF events
    FOR VALUES FROM ('2032-01-01') TO ('2033-01-01');
CREATE TABLE events_2033 PARTITION OF events
    FOR VALUES FROM ('2033-01-01') TO ('2034-01-01');
CREATE TABLE events_2034 PARTITION OF events
    FOR VALUES FROM ('2034-01-01') TO ('2035-01-01');
CREATE TABLE events_2035 PARTITION OF events
    FOR VALUES FROM ('2035-01-01') TO ('2036-01-01');

CREATE TABLE events_overflow PARTITION OF events DEFAULT;

CREATE TABLE decisions_2028 PARTITION OF decisions
    FOR VALUES FROM ('2028-01-01') TO ('2029-01-01');
CREATE TABLE decisions_2029 PARTITION OF decisions
    FOR VALUES FROM ('2029-01-01') TO ('2030-01-01');
CREATE TABLE decisions_2030 PARTITION OF decisions
    FOR VALUES FROM ('2030-01-01') TO ('2031-01-01');
CREATE TABLE decisions_2031 PARTITION OF decisions
    FOR VALUES FROM ('2031-01-01') TO ('2032-01-01');
CREATE TABLE decisions_2032 PARTITION OF decisions
    FOR VALUES FROM ('2032-01-01') TO ('2033-01-01');
CREATE TABLE decisions_2033 PARTITION OF decisions
    FOR VALUES FROM ('2033-01-01') TO ('2034-01-01');
CREATE TABLE decisions_2034 PARTITION OF decisions
    FOR VALUES FROM ('2034-01-01') TO ('2035-01-01');
CREATE TABLE decisions_2035 PARTITION OF decisions
    FOR VALUES FROM ('2035-01-01') TO ('2036-01-01');

CREATE TABLE decisions_overflow PARTITION OF decisions DEFAULT;

COMMENT ON TABLE events_overflow IS
    'Backstop, expected to stay empty. Rows here mean the yearly partitions ran '
    'out and writes were kept alive at the cost of having to move these before '
    'the proper partition can be created. The server warns about this at '
    'startup.';

COMMENT ON TABLE decisions_overflow IS
    'Backstop, expected to stay empty. See events_overflow.';
