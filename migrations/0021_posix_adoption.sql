-- Cardinal 0021: when a number may still be changed.
--
-- Migration 0019 states that a uid is permanent, and gives the reason: every
-- file on every disk records it, so changing one reattributes files rather than
-- editing an attribute. That is right, and it is not the whole story.
--
-- A number that has never left Cardinal has reattributed nothing. Before the
-- first host is told about it, it is a row in a table and changing it costs
-- exactly nothing. That window is the only thing that makes migration possible
-- at all: a machine that already calls alice 1234 needs Cardinal to agree, and
-- the alternative is `find -uid 1234 -exec chown` on a quiet evening.
--
-- So the rule is not "never" but "never after it has been served", and this
-- column is what makes that a constraint rather than a warning in a manual.
-- Stamped the first time an assignment includes the identity, once, and never
-- cleared.
--
-- This refines 0019, which says a number never changes, full stop. That file is
-- left exactly as it was — migrations are immutable once applied, and the
-- integrity check caught an attempt to add this note there instead. Read the two
-- together: **never reused** holds without qualification; **never changed** holds
-- from the moment a host is first told.

ALTER TABLE posix_identities
    ADD COLUMN first_served_at timestamptz;

COMMENT ON COLUMN posix_identities.first_served_at IS
    'When a host was first told this number. NULL means it may still be changed; set means it is on a filesystem somewhere and is now permanent.';

-- Deliberately no index. It is read when adopting a number — a rare,
-- operator-driven action on one row at a time — and written by a statement that
-- already names the entity ids. An index would cost every assignment fetch a
-- little to make an occasional command marginally faster.
