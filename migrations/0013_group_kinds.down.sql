-- Reverses 0013_group_kinds.sql.
--
-- Loses which groups are system groups and who owns the others. A version
-- without these columns treats every group the same way, which is what it did
-- before they existed.
ALTER TABLE entities DROP CONSTRAINT IF EXISTS entities_system_groups_are_unowned;
DROP INDEX IF EXISTS entities_owner_idx;
ALTER TABLE entities DROP COLUMN IF EXISTS owner_id;
ALTER TABLE entities DROP COLUMN IF EXISTS system;
