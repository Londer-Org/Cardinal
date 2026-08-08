-- Reverses 0002_redaction.sql.
--
-- Loses which entities had been redacted. That is data the version being
-- returned to has no column for and no way to act on, so it is lost in the same
-- sense a newer feature is: it was never visible to the older code.
ALTER TABLE entities DROP CONSTRAINT IF EXISTS entities_redaction_is_complete;
DROP INDEX IF EXISTS entities_active_lookup_idx;
ALTER TABLE entities DROP COLUMN IF EXISTS redacted_at;
