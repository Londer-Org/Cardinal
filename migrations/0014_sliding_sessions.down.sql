-- Reverses 0014_sliding_sessions.sql.
--
-- Sessions lose their absolute expiry and are bounded only by the idle window
-- again. Every existing session stays valid, which is the point of reversing
-- rather than truncating: a downgrade should not sign everybody out.
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_absolute_after_start;
ALTER TABLE sessions DROP COLUMN IF EXISTS absolute_expiry;
