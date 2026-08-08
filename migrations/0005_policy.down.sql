-- Reverses 0005_policy.sql.
--
-- DESTRUCTIVE, and in a way worth naming. `decisions` is the record behind the
-- decision explorer — the answer to "why was I denied" — and `policy_versions`
-- holds every published rule set including the ones a rollback would return to.
-- Both are append-only by rule; dropping the table drops the rule with it.
-- The yearly partitions go with the parent; naming them separately would be
-- wrong the first year somebody adds another one.
DROP TABLE IF EXISTS decisions;
DROP TABLE IF EXISTS policy_versions;
