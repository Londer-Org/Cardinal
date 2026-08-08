-- Reverses 0004_ceremonies.sql.
--
-- Both tables are ephemeral: a ceremony in flight and a rate-limit window.
-- Losing them costs somebody a retry.
DROP TABLE IF EXISTS rate_limits;
DROP TABLE IF EXISTS webauthn_ceremonies;
