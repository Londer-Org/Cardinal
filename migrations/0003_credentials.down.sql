-- Reverses 0003_credentials.sql.
--
-- DESTRUCTIVE. Drops every registered passkey and every recovery code. An
-- account whose only credential was a passkey cannot sign in after this, and
-- restoring the rows is the only way back — which is why `cardinal migrate -to`
-- refuses to run without a backup.
ALTER TABLE sessions DROP COLUMN IF EXISTS credential_id;
DROP TABLE IF EXISTS recovery_codes;
DROP TABLE IF EXISTS break_glass_challenges;
DROP TABLE IF EXISTS webauthn_credentials;
