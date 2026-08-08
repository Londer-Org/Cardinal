-- Reverses 0015_oidc_prompt.sql.
--
-- Authorization requests in flight lose `prompt` and `max_age`, so a client
-- that asked for a fresh ceremony would not get one. They expire in minutes;
-- anything mid-flight is retried by the client.
ALTER TABLE oidc_auth_requests DROP COLUMN IF EXISTS max_age;
ALTER TABLE oidc_auth_requests DROP COLUMN IF EXISTS prompt;
