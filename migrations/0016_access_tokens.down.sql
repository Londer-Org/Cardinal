-- Reverses 0016_access_tokens.sql.
--
-- DESTRUCTIVE. Every access token is revoked by being forgotten, so anything
-- running unattended against this Cardinal — CI, scripts — stops working until
-- reissued (ADR 0018).
DROP TABLE IF EXISTS access_tokens;
