-- Reverses 0006_oidc.sql.
--
-- DESTRUCTIVE. Removes every registered application, its keys, and the signing
-- key every issued token was signed with. Tokens already in the wild stop
-- verifying, which is a logout for every application at once.
DROP TABLE IF EXISTS oidc_signing_keys;
DROP TABLE IF EXISTS oidc_tokens;
DROP TABLE IF EXISTS oidc_auth_requests;
DROP TABLE IF EXISTS oidc_client_keys;
DROP TABLE IF EXISTS oidc_clients;
DROP TYPE IF EXISTS oidc_auth_method;
