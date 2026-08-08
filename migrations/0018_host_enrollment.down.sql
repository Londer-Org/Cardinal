-- Reverses 0018_host_enrollment.sql.
--
-- DESTRUCTIVE. Every enrolled machine loses the credential that identifies it,
-- so each has to enroll again with a fresh token — on the machine itself, since
-- the agent generates its own keypair and Cardinal never holds the private half.
DROP TABLE IF EXISTS host_enrollment_tokens;
DROP TABLE IF EXISTS host_credentials;
