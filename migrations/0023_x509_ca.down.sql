-- Reverses 0023_x509_ca.sql.
--
-- DESTRUCTIVE. Drops the X.509 authority and everything ACME kept: accounts,
-- orders, authorizations, external-account credentials and the nonce store. ACME
-- stops working and nothing already issued can be renewed. Certificates in the
-- wild keep verifying until they expire (ADR 0023).
DROP TABLE IF EXISTS acme_authorizations;
DROP TABLE IF EXISTS acme_orders;
DROP TABLE IF EXISTS acme_nonces;
DROP TABLE IF EXISTS acme_eab_credentials;
DROP TABLE IF EXISTS acme_accounts;
DROP TABLE IF EXISTS x509_ca_keys;
