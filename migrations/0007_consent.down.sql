-- Reverses 0007_consent.sql.
--
-- Loses recorded consent, so every application asks again on its next
-- authorization. Annoying rather than dangerous — asking twice is the safe
-- direction for consent.
ALTER TABLE oidc_auth_requests DROP COLUMN IF EXISTS consent_given_at;
ALTER TABLE oidc_clients DROP COLUMN IF EXISTS require_consent;
DROP TABLE IF EXISTS oidc_consents;
