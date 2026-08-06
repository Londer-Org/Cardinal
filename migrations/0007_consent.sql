-- Cardinal 0007: consent.
--
-- Consent exists for third-party applications — "Grafana wants to read your
-- profile". For a first-party application in your own organisation it is
-- theatre: nobody meaningfully declines their employer's intranet, and a prompt
-- everyone clicks through trains people to click through prompts.
--
-- So it is off by default and enabled per client. That is the same position
-- Keycloak takes, for the same reason.

ALTER TABLE oidc_clients
    ADD COLUMN require_consent boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN oidc_clients.require_consent IS
    'Ask the user before releasing claims to this application. Off by default: '
    'a consent prompt for a first-party application is one more thing people '
    'learn to dismiss without reading.';

-- Consent, once given, is remembered.
--
-- Asking on every sign-in would make the prompt meaningless within a week. It
-- is re-asked when the application requests something it was not granted
-- before, which is the moment the answer might genuinely differ.
CREATE TABLE oidc_consents (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    subject_id uuid        NOT NULL REFERENCES entities(id),
    client_id  text        NOT NULL,

    -- What was actually agreed to. A later request for a wider set does not
    -- match, so consent is asked again rather than silently widened.
    scopes     text[]      NOT NULL DEFAULT '{}',

    granted_at timestamptz NOT NULL DEFAULT now(),

    -- Withdrawn rather than deleted, so "who had access to what, when" stays
    -- answerable — the same reasoning as revoked grants (ADR 0001).
    revoked_at timestamptz,

    UNIQUE (subject_id, client_id)
);

CREATE INDEX oidc_consents_subject_idx ON oidc_consents (subject_id)
    WHERE revoked_at IS NULL;

-- Records whether the user was asked, so an authorization completed without a
-- prompt is distinguishable from one where consent was given. Without this,
-- "did they agree to this?" is unanswerable after the fact.
ALTER TABLE oidc_auth_requests
    ADD COLUMN consent_given_at timestamptz;
