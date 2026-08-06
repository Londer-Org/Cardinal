-- Cardinal 0016: personal access tokens.
--
-- A browser has a session cookie. A script has neither a browser nor a passkey,
-- and until now had nothing at all — so anything automated had to be routed
-- around Cardinal entirely, with a proxy rule matching the Authorization header
-- and sending it straight to the application. That works, and it costs three
-- things: the application has to validate the credential itself, the routing
-- regex becomes a security boundary, and — worst here — the request never
-- reaches a policy decision, so the one class of traffic that runs unattended
-- is the one class missing from the decision log.
--
-- A token is presented as `Authorization: Bearer <token>` and authenticates the
-- same principal a session would. What it deliberately does *not* do is confer
-- the same authority:
--
--   * device_bound is false for a token, always. Two existing forbid rules —
--     admin-requires-fresh-device-bound-auth and ssh-requires-device-bound —
--     are written `unless { principal.deviceBound && … }`, so a token is
--     refused every administrative action and every SSH certificate without a
--     single new line of policy. That is the property this design rests on, and
--     it is a property of the policy rather than of this table.
--
--   * auth_at is the moment the token was issued, not the moment it was used.
--     Reporting "authenticated just now" for a credential typed into a CI
--     variable months ago would make authAgeSeconds a fiction, and freshness
--     rules are built on it.
--
-- Hashed with SHA-256 rather than Argon2id: this is 256 bits of machine-
-- generated randomness, not a human-chosen or human-typed secret, so there is
-- nothing to brute-force and the cost per request would buy nothing. Recovery
-- codes use Argon2id for the opposite reason.

CREATE TABLE access_tokens (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    subject_id   uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,

    -- What it is for, in the owner's words. Shown in the list; a token nobody
    -- can identify is a token nobody dares revoke.
    name         text NOT NULL CHECK (length(btrim(name)) > 0),

    token_hash   bytea NOT NULL UNIQUE,

    -- The leading characters, stored in clear so the UI and the CLI can show
    -- which token a row refers to. Not a secret: it identifies, it does not
    -- authenticate.
    prefix       text NOT NULL,

    -- The same temporal machinery as membership and sessions, so "expires in
    -- 90 days" is a range rather than a job that has to run. Revocation closes
    -- the range at now(), which keeps the history rather than deleting it.
    valid_period tstzrange NOT NULL,

    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   uuid REFERENCES entities(id),

    -- Throttled to at most once a minute, like session last-seen. Useful for
    -- finding tokens nobody uses any more, which are the ones worth revoking.
    last_used_at timestamptz,

    CONSTRAINT access_tokens_period_not_empty CHECK (NOT isempty(valid_period))
);

-- Lookup is by hash on every request, so it is the index that matters.
CREATE INDEX access_tokens_subject_idx ON access_tokens (subject_id);

COMMENT ON TABLE access_tokens IS
    'Bearer credentials for scripts and automation. Never device-bound, so policy refuses them administrative actions.';
