-- Cardinal 0004: in-flight authentication ceremonies and rate limiting.

-- ---------------------------------------------------------------------------
-- WebAuthn ceremonies
-- ---------------------------------------------------------------------------

-- A WebAuthn ceremony spans two requests: the server issues a challenge, the
-- authenticator signs it, the server verifies. The challenge must survive
-- between them.
--
-- It lives in Postgres rather than process memory so that any node can complete
-- a ceremony any other node began. That matters behind a load balancer, and it
-- is the same reasoning as break-glass challenges (ADR 0004: no second
-- datastore).
CREATE TABLE webauthn_ceremonies (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),

    -- 'registration' or 'authentication'.
    kind       text        NOT NULL,

    -- Null for a usernameless authentication, where the subject is not known
    -- until the authenticator reveals which credential it used.
    entity_id  uuid        REFERENCES entities(id),

    -- go-webauthn's SessionData, including the challenge.
    session    jsonb       NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,

    -- Single use. A completed ceremony must not be replayable.
    consumed_at timestamptz,

    CONSTRAINT webauthn_ceremonies_kind
        CHECK (kind IN ('registration', 'authentication')),
    CONSTRAINT webauthn_ceremonies_expiry CHECK (expires_at > created_at)
);

CREATE INDEX webauthn_ceremonies_pending_idx ON webauthn_ceremonies (expires_at)
    WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- Rate limiting
-- ---------------------------------------------------------------------------

-- A fixed-window counter, in Postgres rather than Redis (ADR 0004).
--
-- Fixed windows allow up to 2x the limit across a boundary. That is a known
-- and accepted imprecision: this exists to stop online guessing, not to meter
-- billing, and a sliding window would cost far more for a bound nobody needs
-- to be exact.
CREATE TABLE rate_limits (
    -- Scope plus subject, e.g. ('webauthn:begin', '192.0.2.10').
    scope        text        NOT NULL,
    subject      text        NOT NULL,

    -- Start of the current fixed window.
    window_start timestamptz NOT NULL,
    count        integer     NOT NULL DEFAULT 0,

    PRIMARY KEY (scope, subject)
);

CREATE INDEX rate_limits_window_idx ON rate_limits (window_start);

COMMENT ON TABLE rate_limits IS
    'Fixed-window counters. Imprecise at window boundaries by design: this '
    'bounds online guessing, it is not an accounting record.';
