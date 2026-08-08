-- Signing a terminal in, by borrowing a ceremony performed in a browser.
--
-- A terminal cannot do WebAuthn: there is no browser in it and no path to a
-- platform authenticator. So the person approves in the console, and what the
-- terminal receives is a session that inherits what that ceremony proved rather
-- than a weaker credential invented for the occasion.
--
-- Short-lived by construction. Nothing here is worth keeping: a row is spent
-- within ninety seconds or it is worthless, and the session it produces lasts
-- ten minutes because the certificate it fetches carries its own expiry from
-- that point.

CREATE TABLE cli_authorizations (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),

    -- The code that travels in the redirect, hashed. A URL is the worst place
    -- to put a credential — shell history, proxy logs, the address bar — so
    -- what travels there is single-use, expires in ninety seconds, and is
    -- useless without the verifier below.
    code_hash     text        NOT NULL UNIQUE,

    -- SHA-256 of a secret the terminal generated and never transmitted.
    -- Whoever reads the redirect holds a code they cannot exchange.
    verifier_hash text        NOT NULL,

    -- The console session whose ceremony is being borrowed. Read again at claim
    -- time, so approving and then signing out everywhere does not leave a code
    -- that still works.
    session_id    uuid        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,

    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,

    -- Set by the claim itself, in the same statement that reads the row, so two
    -- terminals racing one code cannot both win.
    claimed_at    timestamptz
);

-- Only the rows that can still be claimed. The table is mostly spent codes
-- within a minute of any activity, and this keeps the lookup off them.
CREATE INDEX cli_authorizations_live_idx
    ON cli_authorizations (code_hash)
    WHERE claimed_at IS NULL;

CREATE INDEX cli_authorizations_expiry_idx
    ON cli_authorizations (expires_at)
    WHERE claimed_at IS NULL;
