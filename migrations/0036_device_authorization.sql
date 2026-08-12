-- Cardinal 0036: signing a terminal in from a device that is not this one.
--
-- The existing flow has the console redirect approval to a loopback listener on
-- the machine running the CLI. That does not need a browser to exist — it needs
-- the browser and the CLI to share a loopback interface, which is a stronger
-- condition and is false in the ordinary case of administering a server over
-- SSH: the approval is sent to 127.0.0.1 on whatever machine the browser runs
-- on, and the terminal waits for something that cannot arrive.
--
-- So a terminal can now ask first and be approved from anywhere (ADR 0033,
-- RFC 8628 in shape). Three columns and one widened constraint.
--
-- The row is created before anybody has approved it, which is the whole
-- difference: session_id is filled in by the approval rather than at insert.

ALTER TABLE cli_authorizations
    -- Short enough to read out loud and type on a phone. It is not a
    -- credential: it names which pending request is being approved, and the
    -- thing that exchanges for a session is the device code the terminal keeps.
    ADD COLUMN user_code text,

    -- When somebody approved it, distinct from when the terminal claimed the
    -- session. A row can be approved and never collected.
    ADD COLUMN approved_at timestamptz,

    -- The address the request came from, as the server saw it.
    --
    -- Server-observed on purpose. A hostname the terminal reports about itself
    -- is chosen by whoever ran it, so showing one on the approval screen would
    -- help exactly the attack this flow is weak to: "run this, approve the code
    -- from web-01" reads as reassuring and is unverifiable.
    ADD COLUMN requested_ip inet;

-- The column becomes nullable, so a request can exist before anybody has
-- approved it.
--
-- Not marked `widens:`, which is for a constraint dropped and replaced by a
-- wider one; there is no constraint here to name. Dropping NOT NULL widens in
-- the same direction: every row a previous build wrote still satisfies the
-- column, and a previous build keeps writing rows that do.
--
-- The one asymmetry, stated rather than discovered: a previous build reading a
-- row where this is null would fail to scan it. It never does — those rows are
-- reachable only by a device code that only the newer flow issues — and they
-- are gone within minutes either way.
ALTER TABLE cli_authorizations
    ALTER COLUMN session_id DROP NOT NULL;

-- One live request per code. Partial, because the table is mostly spent rows
-- within minutes of any activity and a code may be reused once its request is
-- gone.
CREATE UNIQUE INDEX cli_authorizations_user_code_idx
    ON cli_authorizations (user_code)
    WHERE user_code IS NOT NULL AND claimed_at IS NULL;

COMMENT ON COLUMN cli_authorizations.user_code IS
    'The short code a person reads and types. Not a credential: it identifies '
    'which pending request is being approved, and the device code the terminal '
    'kept is what exchanges for a session.';
