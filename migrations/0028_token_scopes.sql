-- Cardinal 0028: what an access token is for.
--
-- A token authenticates its owner and is never device-bound, so policy already
-- refuses it every administrative action and every SSH certificate (ADR 0018).
-- What it does not refuse is everything else the owner can do without a
-- hardware key — and that turned out to be a wider set than the ADR's framing
-- suggests: reading the decision log, reading the active policy set, editing
-- the owner's own display name and email, and reaching every application the
-- owner can reach.
--
-- For a credential that lives in a CI variable, "everything my owner can do
-- that does not need a passkey" is a grant nobody would write down on purpose.
--
-- A scope narrows and can never widen. Policy still decides; this decides what
-- the token is even allowed to attempt. Both have to say yes, which is why this
-- is a column rather than a second authorization system.

ALTER TABLE access_tokens
    ADD COLUMN scopes text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN access_tokens.scopes IS
    'What this token may attempt. A ceiling, not a grant: policy still '
    'decides, and a scope can only narrow what the owner could already do. '
    'Empty means the token can authenticate and nothing else.';

-- Every token that already exists keeps exactly what it had.
--
-- The alternative — defaulting to empty and letting existing tokens stop
-- working on upgrade — would be a security improvement delivered as an outage,
-- and the people it broke would be running unattended pipelines with nobody
-- watching. Narrowing an existing token is a deliberate act, so it is done by
-- reissuing it.
UPDATE access_tokens
   SET scopes = ARRAY['identity', 'applications', 'profile', 'decisions', 'policy']
 WHERE scopes = '{}';
