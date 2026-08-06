-- Cardinal 0014: sessions that survive being used.
--
-- valid_period was set once, at sign-in, and ran for twelve hours regardless of
-- what its holder was doing. So somebody halfway through a morning's work was
-- signed out because of when they started, not because they had stopped — and
-- the only signal was the page they were on emptying itself.
--
-- Two clocks instead of one, which is what every session system converges on:
--
--   idle      the session ends this long after the last request. Extended as
--             it is used, so activity keeps it alive.
--   absolute  the session ends here no matter what. Not extendable, so a
--             session cannot be kept alive indefinitely by a browser tab
--             polling in the background — or by whoever stole the cookie.
--
-- The absolute cap is what makes "everyone re-authenticates eventually" true
-- rather than aspirational. Without it, sliding expiry means a stolen session
-- token is valid forever provided it is used.

ALTER TABLE sessions
    ADD COLUMN absolute_expiry timestamptz;

-- Existing sessions get a cap from where they are. Leaving it NULL would mean
-- "no cap", which is the one value this column exists to prevent.
UPDATE sessions
   SET absolute_expiry = greatest(upper(valid_period), now() + interval '7 days')
 WHERE absolute_expiry IS NULL;

ALTER TABLE sessions
    ALTER COLUMN absolute_expiry SET NOT NULL;

ALTER TABLE sessions
    ADD CONSTRAINT sessions_absolute_after_start
    CHECK (absolute_expiry > lower(valid_period));

COMMENT ON COLUMN sessions.absolute_expiry IS
    'The hard end of this session, never extended. Idle expiry lives in '
    'valid_period and slides while the session is used; this is what stops a '
    'session being kept alive indefinitely by whoever holds the cookie.';
