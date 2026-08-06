-- Cardinal 0015: remember what the relying party asked for about authentication.
--
-- An authorization request can say how the user must be authenticated, not just
-- who they are. OpenID Connect Core gives a client two ways to say it:
--
--   prompt=login   authenticate again, whatever session already exists
--   prompt=none    do not show the user anything; if that means you cannot
--                  complete, return login_required instead
--   max_age=N      the authentication must be no older than N seconds
--
-- Cardinal accepted all three, stored none of them, and silently completed
-- every one from whatever session happened to exist. That is a real failure
-- rather than a missing feature: a client asking for prompt=login is usually
-- doing it before something that matters — a payment, a privilege change — and
-- an identity provider that answers "yes, they authenticated" without having
-- asked has told it something untrue.
--
-- Found by the OpenID Foundation conformance suite, which fails
-- oidcc-prompt-login, oidcc-prompt-none-not-logged-in and oidcc-max-age-1 on
-- exactly this.
--
-- Nullable and empty-by-default, so requests already in flight when this
-- applies keep their current meaning: no constraint on how authentication
-- happened.

ALTER TABLE oidc_auth_requests
    ADD COLUMN prompt  text[],
    -- Seconds, as the parameter is defined. Stored rather than resolved to an
    -- instant, because the comparison belongs at completion time: the session
    -- may be re-authenticated between the request arriving and the user
    -- finishing, which is the entire point of asking.
    ADD COLUMN max_age bigint;

COMMENT ON COLUMN oidc_auth_requests.prompt IS
    'OIDC prompt values from the authorization request: none, login, consent, select_account.';
COMMENT ON COLUMN oidc_auth_requests.max_age IS
    'OIDC max_age in seconds; NULL means the client did not constrain authentication age.';
