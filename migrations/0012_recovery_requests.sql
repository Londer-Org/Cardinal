-- Cardinal 0012: dual-control recovery.
--
-- Issuing an enrollment invitation for an account that already has passkeys is
-- account takeover by shape: open the link, register a credential, and you are
-- that person. Until now one user-admin could do it to a directory-admin, which
-- made the tiers introduced in migration 0011 decorative — the narrow tier
-- contained a path to the broad one.
--
-- So the two cases are separated by what they actually are:
--
--   onboarding  the account has no credentials. Nobody can sign in to it
--               anyway, and someone had to create it. Single control.
--   recovery    the account can already sign in. Two administrators, or it
--               does not happen.
--
-- This is also what replaces the role separation break-glass used to provide
-- (ADR 0014): recovery without shell access to the host, but requiring two
-- people rather than one sealed envelope.

CREATE TABLE recovery_requests (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),

    subject_id   uuid        NOT NULL REFERENCES entities(id),
    requested_by uuid        NOT NULL REFERENCES entities(id),
    requested_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,

    -- Free-form text is not permitted in the audit journal (ADR 0010), but it
    -- belongs here: an approver deciding whether to restore someone's access
    -- needs to know why they are being asked, and the request is state rather
    -- than journal. It is deleted with the request.
    reason       text        NOT NULL DEFAULT '',

    completed_at timestamptz,
    cancelled_at timestamptz,

    CONSTRAINT recovery_requests_window CHECK (expires_at > requested_at),

    -- Nobody may request their own recovery. Someone who can authenticate does
    -- not need recovering, and someone who cannot could not have asked — so a
    -- self-request means a live session is being used to mint a second
    -- credential without a second person, which is the thing this table exists
    -- to prevent.
    CONSTRAINT recovery_requests_not_self CHECK (subject_id <> requested_by)
);

-- One live request per account, for the same reason invitations have one: two
-- outstanding requests make "cancel it" ambiguous.
CREATE UNIQUE INDEX recovery_requests_live_idx
    ON recovery_requests (subject_id)
 WHERE completed_at IS NULL AND cancelled_at IS NULL;

CREATE TABLE recovery_approvals (
    request_id  uuid        NOT NULL REFERENCES recovery_requests(id) ON DELETE CASCADE,
    approver_id uuid        NOT NULL REFERENCES entities(id),
    approved_at timestamptz NOT NULL DEFAULT now(),

    -- One approval each. Without this, "two approvals" is satisfiable by one
    -- administrator pressing the button twice, which is not dual control.
    PRIMARY KEY (request_id, approver_id)
);

COMMENT ON TABLE recovery_requests IS
    'Dual-control restoration of access to an account that already has '
    'credentials. Two distinct administrators, neither of them the subject.';
