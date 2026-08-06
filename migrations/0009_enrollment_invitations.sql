-- Cardinal 0009: enrollment invitations.
--
-- Until now there was no safe way to onboard anyone. `cardinal user create`
-- made an account nobody could sign in to, and the only route to a first
-- passkey was break-glass — an offline key that can assume *any* account. So
-- adding a colleague meant either handing them that key or an administrator
-- break-glassing into their account and enrolling a credential the
-- administrator physically possessed. Both are worse than the problem.
--
-- An invitation is a bearer credential, deliberately a weak one: it authorises
-- exactly one act (registering a passkey on one named account), once, within a
-- short window, and it is revocable. That is the whole design — it must be safe
-- to send over chat or email, because that is what will happen to it.
--
-- The alternative most systems reach for is a generated first-use password.
-- That is a credential which exists off the user's device, is phishable, is
-- reusable until changed, and tends to be reused elsewhere. Cardinal has no
-- password column and this is not the feature that adds one.

CREATE TABLE enrollment_invitations (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),

    subject_id  uuid        NOT NULL REFERENCES entities(id),

    -- sha256 of the token, never the token. A database read must not yield a
    -- usable credential — the same rule as sessions and recovery codes.
    token_hash  bytea       NOT NULL UNIQUE,

    issued_by   uuid        REFERENCES entities(id),
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,

    -- Redemption and revocation are recorded rather than deleted, so "this
    -- invitation was used at 14:03 by someone at this address" survives, and an
    -- unused invitation is distinguishable from one that never existed.
    redeemed_at timestamptz,
    redeemed_ip inet,
    revoked_at  timestamptz,

    CONSTRAINT enrollment_invitations_window CHECK (expires_at > issued_at)
);

-- One live invitation per account.
--
-- Issuing a second while the first is outstanding would leave two working
-- links, and revoking "the" invitation would then be ambiguous — which is
-- exactly the state you do not want when revoking is the thing you are doing in
-- a hurry. Issuing again replaces, and the store enforces that explicitly.
CREATE UNIQUE INDEX enrollment_invitations_live_idx
    ON enrollment_invitations (subject_id)
 WHERE redeemed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX enrollment_invitations_expiry_idx
    ON enrollment_invitations (expires_at)
 WHERE redeemed_at IS NULL AND revoked_at IS NULL;

COMMENT ON TABLE enrollment_invitations IS
    'Single-use, short-lived authorisation to register a first passkey on one '
    'named account. Safe to send over an untrusted channel: it grants no '
    'session, cannot administer, and expires unused.';

COMMENT ON COLUMN enrollment_invitations.token_hash IS
    'sha256 of the invitation token. The token itself is shown once, at issue, '
    'and is not recoverable.';
