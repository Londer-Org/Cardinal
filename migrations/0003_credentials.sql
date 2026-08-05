-- Cardinal 0003: credentials and emergency access.
--
-- Cardinal has no password column and this migration does not add one. The
-- primary credential is a WebAuthn passkey; TOTP exists for migration from
-- FreeIPA and as a second factor, never for privileged actions (ADR 0009).

-- ---------------------------------------------------------------------------
-- WebAuthn credentials
-- ---------------------------------------------------------------------------

CREATE TABLE webauthn_credentials (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    entity_id     uuid        NOT NULL REFERENCES entities(id),

    -- The authenticator's own credential identifier. Globally unique, and the
    -- lookup key during authentication.
    credential_id bytea       NOT NULL UNIQUE,

    -- COSE-encoded public key. Only ever a public key: unlike TOTP, the server
    -- holds nothing that could impersonate the user, so a database dump yields
    -- no usable credential.
    public_key    bytea       NOT NULL,

    -- Signature counter for clone detection. Many authenticators (notably
    -- synced passkeys) always report 0, which means "unsupported" rather than
    -- "suspicious" -- the distinction matters, see sign_count handling in Go.
    sign_count    bigint      NOT NULL DEFAULT 0,

    -- Authenticator model identifier. Used for enterprise attestation policy:
    -- an organisation may require a specific hardware key for admin accounts.
    aaguid        bytea,

    -- Whether the credential can be, and is, backed up to a cloud account.
    -- A synced passkey is more recoverable but less hardware-bound, so policy
    -- may demand backup_eligible = false for high-assurance roles.
    backup_eligible boolean   NOT NULL DEFAULT false,
    backup_state    boolean   NOT NULL DEFAULT false,

    -- User-supplied label ("YubiKey in the safe"), so people can tell their
    -- own credentials apart when revoking one.
    name          text        NOT NULL DEFAULT '',

    transports    text[]      NOT NULL DEFAULT '{}',

    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,

    -- Revoked rather than deleted, so "which credential authorised this?"
    -- stays answerable after the credential is gone.
    revoked_at    timestamptz,

    CONSTRAINT webauthn_credentials_name_len CHECK (length(name) <= 64)
);

CREATE INDEX webauthn_credentials_entity_idx ON webauthn_credentials (entity_id)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE webauthn_credentials IS
    'Passkey public keys. Contains no secret: a database dump yields nothing '
    'that can authenticate as anyone.';

-- ---------------------------------------------------------------------------
-- Break-glass challenges
-- ---------------------------------------------------------------------------

-- Challenge-response, so the offline private key is never transmitted and
-- cannot be captured from a terminal, a log, or the network.
--
-- Challenges live here rather than in process memory so that any node can
-- verify a challenge any other node issued, and so that single-use is enforced
-- by a database constraint rather than by hoping the right node handles the
-- reply.
CREATE TABLE break_glass_challenges (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    nonce       bytea       NOT NULL UNIQUE,

    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,

    -- Single use. A replayed challenge must fail even with a valid signature,
    -- so a captured (challenge, signature) pair is worthless.
    consumed_at timestamptz,

    -- Recorded for the incident review that should follow every use.
    issued_to_ip inet,

    CONSTRAINT break_glass_expiry_after_issue CHECK (expires_at > issued_at)
);

CREATE INDEX break_glass_challenges_pending_idx
    ON break_glass_challenges (expires_at)
    WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- Recovery codes
-- ---------------------------------------------------------------------------

-- Argon2id-hashed and single-use. Stored hashed for the same reason passwords
-- would be: a database read must not yield a usable credential.
CREATE TABLE recovery_codes (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    entity_id  uuid        NOT NULL REFERENCES entities(id),
    code_hash  bytea       NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz,

    UNIQUE (entity_id, code_hash)
);

CREATE INDEX recovery_codes_unused_idx ON recovery_codes (entity_id)
    WHERE used_at IS NULL;

-- ---------------------------------------------------------------------------
-- Session context for policy
-- ---------------------------------------------------------------------------

-- How long ago the subject actually authenticated, as opposed to how long the
-- session has existed. Cedar policy uses this for step-up: administrative
-- actions require a *fresh* authentication, not merely a valid session that
-- began fresh eight hours ago.
ALTER TABLE sessions
    ADD COLUMN credential_id uuid REFERENCES webauthn_credentials(id);

COMMENT ON COLUMN sessions.auth_at IS
    'When the subject last proved possession of a credential. Policy uses this '
    'for step-up; it is not the same as when the session was created.';
