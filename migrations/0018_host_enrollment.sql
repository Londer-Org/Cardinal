-- Cardinal 0018: a machine proves which host it is.
--
-- Until now a host was a name in the directory that policy could refer to.
-- Nothing stopped a different machine claiming it, which is fine while the only
-- consumer is a *user* asking for a certificate — that decision is about the
-- user, and the host name is just the resource. It stops being fine the moment
-- the host itself asks for something: its sudoers rules, the POSIX identities
-- it should serve, or an X.509 certificate for its own name.
--
-- The shape is the one ADR 0013 chose for people, because the problem is the
-- same: a credential has to reach something that has none yet.
--
--   * A single-use token, hashed at rest, with a short life.
--   * Redeeming it registers a key the machine generated itself, so Cardinal
--     never holds a host's private key and cannot leak one it never had.
--   * Redemption is recorded rather than deleted, so an unused token is
--     distinguishable from one that never existed.
--
-- What differs from a person: there is no second factor and no recovery. A host
-- that loses its key is re-enrolled by whoever can reach its console, which is
-- the same authority that could re-provision the machine entirely — so a
-- recovery path would protect nothing that is not already lost.

CREATE TABLE host_enrollment_tokens (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),

    host_id     uuid        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,

    -- sha256 of the token, never the token.
    token_hash  bytea       NOT NULL UNIQUE,

    issued_by   uuid        REFERENCES entities(id),
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,

    redeemed_at timestamptz,
    redeemed_ip inet,
    revoked_at  timestamptz,

    CONSTRAINT host_enrollment_tokens_window CHECK (expires_at > issued_at)
);

CREATE INDEX host_enrollment_tokens_host_idx ON host_enrollment_tokens (host_id);

COMMENT ON TABLE host_enrollment_tokens IS
    'Single-use tokens that let a machine register its key once. Hashed at rest.';

-- The key a host authenticates with afterwards.
--
-- Public only. The machine generated the pair and keeps the private half, so
-- there is nothing here an attacker could steal and use to impersonate a host —
-- the worst a database read yields is the ability to recognise one.
--
-- A host may hold more than one over time: re-enrolling after a rebuild issues
-- a new key, and the old row stays with its window closed so that "this host
-- authenticated at 03:14 with a key retired last month" remains answerable.
CREATE TABLE host_credentials (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    host_id      uuid        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,

    -- authorized_keys format, as the machine presented it.
    public_key   text        NOT NULL,
    fingerprint  text        NOT NULL,

    -- The same temporal machinery as everything else: retiring a key closes the
    -- range rather than deleting the row.
    valid_period tstzrange   NOT NULL,

    enrolled_at  timestamptz NOT NULL DEFAULT now(),
    enrolled_ip  inet,
    last_seen_at timestamptz,

    CONSTRAINT host_credentials_period_not_empty CHECK (NOT isempty(valid_period))
);

-- Lookup is by fingerprint on every host request, so that is the index that
-- matters. Unique across live credentials only: a retired key may legitimately
-- reappear in history, and two hosts presenting the same live key is the
-- ambiguity worth forbidding.
CREATE UNIQUE INDEX host_credentials_live_fingerprint
    ON host_credentials (fingerprint)
 WHERE upper(valid_period) = 'infinity'::timestamptz;

CREATE INDEX host_credentials_host_idx ON host_credentials (host_id);

COMMENT ON TABLE host_credentials IS
    'Public keys hosts authenticate with. Cardinal never holds the private half.';
