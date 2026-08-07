-- Cardinal 0017: the SSH certificate authority.
--
-- Whoever holds this key can mint a certificate for any user on any host, and
-- sshd will accept it because that is what the key means. The compromise is
-- fleet-wide, silent — nothing distinguishes a forged certificate from a real
-- one in a log — and recovering means changing what every host trusts.
--
-- ADR 0021 decided the custody model, and two of its conclusions are visible in
-- this table:
--
--   * The private key is sealed with its own encryption key, separate from the
--     one protecting OIDC signing keys. One leaked configuration file must not
--     yield both the token signer and the fleet.
--
--   * There is no single-key assumption anywhere. OpenSSH certificates cannot
--     be chained, so whatever signs must itself be trusted by every host — but
--     `TrustedUserCAKeys` accepts several keys at once, which is what makes
--     rotation possible at all. So this table holds a *set*: a new key is
--     published and trusted everywhere before it starts signing, and the old
--     one stops signing before it stops being trusted.
--
-- Rotation is designed in from the start rather than added later, because a
-- rotation procedure retrofitted to a live fleet is how a compromised key stays
-- in place for months.

CREATE TABLE ssh_ca_keys (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),

    -- Ed25519: small, fast, no parameter choices to get wrong, and supported by
    -- every OpenSSH anyone still runs.
    algorithm     text NOT NULL DEFAULT 'ssh-ed25519',

    -- AES-GCM sealed, nonce prepended. The same shape as oidc_signing_keys,
    -- deliberately: one sealing implementation to review rather than two.
    private_key_sealed bytea NOT NULL,

    -- The authorized_keys-format public key. Not a secret — it is what goes
    -- into TrustedUserCAKeys on every host, so it is read far more often than
    -- the private half and is stored ready to serve.
    public_key    text NOT NULL,

    -- SHA-256 fingerprint, for recognising a key in logs and in `cardinal ssh
    -- ca list` without printing the whole thing.
    fingerprint   text NOT NULL UNIQUE,

    created_at    timestamptz NOT NULL DEFAULT now(),

    -- Three states, and the order between them is the rotation procedure:
    --
    --   signing            active_at set, retired_at null
    --   trusted, not signing   retired_at set, valid_until in the future
    --   withdrawn          valid_until passed; safe to remove from hosts
    --
    -- A key is published and distributed *before* active_at, so no certificate
    -- is ever signed by something the fleet does not yet trust.
    active_at     timestamptz,
    retired_at    timestamptz,
    valid_until   timestamptz
);

-- At most one key signs at a time. A partial unique index rather than
-- application logic: two active signing keys is not a state to handle
-- gracefully, it is one to make unrepresentable.
CREATE UNIQUE INDEX ssh_ca_keys_one_active
    ON ssh_ca_keys ((active_at IS NOT NULL))
 WHERE active_at IS NOT NULL AND retired_at IS NULL;

COMMENT ON TABLE ssh_ca_keys IS
    'SSH certificate authority keys. Several may be trusted at once; exactly one signs.';
COMMENT ON COLUMN ssh_ca_keys.public_key IS
    'authorized_keys format. Goes into TrustedUserCAKeys on every host.';

-- Issued certificates.
--
-- The certificate itself is not stored — it is short-lived, it is handed to the
-- user, and keeping a copy would create a place to steal them from. What is
-- kept is the fact of issuance, which is what an audit needs: who, for which
-- host, as which local user, and under which CA key.
--
-- Revocation is deliberately absent. A certificate measured in minutes is
-- revoked by refusing to renew it; maintaining a KRL and distributing it to
-- every host to withdraw something that expires before the distribution
-- finishes is machinery that buys nothing.
CREATE TABLE ssh_certificates (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    serial        bigint NOT NULL,

    subject_id    uuid NOT NULL REFERENCES entities(id),
    host_id       uuid REFERENCES entities(id),

    -- The local accounts this certificate is good for. Derived from policy, not
    -- from what the client asked for.
    principals    text[] NOT NULL,

    ca_key_id     uuid NOT NULL REFERENCES ssh_ca_keys(id),
    key_id        text NOT NULL,

    issued_at     timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,

    CONSTRAINT ssh_certificates_expiry_after_issue CHECK (expires_at > issued_at)
);

CREATE INDEX ssh_certificates_subject_idx ON ssh_certificates (subject_id, issued_at DESC);
CREATE INDEX ssh_certificates_serial_idx ON ssh_certificates (serial);

COMMENT ON TABLE ssh_certificates IS
    'A record that a certificate was issued. The certificate itself is not stored: it is short-lived, and a copy would be somewhere to steal one from.';
