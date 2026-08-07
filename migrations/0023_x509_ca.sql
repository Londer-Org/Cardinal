-- Cardinal 0023: the X.509 certificate authority, and ACME.
--
-- ADR 0023 decided this, and its reasoning is worth restating because it is the
-- reason the table below looks nothing like a general-purpose PKI:
--
--   A CA's hard question is not signing. It is knowing who is asking and
--   whether they should have it.
--
-- Cardinal already answers that. A host has proved which host it is (ADR 0024),
-- the names it may hold are written down (0020_host_aliases), and Cedar decides.
-- What is left is encoding, which crypto/x509 does.
--
-- The custody model is ADR 0021's, transferred wholesale from the SSH side —
-- sealed with its own key, rotation designed in rather than retrofitted. One
-- difference, and it is in X.509's favour: certificates chain. An offline root
-- signing a short-lived online intermediate is possible here and is the
-- recommended shape, which is why this table holds a chain rather than a key.

CREATE TABLE x509_ca_keys (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),

    -- ECDSA P-256. Universally supported, small, and no parameter choices that
    -- can be got wrong — the same reasoning that picked Ed25519 for SSH, landing
    -- differently only because Ed25519 X.509 is still refused by enough clients
    -- to be a support problem rather than a preference.
    algorithm     text NOT NULL DEFAULT 'ecdsa-p256',

    -- AES-GCM sealed, nonce prepended. The same shape as ssh_ca_keys and
    -- oidc_signing_keys: one sealing implementation to review rather than three.
    private_key_sealed bytea NOT NULL,

    -- This key's own certificate, DER. Self-signed when Cardinal generated the
    -- root; signed by something else when an existing root was adopted.
    certificate   bytea NOT NULL,

    -- Everything above it, leaf-to-root order, excluding this certificate and
    -- excluding the root. What a TLS server must present alongside a leaf.
    --
    -- Empty when this key *is* the root, which is the simple deployment and the
    -- one that needs no explanation. Non-empty is the shape ADR 0023 recommends:
    -- a root that stays offline and never appears in this database at all.
    chain         bytea[] NOT NULL DEFAULT '{}',

    -- SHA-256 of the certificate, for naming a key in logs and in `cardinal
    -- x509 ca list` without printing it.
    fingerprint   text NOT NULL UNIQUE,

    subject       text NOT NULL,
    not_before    timestamptz NOT NULL,
    not_after     timestamptz NOT NULL,

    created_at    timestamptz NOT NULL DEFAULT now(),

    -- The same three states as the SSH authority, and the same ordering
    -- discipline: published and distributed before it signs, stops signing
    -- before it stops being trusted.
    active_at     timestamptz,
    retired_at    timestamptz,

    CONSTRAINT x509_ca_keys_validity CHECK (not_after > not_before)
);

CREATE UNIQUE INDEX x509_ca_keys_one_active
    ON x509_ca_keys ((active_at IS NOT NULL))
 WHERE active_at IS NOT NULL AND retired_at IS NULL;

COMMENT ON TABLE x509_ca_keys IS
    'X.509 authority keys. Several may be trusted at once; exactly one signs.';
COMMENT ON COLUMN x509_ca_keys.chain IS
    'Intermediates above this key, leaf-to-root, excluding the root. Empty when this key is the root.';

-- ---------------------------------------------------------------------------
-- ACME
-- ---------------------------------------------------------------------------

-- An ACME account, bound to a host.
--
-- The binding is the whole point and is what distinguishes this from a public
-- CA. Let's Encrypt has no idea who you are and must therefore prove you control
-- a name; Cardinal knows exactly which machine is asking, because it authorised
-- the account against a credential handed to that machine.
--
-- The mechanism is External Account Binding (RFC 8555 §7.3.4), chosen because it
-- is the standard one — cert-manager, lego, certbot and acme.sh all speak it —
-- and because the alternative was inventing a way to carry Cardinal's own host
-- signature through a protocol that has no room for it.
CREATE TABLE acme_accounts (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),

    -- The entity this account may request certificates for. A host today;
    -- service accounts are the obvious extension and the column does not care.
    subject_id  uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,

    -- The client's account key, JWK thumbprint (RFC 7638). Every subsequent
    -- request is signed by the key this identifies.
    thumbprint  text NOT NULL UNIQUE,

    -- The key itself, so signatures can be verified without the client
    -- re-sending it. JSON, as it arrived.
    public_jwk  jsonb NOT NULL,

    contact     text[] NOT NULL DEFAULT '{}',

    created_at  timestamptz NOT NULL DEFAULT now(),
    -- Deactivated rather than deleted: an account that issued certificates last
    -- month is why those certificates exist, and the journal references it.
    deactivated_at timestamptz
);

CREATE INDEX acme_accounts_subject_idx ON acme_accounts (subject_id);

-- The credential that lets a machine create an account in the first place.
--
-- Single-use like a host enrollment token, and for the same reason: it is handed
-- over a channel Cardinal does not control, and one that keeps working is one
-- that keeps working for whoever finds it later.
CREATE TABLE acme_eab_credentials (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    subject_id  uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,

    -- The `kid` a client sends. Not secret — it names the credential.
    key_id      text NOT NULL UNIQUE,

    -- The HMAC key, sealed. The client signs its account key with this to prove
    -- the account belongs to that host.
    hmac_sealed bytea NOT NULL,

    issued_by   uuid REFERENCES entities(id),
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    redeemed_at timestamptz,
    revoked_at  timestamptz,

    CONSTRAINT acme_eab_window CHECK (expires_at > issued_at)
);

CREATE INDEX acme_eab_subject_idx ON acme_eab_credentials (subject_id);

-- Anti-replay nonces.
--
-- Every ACME request carries one and it may be used once. A table rather than
-- memory because Cardinal is meant to run as several stateless nodes, and a
-- nonce issued by one that the next request reaches a different one with must
-- still be valid — the failure otherwise is intermittent and looks like a
-- client bug.
CREATE TABLE acme_nonces (
    nonce      text PRIMARY KEY,
    issued_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX acme_nonces_issued_idx ON acme_nonces (issued_at);

-- An order, and what it is for.
--
-- The identifiers are stored resolved rather than as the client sent them,
-- because what a client asks for and what it is entitled to are different
-- questions and only the second belongs in a certificate.
CREATE TABLE acme_orders (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    account_id  uuid NOT NULL REFERENCES acme_accounts(id) ON DELETE CASCADE,

    -- pending → ready → processing → valid, or invalid. RFC 8555 §7.1.6.
    --
    -- `pending` never appears here in practice: Cardinal knows which names the
    -- host may hold, so there is nothing for a challenge to prove and the order
    -- is ready the moment it is created.
    status      text NOT NULL,

    identifiers text[] NOT NULL,

    not_before  timestamptz,
    not_after   timestamptz,

    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,

    -- Set when finalised. The certificate is stored, unlike the SSH side, and
    -- the difference is not an inconsistency: ACME requires the certificate be
    -- retrievable at a URL after issuance, and a client that loses the response
    -- has no other way to recover it. It is a public document either way.
    certificate bytea,
    ca_key_id   uuid REFERENCES x509_ca_keys(id),
    serial      text,

    CONSTRAINT acme_orders_status CHECK (
        status IN ('pending', 'ready', 'processing', 'valid', 'invalid'))
);

CREATE INDEX acme_orders_account_idx ON acme_orders (account_id, created_at DESC);
CREATE INDEX acme_orders_serial_idx ON acme_orders (serial) WHERE serial IS NOT NULL;

-- An authorization, one per identifier.
--
-- Present because RFC 8555 requires an order to reference them and clients
-- fetch them, not because anything is being authorised here that was not
-- already decided. Every one Cardinal creates is born `valid`: the host proved
-- which host it is when it enrolled, and the names it may hold are in the
-- directory. There is nothing left for a challenge to demonstrate.
CREATE TABLE acme_authorizations (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    order_id   uuid NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
    identifier text NOT NULL,
    status     text NOT NULL,
    expires_at timestamptz NOT NULL,

    CONSTRAINT acme_authz_status CHECK (
        status IN ('pending', 'valid', 'invalid', 'deactivated', 'expired', 'revoked'))
);

CREATE INDEX acme_authz_order_idx ON acme_authorizations (order_id);

COMMENT ON TABLE acme_authorizations IS
    'One per identifier. Always born valid: control of the name was established at enrollment, not by a challenge.';
