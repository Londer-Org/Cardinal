-- Cardinal 0006: OpenID Connect provider.
--
-- Applications are directory entities, not a separate registry. An application
-- can therefore be a member of a group, be the subject of a Cedar policy, and
-- appear in the audit trail exactly like a person — which is what lets one
-- policy set govern "who may reach this app" and "which apps exist" together.

-- ---------------------------------------------------------------------------
-- Clients
-- ---------------------------------------------------------------------------

CREATE TYPE oidc_auth_method AS ENUM (
    'none',            -- public client, PKCE only
    'client_secret_basic',
    'client_secret_post',
    'private_key_jwt'  -- strongest: no shared secret exists to leak
);

CREATE TABLE oidc_clients (
    -- The application's directory entity. Deleting the entity is impossible
    -- (soft delete only), so a token's audience always resolves.
    entity_id     uuid PRIMARY KEY REFERENCES entities(id),

    -- Public identifier. Opaque and unguessable rather than a readable slug:
    -- client_id appears in browser URLs and referrer headers, so a readable one
    -- leaks the shape of internal systems to anywhere a user navigates next.
    client_id     text NOT NULL UNIQUE,

    -- Argon2id, like any other credential. NULL for public clients, which have
    -- no secret because they cannot keep one.
    secret_hash   bytea,

    auth_method   oidc_auth_method NOT NULL DEFAULT 'none',

    redirect_uris             text[] NOT NULL DEFAULT '{}',
    post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',

    grant_types   text[] NOT NULL DEFAULT '{authorization_code}',
    scopes        text[] NOT NULL DEFAULT '{openid,profile,email,groups}',

    -- PKCE is required by default and for every client type.
    --
    -- OAuth 2.1 makes it mandatory even for confidential clients, because a
    -- leaked authorization code is otherwise enough on its own. Making it
    -- opt-out rather than opt-in means the insecure choice has to be made
    -- deliberately and is visible in the row.
    require_pkce  boolean NOT NULL DEFAULT true,

    -- Permits http:// redirect URIs. Named to be embarrassing in a production
    -- table listing, because that is exactly where it should stand out.
    dev_mode      boolean NOT NULL DEFAULT false,

    access_token_lifetime interval NOT NULL DEFAULT '15 minutes',
    id_token_lifetime     interval NOT NULL DEFAULT '15 minutes',
    refresh_token_lifetime interval NOT NULL DEFAULT '720 hours',

    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    -- A confidential client with no secret could never authenticate; a public
    -- client with one implies a secret that cannot be kept. Both are
    -- misconfigurations that would only surface at first use.
    CONSTRAINT oidc_clients_secret_matches_method CHECK (
        (auth_method = 'none' AND secret_hash IS NULL)
        OR (auth_method = 'private_key_jwt' AND secret_hash IS NULL)
        OR (auth_method IN ('client_secret_basic', 'client_secret_post')
            AND secret_hash IS NOT NULL)
    ),

    CONSTRAINT oidc_clients_needs_redirect CHECK (
        cardinality(redirect_uris) > 0
    )
);

CREATE INDEX oidc_clients_client_id_idx ON oidc_clients (client_id);

-- Public keys for private_key_jwt clients. Asymmetric client authentication:
-- Cardinal holds only a public key, so a database read yields nothing that can
-- authenticate as the client.
CREATE TABLE oidc_client_keys (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    entity_id  uuid NOT NULL REFERENCES oidc_clients(entity_id),
    key_id     text NOT NULL,
    public_key bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),

    UNIQUE (entity_id, key_id)
);

-- ---------------------------------------------------------------------------
-- Authorization requests
-- ---------------------------------------------------------------------------

-- One in-flight authorization code flow.
--
-- Persisted rather than held in memory so any node can complete a flow another
-- began, and so single-use of the code is a database guarantee rather than a
-- hope that the same node handles the callback (ADR 0004).
CREATE TABLE oidc_auth_requests (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    client_id     text NOT NULL,

    -- NULL until the user has authenticated. The request exists first: the
    -- browser arrives at /authorize before anyone has proven who they are.
    subject_id    uuid REFERENCES entities(id),

    scopes        text[] NOT NULL DEFAULT '{}',
    response_type text   NOT NULL,
    redirect_uri  text   NOT NULL,
    state         text,
    nonce         text,

    -- PKCE. The verifier is never stored — only the challenge the client sent,
    -- against which the verifier is checked at token exchange.
    code_challenge        text,
    code_challenge_method text,

    -- The authorization code, set once the user has consented. Hashed for the
    -- same reason a session token is: a database read must not yield something
    -- redeemable.
    code_hash     bytea UNIQUE,

    auth_time     timestamptz,
    amr           text[] NOT NULL DEFAULT '{}',

    done          boolean NOT NULL DEFAULT false,
    consumed_at   timestamptz,

    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,

    CONSTRAINT oidc_auth_requests_expiry CHECK (expires_at > created_at)
);

CREATE INDEX oidc_auth_requests_pending_idx ON oidc_auth_requests (expires_at)
    WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- Tokens
-- ---------------------------------------------------------------------------

CREATE TABLE oidc_tokens (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    client_id     text NOT NULL,
    subject_id    uuid NOT NULL REFERENCES entities(id),

    scopes        text[] NOT NULL DEFAULT '{}',
    audience      text[] NOT NULL DEFAULT '{}',

    -- Refresh tokens are hashed. Access tokens are JWTs and are not stored at
    -- all: storing them would create a second place to leak them from without
    -- adding a check the signature does not already provide.
    refresh_hash  bytea UNIQUE,

    -- Links the token back to the browser session that produced it, so signing
    -- out of Cardinal can revoke tokens issued from that session — otherwise
    -- "sign out" leaves live access tokens behind for up to their lifetime.
    session_id    uuid REFERENCES sessions(id),

    auth_time     timestamptz NOT NULL,
    amr           text[] NOT NULL DEFAULT '{}',

    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz
);

CREATE INDEX oidc_tokens_subject_idx ON oidc_tokens (subject_id)
    WHERE revoked_at IS NULL;
CREATE INDEX oidc_tokens_session_idx ON oidc_tokens (session_id)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Signing keys
-- ---------------------------------------------------------------------------

-- Keys that sign ID tokens and JWT access tokens.
--
-- The private key is stored ENCRYPTED, with the encryption key coming from
-- configuration rather than the database — the same reasoning as the
-- break-glass public key (ADR 0009). A database compromise alone therefore does
-- not yield the ability to forge tokens for every application, which it would
-- if the key were stored in the clear.
--
-- This is an interim answer. Proper key management (KMS, HSM) is an open
-- question tracked in docs/adr/README.md.
CREATE TABLE oidc_signing_keys (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    key_id        text NOT NULL UNIQUE,
    algorithm     text NOT NULL DEFAULT 'RS256',

    -- AES-GCM sealed. The nonce is prepended to the ciphertext.
    private_key_sealed bytea NOT NULL,
    public_key    bytea NOT NULL,

    created_at    timestamptz NOT NULL DEFAULT now(),

    -- Rotation: a key stops signing before it stops verifying, so tokens issued
    -- under the old key remain valid until they expire naturally.
    retired_at    timestamptz,
    expires_at    timestamptz
);

CREATE INDEX oidc_signing_keys_active_idx ON oidc_signing_keys (created_at DESC)
    WHERE retired_at IS NULL;
