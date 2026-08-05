-- Cardinal 0001: foundation.
--
-- Establishes the two ideas the whole system rests on:
--   1. Identity is an immutable UUIDv7. Names are mutable attributes.
--   2. Access grants carry a validity period, enforced by the database.
--
-- Requires PostgreSQL 19+ (FOR PORTION OF). Verified against 19beta2.

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------

-- REQUIRED, and non-obvious: `WITHOUT OVERLAPS` primary keys compile down to
-- GiST exclusion constraints. The *scalar* columns in such a key (our uuids)
-- therefore need a GiST operator class, and uuid has no default one in core.
-- Without this extension every temporal table below fails at CREATE TABLE with
--   "data type uuid has no default operator class for access method gist".
--
-- Note this is unrelated to PG19 deprecating btree_gist's inet/cidr opclasses;
-- that change affects `gist_inet_ops` only. We use core `inet_ops` for inet.
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- ---------------------------------------------------------------------------
-- Entities: one identity space for every kind of principal and resource
-- ---------------------------------------------------------------------------

CREATE TYPE entity_type AS ENUM (
    'user',
    'group',
    'host',
    'service_account',
    'application',
    'device',
    'role'
);

-- The identity table. An entity's id is assigned once and never changes or is
-- reused, which is the whole point: this is what LDAP got wrong by making the
-- DN both the identity and the location. Renaming a user here is an UPDATE to
-- an attribute, not a structural change that breaks every reference to them.
CREATE TABLE entities (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    type        entity_type NOT NULL,

    -- Human-readable, unique per type, and freely mutable. Never an identifier.
    name        text        NOT NULL,

    display_name text,

    -- Schema-registry-governed extension attributes. Core attributes live in
    -- real columns on the typed tables; this is for org-specific additions.
    attrs       jsonb       NOT NULL DEFAULT '{}'::jsonb,

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    -- Soft delete. Entities are never hard-deleted: audit history must keep
    -- resolving, and a deleted user's past grants still need to be explicable.
    disabled_at timestamptz,

    CONSTRAINT entities_name_not_blank CHECK (length(trim(name)) > 0),
    CONSTRAINT entities_name_unique_per_type UNIQUE (type, name)
);

CREATE INDEX entities_type_idx    ON entities (type);
CREATE INDEX entities_attrs_idx   ON entities USING gin (attrs jsonb_path_ops);
CREATE INDEX entities_active_idx  ON entities (type, name) WHERE disabled_at IS NULL;

-- Full-text search over names, so the admin UI needs no external search engine.
CREATE INDEX entities_search_idx ON entities
    USING gin (to_tsvector('simple', name || ' ' || coalesce(display_name, '')));

COMMENT ON COLUMN entities.id IS
    'Immutable UUIDv7. Never changes, never reused. The only true identifier.';
COMMENT ON COLUMN entities.name IS
    'Mutable human-readable name, unique per type. NOT an identifier.';

-- ---------------------------------------------------------------------------
-- Schema registry: extension attributes are declared, not ad hoc
-- ---------------------------------------------------------------------------

CREATE TYPE attribute_kind AS ENUM (
    'string', 'integer', 'boolean', 'timestamp', 'uuid', 'inet', 'string_array'
);

CREATE TABLE attribute_definitions (
    id           uuid           PRIMARY KEY DEFAULT uuidv7(),
    entity_type  entity_type    NOT NULL,
    name         text           NOT NULL,
    kind         attribute_kind NOT NULL,

    required     boolean        NOT NULL DEFAULT false,
    multi_valued boolean        NOT NULL DEFAULT false,
    unique_value boolean        NOT NULL DEFAULT false,

    -- Drives encryption at rest and redaction in logs, decisions, and API
    -- responses. Declaring it here means no code path has to remember.
    sensitive    boolean        NOT NULL DEFAULT false,

    -- false => set once at creation, then immutable (e.g. posix_uid).
    mutable      boolean        NOT NULL DEFAULT true,

    description  text,
    created_at   timestamptz    NOT NULL DEFAULT now(),

    CONSTRAINT attrdef_unique UNIQUE (entity_type, name),
    CONSTRAINT attrdef_name_valid CHECK (name ~ '^[a-z][a-z0-9_]*$')
);

-- ---------------------------------------------------------------------------
-- Temporal membership: the flagship
-- ---------------------------------------------------------------------------

-- Group membership with a validity period, so that:
--   * a time-boxed grant is an INSERT with a bounded range, and expiry is
--     enforced by the query rather than by a cron job that might not run;
--   * early revocation is DELETE ... FOR PORTION OF, and Postgres truncates
--     the range for us;
--   * "who had access on date D" is `valid_period @> D`, not log archaeology.
--
-- The WITHOUT OVERLAPS key makes contradictory overlapping grants for the same
-- (group, member) pair impossible at the constraint level. Two different
-- members may of course overlap in time.
CREATE TABLE group_members (
    group_id     uuid      NOT NULL REFERENCES entities(id),
    member_id    uuid      NOT NULL REFERENCES entities(id),
    valid_period tstzrange NOT NULL,

    granted_by   uuid      NOT NULL REFERENCES entities(id),
    reason       text,

    PRIMARY KEY (group_id, member_id, valid_period WITHOUT OVERLAPS),

    -- Self-membership would make transitive resolution non-terminating.
    CONSTRAINT group_members_no_self CHECK (group_id <> member_id),
    CONSTRAINT group_members_bounded CHECK (NOT isempty(valid_period))
);

CREATE INDEX group_members_member_idx ON group_members (member_id);
CREATE INDEX group_members_period_idx ON group_members USING gist (valid_period);

COMMENT ON TABLE group_members IS
    'Time-bounded membership. Revoke with DELETE ... FOR PORTION OF, which '
    'truncates the range rather than erasing the historical fact of the grant.';

-- ---------------------------------------------------------------------------
-- Hash-chained event log: tamper-evident audit
-- ---------------------------------------------------------------------------

-- Every mutation appends here in the SAME transaction as the state change, so
-- the journal cannot drift from reality. Each row carries the hash of its
-- predecessor: editing or deleting any row breaks the chain detectably.
--
-- This is not event sourcing -- the state tables above remain authoritative.
-- It is an audit journal that can be cryptographically verified, including
-- after a restore, which a plain Postgres backup cannot tell you.
CREATE TABLE events (
    seq          bigint      GENERATED ALWAYS AS IDENTITY,
    id           uuid        NOT NULL DEFAULT uuidv7(),
    occurred_at  timestamptz NOT NULL DEFAULT now(),

    action       text        NOT NULL,
    entity_id    uuid,
    actor_id     uuid,
    payload      jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- sha256(prev_hash || seq || occurred_at || action || entity_id ||
    --        actor_id || payload), computed in Go so the algorithm is
    --        versioned with the code and testable in isolation.
    prev_hash    bytea,
    hash         bytea       NOT NULL,

    PRIMARY KEY (seq, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX events_entity_idx   ON events (entity_id, occurred_at DESC);
CREATE INDEX events_actor_idx    ON events (actor_id, occurred_at DESC);
CREATE INDEX events_occurred_idx ON events (occurred_at DESC);

-- Partitioned by time so retention is a partition drop rather than a mass
-- DELETE, and PG19's MERGE/SPLIT PARTITIONS can reshape it online.
CREATE TABLE events_2026 PARTITION OF events
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE TABLE events_2027 PARTITION OF events
    FOR VALUES FROM ('2027-01-01') TO ('2028-01-01');

-- Append-only, enforced in the database rather than trusted to the application.
CREATE RULE events_no_update AS ON UPDATE TO events DO INSTEAD NOTHING;
CREATE RULE events_no_delete AS ON DELETE TO events DO INSTEAD NOTHING;

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

-- Same temporal machinery as membership, so expiry and revocation work the way
-- everything else in Cardinal does.
CREATE TABLE sessions (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    subject_id   uuid        NOT NULL REFERENCES entities(id),

    -- sha256 of the bearer token. A database read must never yield a usable
    -- credential -- the same reason we don't store passwords in plaintext.
    token_hash   bytea       NOT NULL UNIQUE,

    valid_period tstzrange   NOT NULL,

    -- Authentication context, consumed by Cedar for step-up decisions
    -- (e.g. admin actions require device-bound auth newer than 5 minutes).
    auth_method  text        NOT NULL,
    auth_at      timestamptz NOT NULL DEFAULT now(),
    device_bound boolean     NOT NULL DEFAULT false,

    client_ip    inet,
    user_agent   text,

    CONSTRAINT sessions_bounded CHECK (NOT isempty(valid_period))
);

-- A partial index on "currently valid" is impossible: now() is STABLE, not
-- IMMUTABLE, so it cannot appear in an index predicate. Instead index the
-- range itself with a composite GiST (available because btree_gist is loaded),
-- which serves `WHERE subject_id = $1 AND valid_period @> now()` -- the query
-- behind "list my sessions" and "revoke every session for this user".
--
-- The hot path is lookup by token_hash, already covered by its UNIQUE index.
CREATE INDEX sessions_subject_period_idx ON sessions USING gist (subject_id, valid_period);

-- PG19 requires the core inet_ops GiST opclass here; btree_gist's gist_inet_ops
-- is deprecated for inet/cidr and blocks pg_upgrade.
CREATE INDEX sessions_ip_idx ON sessions USING gist (client_ip inet_ops);

-- NOTE: there is deliberately no `last_seen` column. Updating one on every
-- request is the standard way to make Postgres session storage slow and then
-- blame Postgres. If activity tracking is ever needed, append to a separate
-- table rather than hot-updating this one.
