-- Cardinal 0005: authorization policy and decision log.
--
-- One Cedar policy set governs every decision point: web access via Traefik
-- forwardAuth, SSH certificate issuance, sudo rules, and Cardinal's own admin
-- API. There is no second, weaker, vendor-specific ACL language guarding the
-- directory itself. See ADR 0005.

-- ---------------------------------------------------------------------------
-- Policy sets
-- ---------------------------------------------------------------------------

-- Policies are authored in git, validated in CI, and loaded here as versioned
-- immutable snapshots. Storing them rather than reading files at request time
-- means every node evaluates the same version, and a decision can name the
-- exact policy text that produced it months later.
CREATE TABLE policy_versions (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),

    -- Monotonic, human-quotable in an incident: "we were on version 47".
    version     bigint      GENERATED ALWAYS AS IDENTITY UNIQUE,

    -- The complete Cedar document. Whole sets are versioned rather than
    -- individual policies because Cedar evaluates a set: a permit means
    -- nothing without knowing which forbids were present alongside it.
    document    text        NOT NULL,

    -- sha256 of document, so an operator can confirm what is loaded matches
    -- what is in git without diffing by eye.
    digest      bytea       NOT NULL,

    description text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid        REFERENCES entities(id),

    -- Exactly one version is live. Activation is a pointer move, so rollback is
    -- immediate and does not require re-uploading anything.
    activated_at timestamptz,

    CONSTRAINT policy_document_not_blank CHECK (length(trim(document)) > 0)
);

CREATE INDEX policy_versions_active_idx ON policy_versions (activated_at DESC)
    WHERE activated_at IS NOT NULL;

-- Policy is evidence of what the rules were: editing a version after decisions
-- were made against it would make the decision log unverifiable.
--
-- A blanket ON UPDATE rule is the wrong tool here, because activation legitimately
-- moves `activated_at`. Instead a trigger freezes the parts that are evidence and
-- leaves the pointer free to move.
CREATE OR REPLACE FUNCTION policy_versions_freeze_document()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.document IS DISTINCT FROM OLD.document
       OR NEW.digest IS DISTINCT FROM OLD.digest
       OR NEW.version IS DISTINCT FROM OLD.version
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION
            'policy version % is immutable; publish a new version instead', OLD.version
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER policy_versions_immutable
    BEFORE UPDATE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION policy_versions_freeze_document();

-- Deletion is likewise refused: a decision referencing a vanished policy
-- version cannot be explained.
CREATE RULE policy_versions_no_delete AS ON DELETE TO policy_versions
    DO INSTEAD NOTHING;

-- ---------------------------------------------------------------------------
-- Decision log
-- ---------------------------------------------------------------------------

-- Every authorization decision, with the policy that made it.
--
-- This is the feature neither FreeIPA nor Keycloak can offer: "why was I
-- denied?" is answerable, by a person, without reading three configurations.
-- It is a product feature, not a debugging aid — the decision explorer UI is
-- built directly on this table.
CREATE TABLE decisions (
    id           uuid        NOT NULL DEFAULT uuidv7(),
    decided_at   timestamptz NOT NULL DEFAULT now(),

    -- Which surface asked. Kept as text rather than an enum so a new decision
    -- point does not require a migration before it can log anything.
    decision_point text      NOT NULL,

    principal_id uuid        REFERENCES entities(id),
    action       text        NOT NULL,
    resource     text        NOT NULL,

    allowed      boolean     NOT NULL,

    -- Cedar's diagnostic: the policy IDs that produced this outcome. Empty on
    -- a deny means nothing matched, which is the default-deny path and is
    -- itself worth being able to distinguish from an explicit forbid.
    reasons      text[]      NOT NULL DEFAULT '{}',
    errors       text[]      NOT NULL DEFAULT '{}',

    policy_version bigint,

    -- Enough context to reconstruct the question, without personal data:
    -- authentication method, device-bound flag, group names. No IP, no user
    -- agent (ADR 0010).
    context      jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- How long evaluation took. A policy set that has grown pathological shows
    -- up here before it shows up as a user complaint.
    duration_us  integer     NOT NULL DEFAULT 0,

    -- The partition key must be part of the primary key on a partitioned
    -- table: PostgreSQL cannot enforce uniqueness across partitions otherwise,
    -- since each partition has its own index.
    PRIMARY KEY (id, decided_at)
) PARTITION BY RANGE (decided_at);

CREATE INDEX decisions_principal_idx ON decisions (principal_id, decided_at DESC);
CREATE INDEX decisions_denied_idx ON decisions (decided_at DESC) WHERE NOT allowed;
CREATE INDEX decisions_resource_idx ON decisions (resource, decided_at DESC);

-- Time-partitioned like the event journal: decisions are high-volume and their
-- retention is an operational choice, not an audit obligation. Dropping an old
-- partition must not require rewriting a table.
CREATE TABLE decisions_2026 PARTITION OF decisions
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE TABLE decisions_2027 PARTITION OF decisions
    FOR VALUES FROM ('2027-01-01') TO ('2028-01-01');

COMMENT ON TABLE decisions IS
    'Every authorization decision and the policy that made it. Distinct from '
    'the events journal: that is tamper-evident audit of *changes*, this is '
    'high-volume observability of *access*, with its own retention.';
