-- Cardinal 0033: how much of the directory an application is told about.
--
-- The forwardAuth header and the OIDC groups claim are both built from the
-- transitive closure — every group a person belongs to, with no reference to
-- who is asking. So an internal wiki learns somebody is in `hr-investigations`
-- and a relying party set up by a contractor learns about
-- `project-acquisition-x`. Neither needed to know.
--
-- Migration 0013 already drew the line this needs. `entities.system` marks a
-- group whose membership is authority inside Cardinal, and `entities.owner_id`
-- records the application a group exists for — and said of the latter that "it
-- still appears in the groups claim like any other". The data model answered
-- the question; nothing asked it. [ADR 0032](../docs/adr/0032-an-application-sees-the-groups-it-owns.md)
--
-- The rule that must not bend, restated here because this is where somebody
-- looks when they wonder what these tables do: filtering changes what an
-- application is *told*, never what Cardinal *decides*. Cedar evaluates the
-- full closure exactly as before.

-- How much of the closure one application is told about.
--
-- A row per application rather than a column on entities: the setting belongs
-- to applications alone, and a column would invite the question of what it
-- means on a user.
CREATE TABLE application_group_projection (
    entity_id uuid PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,

    -- 'all' is the behaviour every deployment has today. 'owned' is the groups
    -- the application owns, plus whatever application_visible_groups adds.
    mode text NOT NULL CHECK (mode IN ('all', 'owned')),

    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid REFERENCES entities(id)
);

COMMENT ON TABLE application_group_projection IS
    'How much of a subject''s group closure this application is told about. '
    'Affects the forwardAuth header and the OIDC groups claim only — Cedar '
    'always evaluates the full closure, so this cannot change a decision.';

-- Groups an application may be told about that it does not own.
--
-- A list of facts rather than a pattern. A wildcard would make "which groups
-- does this application see" a question nobody can answer without evaluating
-- it, and that question is the whole reason an operator opens this page.
CREATE TABLE application_visible_groups (
    application_id uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    group_id       uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,

    added_at timestamptz NOT NULL DEFAULT now(),
    added_by uuid REFERENCES entities(id),

    PRIMARY KEY (application_id, group_id)
);

CREATE INDEX application_visible_groups_group_idx
    ON application_visible_groups (group_id);

COMMENT ON TABLE application_visible_groups IS
    'Groups an application is told about that it does not own. The escape '
    'hatch for a projection in owned mode; ignored in all mode.';

-- Every application that already exists keeps the behaviour it has.
--
-- This is what makes the change expand-only in behaviour and not merely in
-- schema: an upgrade tells no application anything different. Newly registered
-- applications are written 'owned' by the registration path, which is the
-- asymmetry ADR 0032 argues for — existing deployments untouched, anything new
-- narrow by default.
INSERT INTO application_group_projection (entity_id, mode)
SELECT id, 'all' FROM entities WHERE type = 'application'
ON CONFLICT (entity_id) DO NOTHING;

-- A system group is never projected to an application, and that falls out of
-- migration 0013 rather than needing a rule here: a system group cannot be
-- owned, so it is never in the owned set, and this constraint stops it being
-- added as an exception either.
--
-- Membership of directory-admins is authority inside Cardinal. An application
-- branching on it would be reading a Cardinal internal as though it were one of
-- its own roles.
--
-- The three identifiers are written out because a CHECK cannot read another
-- table, and that is a real limitation rather than a tidy one: a system group
-- added by a later migration would not be covered here. So this is defence in
-- depth and not the rule. The rule is enforced where `entities.system` can
-- actually be read — in the store, on the way in — and this constraint exists
-- to catch a direct INSERT that went around it.
ALTER TABLE application_visible_groups
    ADD CONSTRAINT application_visible_groups_never_system
    CHECK (group_id NOT IN (
        '00000000-0000-7000-8000-00000000ad11',  -- directory-admins
        '00000000-0000-7000-8000-00000000ad12',  -- user-admins
        '00000000-0000-7000-8000-00000000ad13'   -- security-admins
    ));
