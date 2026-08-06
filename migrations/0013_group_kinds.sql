-- Cardinal 0013: system groups, and groups that belong to an application.
--
-- Two kinds of group had been sharing one shape.
--
-- Some confer authority *inside* Cardinal: directory-admins, user-admins,
-- security-admins. Membership of one of those is a grant of administrative
-- power, and granting it is therefore an administrative act of the same weight
-- as the power it hands over.
--
-- The rest mean nothing to Cardinal and everything to somebody else. An
-- application registered as `aura` wants `aura-users` and `aura-admins`, which
-- Cardinal delivers in the groups claim and never interprets. Those are
-- ordinary directory data, and managing them is ordinary user administration.
--
-- Treating them alike was an escalation: granting membership is ManageUsers, so
-- a user-admin could grant themselves directory-admins and become one. The
-- tier boundary introduced in migration 0011 was decorative for exactly as long
-- as this column did not exist.

ALTER TABLE entities
    ADD COLUMN system boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN entities.system IS
    'Membership of this group confers authority within Cardinal itself. '
    'Granting or revoking it requires AdministerDirectory, not merely '
    'ManageUsers — otherwise a narrow tier can hand itself a broad one.';

UPDATE entities SET system = true
 WHERE id IN (
    '00000000-0000-7000-8000-00000000ad11',  -- directory-admins
    '00000000-0000-7000-8000-00000000ad12',  -- user-admins
    '00000000-0000-7000-8000-00000000ad13'   -- security-admins
 );

-- Groups an application owns.
--
-- Nothing about this changes what Cardinal does with the group: it still
-- appears in the groups claim like any other. It records who it is *for*, so an
-- administrator looking at `aura` can see `aura-users` beside it rather than
-- hunting through a flat list, and so retiring an application shows what it
-- leaves behind.
--
-- Deliberately not a cascade. An application is retired far more often than its
-- groups become meaningless, and deleting people's memberships because a client
-- registration was removed would be a surprising amount of damage from one
-- button.
ALTER TABLE entities
    ADD COLUMN owner_id uuid REFERENCES entities(id);

CREATE INDEX entities_owner_idx ON entities (owner_id)
 WHERE owner_id IS NOT NULL;

COMMENT ON COLUMN entities.owner_id IS
    'The application a group exists for, if any. Organisational only: Cardinal '
    'treats an owned group exactly like any other.';

-- A system group cannot belong to an application: the two kinds are the point.
ALTER TABLE entities
    ADD CONSTRAINT entities_system_groups_are_unowned
    CHECK (NOT (system AND owner_id IS NOT NULL));
