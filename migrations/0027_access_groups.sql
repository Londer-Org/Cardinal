-- Cardinal 0027: the groups the shipped policy set has always named.
--
-- Three of the eleven rules in policies/cardinal.cedar referenced group
-- identifiers no migration created — the rules governing SSH, sudo, and web
-- access. Cedar is default-deny and a rule matching a group that does not exist
-- simply never matches, so a fresh install denied all host access while
-- appearing to grant it conditionally. The policy file's own comment warns about
-- exactly this ("looks like a working deny"); the file then did it.
--
-- Creating them here makes those rules real. It grants nobody anything: a group
-- with no members permits nothing, so the security posture of a fresh install is
-- unchanged. What changes is that `cardinal grant sre alice` now works, instead
-- of succeeding and having no effect.
--
-- Identifiers follow migrations 0008 and 0011: recognisably synthetic, valid
-- UUIDs, and mirrored in internal/server/policy with a test asserting SQL, Go
-- and Cedar agree. These are the identifiers the policy file already used.
--
-- ON CONFLICT DO NOTHING is untargeted on purpose. entities has UNIQUE
-- (type, name), so a deployment that already created its own group called
-- `engineers` would otherwise fail this migration and refuse to start — turning
-- a naming coincidence into an outage. The row is skipped instead, and
-- `cardinal policy test` reports the consequence by name: a rule referencing a
-- group that is not there.

INSERT INTO entities (id, type, name, display_name)
VALUES
    -- Applications every member of staff may reach. A resource group: its
    -- members are applications, not people. Empty, so forwardAuth admits
    -- nobody to anything until an application is put in it — which is the
    -- deliberate act that "public to staff" should be.
    ('00000000-0000-7000-8000-0000000e5be0', 'group', 'staff-apps',
     'Applications every member of staff may reach'),

    ('00000000-0000-7000-8000-0000000e5be1', 'group', 'sre',
     'Site Reliability Engineers'),
    ('00000000-0000-7000-8000-0000000e5be2', 'group', 'env-prod',
     'Production machines'),
    ('00000000-0000-7000-8000-0000000e5be3', 'group', 'engineers',
     'Engineers'),
    ('00000000-0000-7000-8000-0000000e5be4', 'group', 'env-dev',
     'Development machines'),
    ('00000000-0000-7000-8000-0000000e5be5', 'group', 'platform-admins',
     'Platform Administrators')
ON CONFLICT DO NOTHING;

-- Deliberately not system groups.
--
-- entities.system means "membership confers authority within Cardinal itself",
-- which raises granting it from ManageUsers to AdministerDirectory. None of
-- these do: platform-admins confers root on the machines in env-dev, which is a
-- large amount of authority and none of it over the directory. Whoever onboards
-- staff is the person who grants host access, and making them ask a directory
-- administrator for every new engineer is how a tier boundary gets removed.
--
-- The honest consequence, stated rather than left to be discovered: a user
-- admin can grant platform-admins and thereby hand out root on development
-- machines. That is a real power and it is the same power they have by granting
-- any group the policy set happens to name. Narrow it by editing the rule, not
-- by hoping the tier boundary covers it.

COMMENT ON TABLE entities IS
    'Every principal, group, host and application. The groups created by '
    'migration — directory-admins, user-admins, security-admins (0008, 0011) '
    'and staff-apps, sre, env-prod, engineers, env-dev, platform-admins (0027) '
    '— are referenced by the default policy set through their identifiers, so '
    'renaming one is safe and deleting one silently removes whatever the rule '
    'naming it was granting.';
