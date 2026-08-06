-- Cardinal 0011: split administration into tiers.
--
-- One group could do everything, which made "give someone admin" an
-- all-or-nothing decision — and an all-or-nothing decision is one people make
-- generously, because the alternative is making it again next week.
--
-- Whoever onboards staff does not need to register OIDC clients, and whoever
-- registers clients does not need to disable accounts. That second one is not a
-- nicety: registering a client means choosing its redirect URIs, which is
-- enough to stand up a phishing surface inside the organisation's own identity
-- provider. It is a different blast radius from adding someone to a group.
--
-- directory-admins stays, and stays the superset. Nobody is migrated into the
-- new groups: an existing administrator keeps exactly what they had, and an
-- operator narrows deliberately rather than discovering after an upgrade that
-- someone lost access.
--
-- Identifiers follow migration 0008: recognisably synthetic, valid UUIDs, and
-- mirrored in policy.UserAdminGroupID / policy.SecurityAdminGroupID with a test
-- asserting the three agree.

INSERT INTO entities (id, type, name, display_name)
VALUES
    ('00000000-0000-7000-8000-00000000ad12', 'group', 'user-admins',
     'User Administrators'),
    ('00000000-0000-7000-8000-00000000ad13', 'group', 'security-admins',
     'Security Administrators')
ON CONFLICT (id) DO NOTHING;

COMMENT ON COLUMN entities.name IS
    'Mutable human-readable name, unique per type. NOT an identifier. The '
    'built-in groups directory-admins, user-admins and security-admins are '
    'created by migration and referenced by the default policy set through '
    'their identifiers, so renaming them is safe and deleting them removes a '
    'tier of administrative authority.';
