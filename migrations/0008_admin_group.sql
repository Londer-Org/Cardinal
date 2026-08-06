-- Cardinal 0008: the built-in directory-admins group.
--
-- Every other decision point answers "may this principal do this" from the
-- policy set, and the directory's own administration is meant to be no
-- exception (ADR 0005). Until now it was: Cardinal::Action::"AdministerDirectory"
-- existed, two forbid rules guarded it, and nothing ever permitted it — so
-- default-deny meant nobody could administer anything.
--
-- The permit rule has to name a group, and a rule shipped in policies/ cannot
-- reference a UUID generated at install time. So the group is created here with
-- a fixed, documented identifier, and the default policy references that.
--
-- The UUID is deliberately not a real UUIDv7. It is recognisably synthetic, so
-- nobody reading a grant log mistakes it for something the system generated,
-- and it sorts to the front of any id-ordered listing. Its version nibble is 7
-- and its variant bits are correct, so it is a valid UUID and every uuid column
-- accepts it.

INSERT INTO entities (id, type, name, display_name)
VALUES (
    '00000000-0000-7000-8000-00000000ad11',
    'group',
    'directory-admins',
    'Directory Administrators'
)
ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE entities IS
    'Every principal, group, host and application. The group '
    'directory-admins (00000000-0000-7000-8000-00000000ad11) is created by '
    'migration and referenced by the default policy set; renaming it is safe, '
    'deleting it locks everyone out of administration.';

-- Membership is granted the ordinary way — `cardinal grant directory-admins
-- <user>` — so it is temporal, audited, and revocable like any other grant.
-- Deliberately nobody is a member here: a migration that silently made the
-- first account an administrator would be a backdoor with a changelog entry.
--
-- Bootstrapping is documented in docs/first-run.md. Break-glass cannot be used
-- to administer the directory (policy: break-glass-cannot-administer), so the
-- first grant is made with the CLI, which talks to the database directly and
-- is reachable by whoever already has database access.
