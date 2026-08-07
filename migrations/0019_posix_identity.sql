-- Cardinal 0019: the numbers a Unix machine actually uses.
--
-- A kernel does not know what "alice" is. It knows uid 100003, and every file
-- on every disk records that number rather than the name. So replacing SSSD
-- means Cardinal has to be the thing that decides which number a person is, and
-- has to keep deciding the same way forever: a uid that changes leaves a
-- home directory nobody owns, and a uid that gets reused hands somebody else's
-- files to a new employee.
--
-- Three decisions are baked into this table.
--
-- **One number space for users and groups.** A user's uid and a group's gid
-- come from the same allocator and can never collide. FreeIPA does this and it
-- is right: the two namespaces are separate to the kernel but not to the people
-- reading `ls -l`, and a uid that happens to equal an unrelated gid is a
-- confusion that shows up years later in a permissions bug nobody can explain.
--
-- **Numbers are never reused.** Allocation is max + 1 within the range, and
-- rows are never deleted — not even by redaction, which keeps the number and
-- erases everything else. Reuse is how a departed employee's files end up
-- readable by their replacement.
--
-- **A user's primary group is their own number.** User-private groups, the
-- convention `useradd` has followed on Debian and Red Hat for twenty years:
-- alice's primary group is `alice`, gid equal to her uid. It is not a directory
-- group and is not stored here — the agent synthesises the record. The
-- alternative, one shared primary group for everybody, makes every file
-- group-readable by the entire company by default.

CREATE TABLE posix_identities (
    -- One per entity, so there is nowhere to put a second conflicting number.
    entity_id      uuid        PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,

    -- uid for a user, gid for a group. UNIQUE across both, which is the whole
    -- point of sharing one allocator.
    id_number      integer     NOT NULL UNIQUE,

    -- Users only. Both or neither — a POSIX user without a shell is a record
    -- getent cannot render, and one without a home is a login that lands in /.
    home_directory text,
    login_shell    text,

    assigned_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT posix_identities_user_fields CHECK (
        (home_directory IS NULL) = (login_shell IS NULL)),

    -- Below 1000 is the distribution's own: root, daemon, and the service
    -- accounts a package manager creates. systemd claims 61184–65519 for
    -- DynamicUser. Colliding with either is a real outage rather than a
    -- cosmetic problem, so the floor is a constraint and not a default.
    CONSTRAINT posix_identities_number_range CHECK (id_number >= 65536)
);

COMMENT ON TABLE posix_identities IS
    'uid and gid numbers. One allocator for both, never reused, never changed.';
COMMENT ON COLUMN posix_identities.id_number IS
    'uid for a user, gid for a group. Unique across both so the two cannot collide.';

-- Redaction erases personal data and keeps the entity, so it must keep the
-- number too: the files on disk still carry it, and forgetting which erased
-- person owned uid 100003 makes those files unattributable rather than private.
-- The home directory is the one field here that contains a name, so that is the
-- one field redaction clears.
