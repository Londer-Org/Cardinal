-- Cardinal 0022: the difference between what Cardinal may allocate and what it
-- may hold.
--
-- Migration 0019 wrote one number into a CHECK constraint:
--
--     CONSTRAINT posix_identities_number_range CHECK (id_number >= 65536)
--
-- That is where Cardinal starts *handing out* numbers, chosen to sit above the
-- distribution's own accounts and above systemd's DynamicUser reservation. As an
-- allocation policy it is right. As a constraint on what may be stored it was
-- wrong, and the error only became visible when adoption existed to expose it:
--
--     store: 1234 is below 65536 ... an account down there is not one to bring
--     into the directory
--
-- uid 1234 is not a system account. It is a person, on a machine that has been
-- numbering people from 1000 upward because that is what UID_MIN says on every
-- mainstream distribution. Refusing it means refusing to migrate the ordinary
-- case, which made adoption a feature that could not do the thing it exists for.
--
-- So the constraint now expresses what is *universally* invalid, and the
-- allocation range stays in configuration where a deployment can choose it:
--
--   * Below 1000 belongs to the distribution — root, daemon, and whatever the
--     package manager creates. Claiming one puts Cardinal in collision with the
--     package manager rather than with another person, which is worse and
--     harder to see.
--   * 61184–65519 is systemd's DynamicUser reservation. A number in there is
--     handed to a transient service and reused, so an account holding one would
--     be periodically impersonated by whatever systemd started that minute.
--
-- Everything else is a number a real person can legitimately have somewhere.

ALTER TABLE posix_identities
    DROP CONSTRAINT posix_identities_number_range;

ALTER TABLE posix_identities
    ADD CONSTRAINT posix_identities_number_range CHECK (
        id_number >= 1000
        AND (id_number < 61184 OR id_number > 65519)
    );

COMMENT ON CONSTRAINT posix_identities_number_range ON posix_identities IS
    'What is universally invalid: the distribution''s own range and systemd''s DynamicUser reservation. Where Cardinal *allocates* is a configuration setting, deliberately narrower than this.';
