-- Reverses 0022_posix_adoption_range.sql.
--
-- Returns the constraint to the narrower range. This one can FAIL rather than
-- lose data, which is the better failure: if any adopted number now falls
-- outside the old range — the common migration case, an existing fleet
-- numbering people from 1000 — the constraint is refused and nothing is
-- changed. That is the signal that this database has outgrown the older
-- version, and it is louder than a silent truncation.
ALTER TABLE posix_identities
    DROP CONSTRAINT IF EXISTS posix_identities_number_range;

ALTER TABLE posix_identities
    ADD CONSTRAINT posix_identities_number_range CHECK (
        id_number >= 100000 AND id_number <= 199999
    );
