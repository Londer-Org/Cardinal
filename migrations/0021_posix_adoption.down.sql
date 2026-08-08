-- Reverses 0021_posix_adoption.sql.
--
-- Loses the record of when a number was first served to a host, which is what
-- decides whether it may still be adopted. Without it every number looks
-- adoptable again — safe on its own, and worth knowing before adopting one.
ALTER TABLE posix_identities DROP COLUMN IF EXISTS first_served_at;
