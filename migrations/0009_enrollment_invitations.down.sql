-- Reverses 0009_enrollment_invitations.sql.
--
-- Outstanding invitations stop working. They are single-use and short-lived, so
-- the cost is reissuing them.
DROP TABLE IF EXISTS enrollment_invitations;
