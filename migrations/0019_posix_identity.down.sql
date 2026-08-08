-- Reverses 0019_posix_identity.sql.
--
-- DESTRUCTIVE in the way that matters most on a filesystem. Every uid and gid is
-- forgotten, and reassigning them afterwards will not reproduce the same
-- numbers — so every file those accounts own becomes owned by a number nobody
-- holds. Restore from the backup rather than re-assigning.
DROP TABLE IF EXISTS posix_identities;
