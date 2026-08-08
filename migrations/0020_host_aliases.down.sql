-- Reverses 0020_host_aliases.sql.
--
-- A machine reachable under more than one name loses the extra ones, so a
-- certificate request naming an alias is refused until the alias is added again.
DROP TABLE IF EXISTS host_aliases;
