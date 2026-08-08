-- Reverses 0011_admin_tiers.sql.
--
-- Removes the two finer-grained administrator groups. Anyone who held access
-- only through them loses it; the tier above (0008) is unaffected.
DELETE FROM entities WHERE id IN (
    '00000000-0000-7000-8000-00000000ad12',
    '00000000-0000-7000-8000-00000000ad13'
);
