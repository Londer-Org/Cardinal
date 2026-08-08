-- Reverses 0008_admin_group.sql.
--
-- Removes the seeded administrators group. Memberships referencing it go with
-- it, which means whoever was an administrator by way of this group is not one
-- afterwards — check that somebody else still is before running this.
DELETE FROM entities WHERE id = '00000000-0000-7000-8000-00000000ad11';
