-- Reverses 0017_ssh_ca.sql.
--
-- DESTRUCTIVE, and the most consequential reversal here. Dropping the authority
-- key means every host trusting it now trusts nothing this Cardinal can sign:
-- certificates already issued keep working until they expire, and no new one can
-- be issued. Restore rather than re-init, or the whole fleet needs its
-- TrustedUserCAKeys replaced by hand.
--
-- ssh_certificates goes with it. That is the record of what was issued to whom,
-- which is the only way to answer "who had access to that machine last Tuesday"
-- after the fact.
DROP TABLE IF EXISTS ssh_certificates;
DROP TABLE IF EXISTS ssh_ca_keys;
