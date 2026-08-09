-- Cardinal 0029: provisioning over SCIM.
--
-- An identity provider keeps its own key for each account it manages, and sends
-- it back on every subsequent request. Storing it is what lets a reconciliation
-- find the account it created last week rather than creating a second one — the
-- failure mode of not storing it is a directory that grows a duplicate of every
-- person each time the IdP forgets a mapping.
--
-- Nullable, and unique only where present: everything created by the CLI, the
-- console or `cardinal init` has no external key and never will.
ALTER TABLE entities
    ADD COLUMN external_id text;

CREATE UNIQUE INDEX entities_external_id_idx
    ON entities (external_id)
 WHERE external_id IS NOT NULL;

COMMENT ON COLUMN entities.external_id IS
    'The identity provider''s own key for this entity, from SCIM. Null for '
    'everything Cardinal created itself. Unique where present, so two '
    'provisioned accounts cannot claim one upstream identity.';

-- Who may provision.
--
-- Empty, like every other group a migration creates. Pointing an identity
-- provider at Cardinal is two deliberate acts — a token carrying the scim
-- scope, and membership here — and neither on its own is enough (ADR 0031).
INSERT INTO entities (id, type, name, display_name)
VALUES ('00000000-0000-7000-8000-0000000e5be6', 'group', 'provisioners',
        'Identity providers that may provision accounts')
ON CONFLICT DO NOTHING;
