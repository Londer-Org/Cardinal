-- Cardinal 0035: an identity for the path that has none.
--
-- Commands that reach PostgreSQL directly have no authenticated principal —
-- that is what makes them the recovery path (ADR 0033) — and the journal had
-- to write something anyway. What it wrote was a lie: `cardinal grant engineers
-- alice` recorded alice as her own granter, because group_members.granted_by is
-- NOT NULL and the member's own id was to hand.
--
-- Attribution nobody can check is worse than none, because it reads as
-- evidence. An auditor asking "who put alice in engineers" was told "alice",
-- and no query distinguished that from a real self-grant.
--
-- So the direct path gets an entity of its own to point at. It is not a
-- person, it cannot sign in — service accounts have no credentials — and its
-- name is the answer to the question: whoever held the database credential.
--
-- The alternative was making granted_by nullable and rendering NULL everywhere
-- as "unknown". That widens a constraint every read already relies on, and
-- "unknown" is less true than this: the path is known exactly, it is only the
-- person who is not.

INSERT INTO entities (id, type, name, display_name, system)
VALUES (
    -- Synthetic like the administration groups above, and for the same reason:
    -- referenced by name in code, so it cannot be a value generated at install
    -- time. `d1` for direct.
    '00000000-0000-7000-8000-0000000000d1',
    'service_account',
    'direct-database',
    'Direct database access (no authenticated person)',
    true
)
ON CONFLICT (id) DO NOTHING;

COMMENT ON COLUMN group_members.granted_by IS
    'Who granted this. The synthetic service account direct-database '
    '(00000000-0000-7000-8000-0000000000d1) means the grant was made through '
    'the command line against the database, where there is no authenticated '
    'person to name — not that nobody knows, but that the path has no identity '
    'to record.';
