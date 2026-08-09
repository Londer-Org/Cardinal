-- Cardinal 0031: say what erasure actually removes.
--
-- No structural change. The comment on entities.redacted_at has described
-- erasure since migration 0002 as tombstoning name, display_name and attrs, and
-- that was the whole of it — the credentials stayed, and disabled_at was never
-- set. Since the login path gates on disabled_at alone, an account erased under
-- Article 17 could still be signed into with the passkey it always had.
--
-- The behaviour is fixed in code. This fixes the description, which is not
-- cosmetic: the comment is the source of the entities table in docs/schema.md,
-- it is what `\d+ entities` shows an operator at a psql prompt during an
-- incident, and a column comment that understates what a destructive operation
-- does is worse than no comment at all.
--
-- A new migration rather than an edit to 0002, because an applied migration is
-- immutable and the digest check enforces it.

COMMENT ON COLUMN entities.redacted_at IS
    'When this entity''s personal data was erased. The row survives so audit '
    'references still resolve, but name/display_name/attrs are tombstoned, the '
    'WebAuthn credentials are deleted and disabled_at is set — an erasure that '
    'leaves a working credential is not an erasure. See ADR 0010.';
