-- Cardinal 0002: erasure support.
--
-- The audit journal is append-only and hash-chained (ADR 0003), so GDPR
-- Article 17 erasure cannot be satisfied by deleting rows. Instead, personal
-- data is confined to mutable state tables and erasure redacts *those*,
-- leaving the chain untouched. See ADR 0010.

ALTER TABLE entities
    ADD COLUMN redacted_at timestamptz;

COMMENT ON COLUMN entities.redacted_at IS
    'When this entity''s personal data was erased. The row survives so audit '
    'references still resolve, but name/display_name/attrs are tombstoned.';

-- A redacted entity must actually be redacted. Without this, a bug in the
-- application could stamp redacted_at while leaving the personal data in
-- place -- producing a system that reports compliance it has not achieved,
-- which is worse than one that reports failure honestly.
ALTER TABLE entities
    ADD CONSTRAINT entities_redaction_is_complete CHECK (
        redacted_at IS NULL
        OR (display_name IS NULL AND attrs = '{}'::jsonb)
    );

-- Redacted entities are excluded from name lookups: the tombstone name is an
-- implementation detail, not something anyone should resolve by hand.
CREATE INDEX entities_active_lookup_idx ON entities (type, name)
    WHERE disabled_at IS NULL AND redacted_at IS NULL;

-- Grant justifications are free text written by humans, so they attract
-- personal data ("covering for Jan while he's on sick leave"). They live here
-- rather than in the journal precisely so they can be cleared.
COMMENT ON COLUMN group_members.reason IS
    'Free-text justification. Personal data may appear here, so it is nulled '
    'on erasure. Never copy this into an event payload -- see ADR 0010.';
