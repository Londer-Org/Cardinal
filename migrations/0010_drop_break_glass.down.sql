-- Reverses 0010_drop_break_glass.sql.
--
-- Recreates the table the forward migration removed, empty.
--
-- Empty is the correct reversal and not a shortcut: break-glass challenges were
-- ephemeral, so a version expecting this table finds it and finds nothing
-- outstanding, which is the same state it would reach on its own after any
-- pending challenge expired. The removal itself is ADR 0014 — the CLI already
-- performed the same recovery, and two credentials of last resort are worse
-- than one.
CREATE TABLE IF NOT EXISTS break_glass_challenges (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    entity_id    uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    code_hash    text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz
);

CREATE INDEX IF NOT EXISTS break_glass_challenges_pending_idx
    ON break_glass_challenges (entity_id)
    WHERE consumed_at IS NULL;
