-- Cardinal 0020: the names a host may prove it has.
--
-- Host certificates end TOFU. Instead of every user deciding on first contact
-- whether an unknown fingerprint is really web-01, they trust one authority and
-- the machine proves its own name. That is the single most visible improvement
-- in this whole project — nobody types `yes` at a prompt they cannot evaluate
-- ever again.
--
-- It also moves a decision that used to be nobody's into Cardinal's: **which
-- names is this machine allowed to answer to?** A certificate naming
-- git.example.com is the power to be git.example.com, so the answer cannot come
-- from the machine asking. It comes from here.
--
-- What is deliberately *not* here: any automatic derivation. A host called
-- web-01.prod does not get `web-01` for free, tempting as it is. Two machines
-- named web-01.prod and web-01.dev would then both hold a certificate for
-- `web-01`, and whichever answered first when somebody typed `ssh web-01` would
-- be trusted — an impersonation created by a convenience nobody asked for. Every
-- name is written down.

CREATE TABLE host_aliases (
    host_id  uuid        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,

    -- The name as it is typed. A certificate principal is compared literally by
    -- OpenSSH, so this is stored exactly as it will be presented.
    name     text        NOT NULL,

    added_at timestamptz NOT NULL DEFAULT now(),
    added_by uuid        REFERENCES entities(id),

    PRIMARY KEY (host_id, name),

    CONSTRAINT host_aliases_name_not_blank CHECK (length(trim(name)) > 0)
);

-- Globally unique, which is the constraint that matters. Two hosts holding a
-- certificate for the same name is precisely the ambiguity this table exists to
-- prevent, and it is not the sort of thing to discover during an incident.
CREATE UNIQUE INDEX host_aliases_name_unique ON host_aliases (name);

COMMENT ON TABLE host_aliases IS
    'Additional names a host may hold a certificate for. Unique across all hosts.';
