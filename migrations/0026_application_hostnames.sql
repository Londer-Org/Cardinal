-- Cardinal 0026: the hostnames an application answers to.
--
-- forwardAuth is asked about a *hostname* — Traefik forwards one in
-- X-Forwarded-Host and nothing else identifies the thing being protected. Until
-- now nothing turned that hostname into a directory entity, so the decision
-- point classified every host identically and the shipped rule permitting
-- "applications marked public-to-staff" permitted every authenticated principal
-- to reach every protected URL. It looked like a policy that discriminated and
-- was a constant.
--
-- With this table a hostname resolves to an application, an application is an
-- entity, and "who may reach it" is group membership — the same mechanism host
-- access already uses, bounded in time and revocable like any other grant.
-- Nothing new to learn, and one fewer kind of object than an `audience` string
-- attribute would have been.

CREATE TABLE application_hostnames (
    -- The hostname is the key, so two applications cannot both claim one.
    -- Deliberately the same refusal host_aliases makes: an ambiguous name is
    -- how a request ends up authorized against the wrong application's rules.
    hostname   text NOT NULL PRIMARY KEY,

    entity_id  uuid NOT NULL REFERENCES entities(id),

    added_at   timestamptz NOT NULL DEFAULT now(),
    added_by   uuid REFERENCES entities(id),

    -- Stored lowercase, because DNS is case-insensitive and a browser may send
    -- either. A constraint rather than a trigger: normalising silently would
    -- mean `cardinal app hostname list` printing something the operator did not
    -- type, and the writer lowercases before it gets here.
    CONSTRAINT application_hostnames_lowercase CHECK (hostname = lower(hostname)),
    CONSTRAINT application_hostnames_not_blank CHECK (length(trim(hostname)) > 0)
);

CREATE INDEX application_hostnames_entity_idx
    ON application_hostnames (entity_id);

COMMENT ON TABLE application_hostnames IS
    'Maps a hostname Traefik forwards to the application entity it belongs to. '
    'A hostname with no row here is refused by forwardAuth before policy is '
    'consulted, the same way an unenrolled machine is refused an SSH '
    'certificate: Cardinal decides about things the directory knows.';
