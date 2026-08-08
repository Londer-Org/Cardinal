# Upgrading and downgrading

Cardinal is pre-1.0. There is no compatibility promise between versions yet, and
this page describes the machinery that exists rather than a guarantee.

## The whole procedure

**Upgrade.** Migrate, then deploy.

```sh
cardinal migrate      # from the new build
# then roll the servers
```

**Roll back.** Deploy the previous build.

That is the entire rollback procedure. No schema change, no reversal, no
ordering to remember, and nothing to back up first.

## Why that works

**Migrations only add.** A migration never drops a table or a column, never
renames, never changes a type, and never narrows a constraint or adds a `NOT
NULL` column without a default. So the previous version keeps working against a
schema newer than itself: it simply does not use the new columns.

This is enforced, not requested. `go test ./migrations/` rejects a migration
that removes or narrows anything — at the moment it is written, rather than
during the rollback in November that no longer works.

Removal still happens, a release later, once nothing running reads the thing
being removed:

| Release | Does | The previous version still works because |
|---|---|---|
| N | Adds the column, writes both | The old column is still there and still written |
| N+1 | Stops reading the old one | Nobody on N-1 is left |
| N+2 | Drops it | Nothing reads it |

Only N+2 removes anything, and by then it removes something no supported version
touches.

### This replaced something worse

There was briefly a reversal beside every migration, a `cardinal migrate -to`
that applied them, and a `-backup` to be taken first. Honestly read, it offered
very little: a reversal restores the *shape* of the data and not the data, so
undoing a `DROP COLUMN` yields a column with nothing in it. It also required
knowing that only the *newer* build contains the reversal for its own migration,
so the reversal had to run before the older build was deployed — an ordering
nobody wants to discover during an incident.

Forbidding the destructive change is simpler than reversing it, and it is the
only version of this where the previous release genuinely still works.

## When a change cannot wait

Some changes are not expressible as an addition. Those declare themselves:

```sql
-- breaking: entities.legacy_dn removed; 0.4 and earlier read it on every login
```

Applying one records the reason in `schema_migrations`, and older builds refuse
to start against it, naming what and why. The reason is stored rather than read
from the file on purpose: a build from before the migration existed has no copy
of it, but it can read the row.

Rolling back past a breaking migration is a restore from backup. That is the
honest cost, it is stated up front, and it should be rare enough to be an event.

## What the server checks at startup

Both checks live in the binary rather than in a deployment manifest, so they
hold for a container, a Kubernetes Job, a systemd unit or a laptop.

**A schema behind the binary is refused.** Migrations it needs have not been
applied; it names them and says to run `cardinal migrate`. This is the check an
upgrade walks into, and it exists because a Kubernetes Job's immutable pod
template made `kubectl apply` update the Deployment and reject the migration —
the new server rolled out and the migration never ran.

**A schema ahead of the binary is allowed, and logged.** That is the rollback
case working. It refuses only if one of the unrecognised migrations declared
itself breaking.

## Container images

Migrating is its own run of the same image, not something the server does:

```sh
docker pull londerbe/cardinal:0.2.0
docker run --rm --network=... -v /etc/cardinal:/etc/cardinal:ro \
    londerbe/cardinal:0.2.0 migrate
docker compose up -d          # or roll the deployment
```

`migrate` finds its connection string at `/etc/cardinal/cardinal.toml` by
convention, so a deployment that already mounts its configuration needs nothing
else. `CARDINAL_DSN` and `-dsn` work too, and `-config` points elsewhere.

Rolling back is deploying the previous tag. Nothing else.

## Everything else that moves

| Component | Updates by | Goes back by |
|---|---|---|
| `cardinal server` | Pull the image, restart | Deploy the previous image |
| Database schema | `cardinal migrate` | Nothing — the old build runs against it |
| `cardinal-agent` | `.deb` / `.rpm` per host | Install the previous package |
| `cardinal` CLI | Binary or package | Install the previous one |
| Policy | `cardinal policy publish -activate` | Activate an earlier version |

Policy was always reversible: every published version is kept, activating an
earlier one is a button in the console, and servers pick it up within ten
seconds.

Agents update per host and will be a mixed fleet during any rollout, which is
fine — an agent fetches an assignment and renders it, so a server that adds a
field sends one older agents ignore. Update servers before agents; a new agent
may ask for a route an old server does not have.

Host access survives all of it. Certificates are validated by signature and
carry their own expiry, so a machine keeps working through an upgrade, a
rollback, and a complete outage
([ADR 0006](adr/0006-ssh-certificates-for-host-access.md)).

## What is not covered

No automated test runs release N-1 against a database migrated by N. The
expand-only rule is what makes that combination work, and the rule is enforced
per migration — but the pairing itself is checked by reading, not by running,
until there are two releases to run it with.

Backups are the operator's own, taken by whatever already backs the database up.
Cardinal briefly shelled out to `pg_dump` and it was never right: the container
image is distroless and has no `pg_dump`, so the flag worked on a laptop and not
where it mattered, and a backup taken by a tool whose restore path nobody
exercises is a file somebody discovers does not restore.
