# Upgrading and downgrading

Cardinal is pre-1.0. There is no compatibility promise between versions yet, and
this page describes the machinery that exists rather than a guarantee.

## The whole procedure

**Upgrade.** Migrate, then deploy.

```sh
cardinal-server migrate   # from the new build
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

There was briefly a reversal beside every migration, a `cardinal-server migrate -to`
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

### The partitions this adds are worth keeping

Migration 0034 gives `events` and `decisions` partitions through 2035 and a
`DEFAULT` partition behind them. Rolling back to a build that predates it is
safe — the tables and their partitions are untouched by the older binary — but
the partitions themselves must not be dropped to "undo" the migration. Doing
that restores the failure it exists to prevent, and that failure is every write
in the system.

Watch the startup log instead. It says when a table has under two years of
partitions left, and says something different once rows are landing in the
backstop.

### Rolling back past a narrowed group projection

Not a schema problem — the tables are expand-only and an older build ignores
them — but the behaviour is not symmetrical, and it is worth knowing before it
surprises somebody.

An application whose projection is `owned` is told about a subset of a person's
groups. A build from before that feature reads neither table and sends the full
closure, so **rolling back widens the claim**: an application that had been told
about two groups is suddenly told about all of them. Nothing breaks and nothing
is refused, because the projection never affected what Cardinal decides — but a
disclosure you had narrowed is open again until you roll forward.

Nothing to do beyond knowing it. If the narrowing mattered, that is a reason to
fix forward rather than back.

### Two changes 0.3.0 needs you to act on

Neither is a schema problem, so nothing refuses to start and nothing appears in
a log. Both are in the changelog under **Security**; they are here because this
is the page somebody reads when they upgrade.

**Access tokens issued before 0.3.0 outlived the sessions that made them.**
Signing out closed the session and left every token minted from it valid for its
full lifetime. If you ran anything earlier, treat tokens issued before the
upgrade as outstanding and revoke them:

```sh
cardinal token list <login>
cardinal token revoke <login> <token-id>
```

**Erasure before 0.3.0 left the passkeys behind.** `cardinal redact` stamped the
entity and never disabled it, and the credentials were not deleted.

Signing in is not the exposure. `loadUser` refuses a redacted entity outright,
separately from the disabled check and deliberately so — an erased account that
somehow kept a credential still cannot authenticate on 0.3.0 or later. What
remains is that a public key is personal data in its own right
([ADR 0010](adr/0010-personal-data-and-erasure.md)), and those rows are still
there.

The changelog for 0.3.0 says to re-run erasure for anyone erased earlier. **That
is not something the CLI can do**, and it was written without being tried:
erasure renames the entity to a tombstone, so the old login no longer resolves,
and the update is guarded by `redacted_at IS NULL`, so it would affect no rows
even if it did.

Whether you are affected at all:

```sql
SELECT count(*) FROM entities e
  JOIN webauthn_credentials w ON w.entity_id = e.id
 WHERE e.redacted_at IS NOT NULL;
```

Zero means every erasure you have run already removed them. If it is not zero,
those rows are the leftovers and removing them is a delete:

```sql
DELETE FROM webauthn_credentials
 WHERE entity_id IN (SELECT id FROM entities WHERE redacted_at IS NOT NULL);
```

Nothing else references them: erasure already cleared the sessions, the grant
justifications and the attributes, and the audit chain records the erasure
rather than the credential.

### One change the expand-only rule does not cover: 0.2.0 and forwardAuth

Not a schema change — a behaviour change, so it does not declare itself and no
startup check finds it.

Before 0.2.0, forwardAuth classified every hostname as the same audience and the
shipped rule permitted that audience, so any authenticated principal reached any
protected URL. It now resolves the hostname to an application entity and asks
about *that*, and a hostname no application claims is refused.

Two things to do before rolling to 0.2.0, in this order:

```sh
cardinal application create <name>                    # if it has no OIDC client
cardinal app hostname add <name> <hostname>           # for every protected host
cardinal grant staff-apps <name>                      # what staff-web-access permits
```

And any rule you wrote naming an application by hostname —
`resource == Cardinal::Application::"aura.example.com"` — now needs the
application's directory name. `cardinal policy test <file> -dsn <url>` reports
every reference that will not resolve.

Rolling back is still deploying the previous image: the hostnames and the group
membership are additions, and the older build ignores them.

## What the server checks at startup

Both checks live in the binary rather than in a deployment manifest, so they
hold for a container, a Kubernetes Job, a systemd unit or a laptop.

**A schema behind the binary is refused.** Migrations it needs have not been
applied; it names them and says to run `cardinal-server migrate`. This is the check an
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

## Agents

An agent is on a machine, and a fleet cannot be updated atomically. Everything
below is measured on a real host rather than reasoned about, because the numbers
are what decide whether this is a maintenance window or a routine act.

### Upgrading one

```sh
sudo apt install ./cardinal-agent_0.2.0_linux_amd64.deb   # or dnf/rpm
sudo systemctl restart cardinal-agent
```

**The restart is a separate step, and the package will not do it for you.**
There is deliberately no postinstall script: the two edits a managed host needs —
`systemd` in `nsswitch.conf` and `@includedir` in `/etc/sudoers` — are exactly
the ones the agent refuses to make itself, and a package allowed what the daemon
is not is the surprise that costs people's trust. The cost of that decision is
this line, and installing without it leaves the old agent running.

**What survives the upgrade,** measured by installing over a running,
enrolled agent:

| | |
|---|---|
| `/etc/cardinal/host_key` | unchanged — **no re-enrollment** |
| `/var/lib/cardinal/assignment.json` | survives; identity is served from it immediately |
| `/etc/cardinal/agent.toml` | `config|noreplace`, so local edits are kept |

**The gap is about 6 ms.** The agent loads its cached assignment from disk
before contacting anything, so identity is being served again before a login has
time to notice. Measured by stopping the agent and polling `getent` until the
name came back.

It is not zero, and what happens inside it is worth knowing: while the agent is
down, directory users **do not exist** on that machine. `getent passwd alice`
returns nothing, a new login is refused, and `sudo` cannot resolve the name.
Already-running sessions keep their shell — the process holds a uid, not a name.

### Rolling out to a fleet

Update one machine, look at it, then the rest.

```sh
cardinal-agent status     # what is cached here, and how old
cardinal-agent doctor     # this machine's prerequisites, changes nothing
```

A mixed fleet is a normal state, not a race to end. An agent fetches an
assignment and renders it, so a server that adds a field simply sends one older
agents ignore.

**Update servers before agents.** The reverse is the risky order: there is no
version negotiation between them, so a newer agent may ask for a route an older
server does not have. Nothing detects that today — it surfaces as a fetch
failing, and the agent goes on serving its cache, which is a degradation that
hides itself.

### If Cardinal is unreachable during any of this

Nothing on the host stops working. Verified by pointing an agent at a hostname
that does not resolve: it logged `loaded cached assignment host=dev-01 users=2`
and went on answering `getent`. That is the property the whole design rests on
([ADR 0006](adr/0006-ssh-certificates-for-host-access.md)) — the machine already
holds what it needs, and the certificate a person logs in with is validated by
signature rather than by asking anybody.

So an agent upgrade during a Cardinal outage is safe, and so is the outage.

### Rolling back an agent

Install the previous package and restart. The host key and cache are untouched,
so nothing re-enrolls and no assignment is refetched before it would have been
anyway.

One thing to know, because the failure is abrupt. The cache is the only file a
newer agent might write in a shape an older one cannot read, and an agent that
cannot parse its cache **exits** rather than starting without it:

```
cardinal-agent: agent: parsing cache /var/lib/cardinal/assignment.json:
  invalid character 't' looking for beginning of object key string
```

That is deliberate — continuing would leave a machine serving nothing while the
file sat there looking fine — but it means the machine has no directory users
until it is dealt with. The fix is one line:

```sh
sudo rm /var/lib/cardinal/assignment.json
sudo systemctl restart cardinal-agent
```

It then starts empty and refetches. Verified: a deliberately corrupted cache
stops the agent, and deleting it brings identity straight back.

The consequence worth planning around: a change to the cache format is a
breaking change *for rollback*, even though nothing about the schema changed. If
a release changes it, say so in the release notes, because rolling back that one
means clearing the cache on every host — and doing that during a Cardinal outage
leaves those hosts with no identity until it returns.

## Everything else that moves

| Component | Updates by | Goes back by |
|---|---|---|
| `cardinal server` | Pull the image, restart | Deploy the previous image |
| Database schema | `cardinal-server migrate` | Nothing — the old build runs against it |
| `cardinal-agent` | `.deb` / `.rpm`, then restart | Install the previous package ([above](#agents)) |
| `cardinal` CLI | Binary or package | Install the previous one |
| Policy | `cardinal policy publish -activate` | Activate an earlier version |

Policy was always reversible: every published version is kept, activating an
earlier one is a button in the console, and servers pick it up within ten
seconds.

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
