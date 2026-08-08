# Upgrading and downgrading

Cardinal is pre-1.0. There is no compatibility promise between versions yet, and
this page describes the machinery that exists rather than a guarantee.

Three things move independently, and that is deliberate — a fleet cannot update
atomically, so nothing here assumes it does.

| Component | How it updates | How it goes back |
|---|---|---|
| `cardinal server` | Pull the new image, restart | Deploy the old image |
| Database schema | `cardinal migrate` | `cardinal migrate -to <migration>` |
| `cardinal-agent` | `.deb` / `.rpm` per host | Install the previous package |
| `cardinal` CLI | Binary or package | Install the previous one |
| Policy | `cardinal policy publish -activate` | Activate an earlier version |

Policy is the one that was always reversible: every published version is kept and
activating an earlier one is a button in the console. The rest of this page is
about the parts that were not.

## The order that works

**Upgrading.** Migrate first, then the server. Every migration is written to
leave the previous version able to run, so a database migrated ahead of its
servers is a normal intermediate state rather than an outage.

```sh
cardinal migrate -backup /var/backups/cardinal-pre-upgrade.dump
# then roll the servers
```

**Downgrading.** The schema first, using the version you are leaving — then the
older server.

That ordering is not a preference. Reversals are embedded in the binary, so the
build that introduced migration N is the only one that contains N's reversal:
undo it *before* the older build is the one you have.

```sh
# still running the newer version, and this must run from it
cardinal migrate -to 0022_posix_adoption_range.sql -backup /var/backups/pre-downgrade.dump
# only now install and start the older one
```

Doing it the other way round is not dangerous — the older server refuses to
start against a schema holding migrations it does not contain, naming them — but
it is a dead end, because the binary you now have cannot perform the reversal
you need.

Both directions are refused rather than attempted. That check exists because the
alternative was silent: a mismatched binary started happily and then failed one
request at a time, wherever a code path first touched a column it did not know
about, which reads like a bug in whichever feature was unlucky rather than like
the wrong version running.

## Container images

The same three steps, but nothing is a shell command on the host — and two
things about it are not obvious.

**Migrating is its own container run, not something the server does.** The image
contains the CLI as well as the server, so it is the same image with a different
argument:

```sh
docker pull londerbe/cardinal:0.2.0
docker run --rm --network=... -v /etc/cardinal:/etc/cardinal:ro \
    londerbe/cardinal:0.2.0 migrate
docker compose up -d          # or roll the deployment
```

`migrate` finds its connection string at `/etc/cardinal/cardinal.toml` by
convention, so a deployment that already mounts its configuration needs nothing
else. `CARDINAL_DSN` and `-dsn` still work, and `-config` points elsewhere.

The server refuses to start if that middle step did not happen, naming what is
missing. That check is in the binary rather than in a manifest so it holds
however the thing is deployed — which matters, because the manifest is exactly
what got it wrong here first: a Kubernetes Job's pod template is immutable, so
`kubectl apply` with a new image tag updates the Deployment and *rejects* the
migration Job. The new server rolled out and the migration never ran, and
nothing noticed.

**Only the newer image can undo its own migrations.** Reversals are embedded in
the binary, so the image that introduced migration N is the only one that
contains N's reversal. A downgrade therefore runs the reversal *before* the old
image is deployed, using the image being left behind:

```sh
# still on 0.2.0, and this must run from 0.2.0
docker run --rm --network=... -v /etc/cardinal:/etc/cardinal:ro \
    londerbe/cardinal:0.2.0 migrate -to 0023_x509_ca.sql -skip-backup
# only now
docker compose up -d          # with 0.1.0
```

Deploying the old image first is not dangerous — it refuses to start — but it is
a dead end: the running image no longer contains the reversal you need, and you
have to pull the newer one back to get out of it.

**`-backup` does not work in the container.** It shells out to `pg_dump`, and the
image is distroless — no shell, no `pg_dump`, deliberately. The error says so
rather than failing obscurely. In a container deployment the backup is taken by
whatever already backs the database up, and `-skip-backup` is how you say it has
been. That is a weaker guarantee than the flag on a host, and it is the honest
one: a backup taken by a tool whose restore path nobody exercises is a file
somebody discovers does not restore at the moment they need it.

## What a reversal actually does

**It restores the shape of the data, not the data.** Dropping a column reverses
to a column with nothing in it, and afterwards nothing can tell the difference.
This is why `-to` refuses to run without either `-backup` or an explicit
`-skip-backup`.

Every reversal states its own cost at the top of the file. Several are
destructive in ways worth reading before running them:

- **`0017_ssh_ca`** — the authority key. Every host trusting it now trusts
  nothing this Cardinal can sign. Certificates already issued keep working until
  they expire; no new one can be issued. Restore rather than re-init, or the
  whole fleet needs its `TrustedUserCAKeys` replaced by hand.
- **`0019_posix_identity`** — every uid and gid. Reassigning afterwards does not
  reproduce the same numbers, so every file those accounts own becomes owned by
  a number nobody holds.
- **`0006_oidc`** — the signing key every issued token was signed with. Tokens
  in the wild stop verifying, which is a logout for every application at once.
- **`0003_credentials`** — every registered passkey. An account whose only
  credential was a passkey cannot sign in afterwards.

`0022_posix_adoption_range` is the one that fails rather than losing data, which
is the better failure: if an adopted number falls outside the older, narrower
range, the constraint is refused and nothing changes. That is the signal the
database has outgrown the older version, and it is louder than a silent
truncation.

`0001_foundation` has no reversal, deliberately. Below it is not an older schema,
it is no schema — dropping the database is not a migration and should not
pretend to be one.

## Writing a migration

Two rules, and a test enforces the first.

**Every migration ships its reversal.** `NNNN_name.sql` gets `NNNN_name.down.sql`
beside it. A migration without one fails `go test ./migrations/`, at the moment
it is written rather than during the incident where somebody needs it. If a
change genuinely cannot be reversed, add it to `irreversible` in
`migrations/migrations_test.go` with the reason — the point is that the decision
is recorded, not that it is forbidden.

A second test compares what each migration creates against what its reversal
drops. `DROP TABLE IF EXISTS a_typo` succeeds and does nothing, so a reversal
naming a table that never existed reports success while changing nothing. Four
such mistakes were caught this way when the reversals were first written, and no
amount of running them would have revealed any of them.

**Expand before contracting.** A migration must leave the previous version able
to run, which means a change lands in two releases:

| Release | Does | Previous version still works because |
|---|---|---|
| N | Adds the column, backfills, writes to both | The old column is still there and still written |
| N+1 | Stops reading the old one | Nobody on N-1 is left |
| N+2 | Drops it | Nothing reads it |

Adding a nullable column, a table, or an index is safe in one step. Renaming,
dropping, or narrowing a constraint is not, and doing it in one release is what
turns a rollback into a restore.

## Agents

Agents update per host and will be a mixed fleet during any rollout. That is
fine and expected — an agent fetches an assignment and renders it, so a server
that adds a field simply sends one older agents ignore.

The reverse — an agent newer than its server — is the case to avoid, because a
new agent may ask for something the old server has no route for. Update servers
before agents.

Host access survives all of this. Certificates are validated by signature and
carry their own expiry, so a machine keeps working through a server upgrade, a
downgrade, and a complete outage (ADR 0006) — which is the property that makes
these operations ordinary rather than frightening.

## What is not covered

There is no automated compatibility test between adjacent versions yet: nothing
runs release N-1 against a database migrated by N. The startup gate makes that
combination refuse rather than misbehave, which is the safe half; proving the
*supported* combination works is still manual.
