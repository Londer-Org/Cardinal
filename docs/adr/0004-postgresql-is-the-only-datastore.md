# ADR 0004: PostgreSQL 19 is the only datastore

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

Identity platforms conventionally run a relational database *plus* Redis — for
sessions, cache invalidation, rate limiting, and job queues. Keycloak, Authentik
and most SaaS IdPs are deployed this way.

The strongest historical argument for that split was pub/sub. PostgreSQL's
`LISTEN`/`NOTIFY` woke *nearly every backend* on any notification — a thundering
herd that made it unusable above modest scale, and pushed people to Redis for
cache invalidation.

**PostgreSQL 19 fixed exactly that**: `NOTIFY` now only wakes backends listening
on the specific channel.

## Decision

**PostgreSQL is the only datastore.** No Redis, no message broker, no second
database, no external search engine.

| Need | Conventionally Redis | Cardinal |
|---|---|---|
| Sessions | KV with TTL | Table with `valid_period` — the same temporal machinery as ADR 0001 |
| Cache invalidation | Pub/Sub | `LISTEN`/`NOTIFY` (targeted, as of PG19) |
| Job queue | Lists / streams | `SELECT … FOR UPDATE SKIP LOCKED` |
| Rate limiting | `INCR` + expiry | In-process token bucket per node, or a table |
| Distributed lock | `SETNX` | Advisory locks |
| Search | RediSearch | Built-in full-text search |

Scale settles the rest. An internal IdP is small: hundreds of users, thousands
of hosts, tens of authentications per second at peak. PostgreSQL handles this
with orders of magnitude of headroom. Redis would add a second stateful system,
a second failure domain, a second backup story, and a cache-coherence bug
surface — for nothing.

## The `NOTIFY` durability caveat

`NOTIFY` is **not durable**. Notifications are lost if a listener is
disconnected, and payloads cap at 8000 bytes. Therefore:

- **`NOTIFY` carries IDs, never state, and is only ever a hint to invalidate.**
- The table is always the source of truth; nodes reconcile on reconnect via a
  version/watermark column.
- **Security-critical revocation is enforced at read time, not only by cache
  eviction.** A missed notification must be a latency problem, never a
  correctness one.

Violating that last rule would turn a dropped TCP connection into an
authorization bypass. It is the single most important constraint in this ADR.

## Alternatives considered

**PostgreSQL + Redis/Valkey.** The conventional split. Rejected on the reasoning
above, and specifically because operational simplicity is a feature for a system
maintained by one person — the fewer things that can be down at 3am, the better.

**PostgreSQL + embedded cache (Ristretto/groupcache).** In-process caching is
still used, invalidated by `NOTIFY`. That's a library, not a datastore, so it
doesn't conflict with this decision.

**A bespoke storage engine** (the Kanidm approach). Rejected: we'd forfeit SQL,
transactions, streaming replication, PITR, `pgBackRest`, and every operational
tool the team already knows — which is precisely Cardinal's differentiator
against Kanidm.

## Consequences

**Good.** One thing to back up, monitor, upgrade, and reason about. Sessions,
grants and audit share one transactional boundary, so there is no window where
a session outlives a revocation because two systems disagreed.

**Costs.** PostgreSQL 19+ is a hard floor (also required by ADR 0001). Job-queue
and pub/sub ergonomics are worse than purpose-built systems, and the durability
caveat above is a permanent correctness constraint on every cache path.

**If this is ever revisited — use Valkey, not Redis.** Redis relicensed to
AGPLv3; Valkey is BSD-licensed under the Linux Foundation and a far cleaner
dependency for an Apache-2.0 project. Make the switch on evidence: sustained
lock waits on the session table in `pg_stat_lock`, or session writes becoming a
measurable share of database load. Not on intuition.
