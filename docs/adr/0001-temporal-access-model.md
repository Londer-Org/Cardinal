# ADR 0001: Access grants are temporal, enforced by the database

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

In LDAP, FreeIPA, and Keycloak, group membership is a boolean fact: you are in
the group, or you are not. Everything time-related is bolted on afterwards.

That creates three recurring problems:

1. **Temporary access becomes permanent.** "Give the contractor prod access for
   two weeks" depends on someone remembering, or a cron job that might not run.
   Access accretes, and nobody notices until an audit.
2. **History is unreconstructable.** "Who could reach production on 3 March?" is
   answerable only from logs, if you kept them, if they weren't rotated, and if
   nothing was changed out of band.
3. **Revocation destroys evidence.** Removing someone from a group erases the
   fact that they were ever in it, along with who granted it and why.

PostgreSQL 18 added temporal constraints (`WITHOUT OVERLAPS`); PostgreSQL 19
added `FOR PORTION OF` for `UPDATE` and `DELETE`. Together these make it
possible to push validity periods into the data model rather than the
application.

## Decision

**Access grants carry a validity period, and the database enforces it.**

```sql
CREATE TABLE group_members (
    group_id     uuid      NOT NULL REFERENCES entities(id),
    member_id    uuid      NOT NULL REFERENCES entities(id),
    valid_period tstzrange NOT NULL,
    granted_by   uuid      NOT NULL REFERENCES entities(id),
    reason       text,
    PRIMARY KEY (group_id, member_id, valid_period WITHOUT OVERLAPS)
);
```

Consequently:

- A time-boxed grant is an `INSERT` with a bounded range. **Expiry is enforced
  by the query**, so there is no scheduled job whose failure silently extends
  access.
- Early revocation is `DELETE ... FOR PORTION OF valid_period FROM now() TO
  'infinity'`, which truncates the range. **The historical grant survives,
  including who made it and why.**
- Point-in-time audit is `WHERE valid_period @> timestamptz '2026-03-03'`.
- Contradictory overlapping grants for the same (group, member) pair are
  impossible at the constraint level, not merely discouraged by application code.

The same pattern applies to role assignments, policy bindings, credential
validity, and sessions.

This makes **PostgreSQL 19 a hard requirement.** `FOR PORTION OF` is 19-only,
and we deliberately did not write an application-level fallback: PG19 GA is
expected roughly two months from this decision, so a dual-path implementation
would have been written to be deleted.

## Alternatives considered

**A `expires_at` column with a sweeper job.** The conventional approach. Rejected
because expiry then depends on the sweeper running — a failure mode that grants
access rather than denying it, which is the wrong direction to fail. It also
leaves history unrepresented.

**Application-level history tables.** A `group_members_history` table written by
triggers. Rejected: two sources of truth that can drift, no constraint
preventing contradictory overlapping grants, and point-in-time queries become
application logic instead of a `WHERE` clause.

**Full event sourcing** (the Zitadel model). Rejected as a large, permanent
complexity tax. Cardinal keeps state tables authoritative and adds an
append-only hash-chained journal alongside — most of the audit benefit, far less
machinery. See ADR 0002.

## Consequences

**Good.** Time-bounded access is native rather than aspirational. Auditors get
one query instead of a log-archaeology project. Revocation preserves evidence.
Overlapping-grant bugs are structurally impossible.

**Costs.** PostgreSQL 19+ only, which is a real deployment constraint while 19
is still in beta. Range semantics are unfamiliar to most developers and need
documenting. Concurrent grant/revoke on the same row needs explicit testing —
the constraint prevents corruption, but the retry behaviour is ours to get right.

**Testing is not optional.** `WITHOUT OVERLAPS` and `FOR PORTION OF` are
database semantics and cannot be mocked. Every invariant here is covered by
integration tests against a real PostgreSQL via testcontainers.

## Verification

Confirmed against `postgres:19beta2` before implementation:

- Overlapping grant for the same (group, member) → rejected by exclusion constraint
- Adjacent grant → accepted
- Different member overlapping in time → accepted
- `DELETE FOR PORTION OF` → range truncated to the revocation instant, `reason` preserved
- `UPDATE FOR PORTION OF` → one row split into three
- Point-in-time → correct on both sides of a revocation boundary

## Implementation notes

Two things cost time to discover and are worth stating plainly:

**`CREATE EXTENSION btree_gist` is required.** A `WITHOUT OVERLAPS` primary key
compiles into a GiST exclusion constraint, so the *scalar* columns in that key
need a GiST operator class. `uuid` has no default one in core, so without the
extension every temporal table fails at `CREATE TABLE` with *"data type uuid has
no default operator class for access method gist"*.

This is unrelated to PostgreSQL 19 deprecating btree_gist's **inet/cidr**
opclasses. That change affects `gist_inet_ops` only, and blocks `pg_upgrade`.
Cardinal uses core `inet_ops` for `inet` columns and is unaffected.

**"Currently valid" cannot be a partial index.** `now()` is STABLE, not
IMMUTABLE, so it cannot appear in an index predicate. Index the range itself
with a composite GiST over `(scalar_column, valid_period)` — which `btree_gist`
makes available anyway.
