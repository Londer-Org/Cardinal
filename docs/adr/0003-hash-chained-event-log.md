# ADR 0003: A hash-chained audit journal, not event sourcing

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

An identity system needs a trustworthy answer to "what changed, when, and who
did it" — and for a security product, "trustworthy" has to mean something
stronger than "we wrote it to a log file."

Application logs are inadequate: they live outside the transaction, so they
drift from reality when a write fails halfway; they're rotated; and anyone with
database or filesystem access can edit them without trace.

## Decision

**Every mutation appends to an immutable `events` table in the same transaction
as the state change**, and each row carries the SHA-256 hash of its predecessor.

State tables remain authoritative. The journal is an audit record, not the
source of truth.

Three properties follow:

- **It cannot drift from reality.** Same transaction means the event and the
  state change commit or roll back together.
- **It is tamper-evident.** Editing or removing any row breaks the chain from
  that point forward, and validation detects it.
- **It survives restore.** Running chain validation after a restore gives
  cryptographic evidence the data wasn't altered — something a plain PostgreSQL
  backup cannot tell you.

Append-only is enforced in the database, not trusted to application discipline:

```sql
CREATE RULE events_no_update AS ON UPDATE TO events DO INSTEAD NOTHING;
CREATE RULE events_no_delete AS ON DELETE TO events DO INSTEAD NOTHING;
```

The table is `PARTITION BY RANGE (occurred_at)`, so retention is a partition
drop rather than a mass `DELETE`, and PG19's `MERGE`/`SPLIT PARTITIONS` can
reshape it online.

The hash is computed **in Go, not in a database trigger**, so the algorithm is
versioned with the code, unit-testable in isolation, and portable if the journal
is ever exported or mirrored.

## Alternatives considered

**Full event sourcing** (the Zitadel model): events are the source of truth,
state is a projection. Rejected. It buys perfect history at the cost of
projection lag, rebuild tooling, versioned event upcasting, and a much harder
mental model for every future contributor — permanently. Cardinal already gets
point-in-time history from the temporal model (ADR 0001), so event sourcing
would be paying that tax twice for a benefit already in hand.

**Trigger-based audit tables.** Simple and automatic. Rejected: triggers make
the audit logic invisible at the call site, are awkward to test, and can't
easily capture actor identity or intent (the *why*) that only the application
knows.

**Write-only external log shipping** (syslog, SIEM). Complementary, not a
substitute — shipping should happen *as well*, but a remote log can't be
verified against local state, and gaps during network partitions are silent.

## Consequences

**Good.** Tamper-evident audit trail. Restores can be integrity-verified. The
journal doubles as the source for outbound SSF/CAEP security events later
(Phase 5).

**Costs.** Every mutation path must write an event — a discipline that has to be
enforced by code review and tests, since nothing structurally compels it. Chain
validation is O(n) and needs periodic checkpointing to stay practical as the
log grows.

**Sequential writes.** The chain means events must be appended in a defined
order, which serialises writers. At Cardinal's scale (an internal IdP) this is
irrelevant, but it is a real ceiling and should be measured before assuming
otherwise rather than discovered under load.

**Deletion is genuinely hard.** Append-only plus hash chaining means GDPR
erasure cannot simply remove rows. Personal data in payloads must be
pseudonymised or stored by reference, so the referenced record can be redacted
while the chain stays intact. **This constrains payload design and must be
decided before the first production deployment.**
