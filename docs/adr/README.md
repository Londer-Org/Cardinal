# Architecture Decision Records

Cardinal makes several non-obvious choices. These records exist so the
*reasoning* survives — not just the outcome — and so decisions get revisited on
evidence rather than relitigated from memory.

Each ADR states the context, the decision, the alternatives that were rejected
and why, and the consequences including the costs. An ADR that lists no costs
isn't finished.

| # | Decision | Status |
|---|---|---|
| [0001](0001-temporal-access-model.md) | Access grants are temporal, enforced by the database | Accepted |
| [0002](0002-identity-is-an-immutable-uuid.md) | Identity is an immutable UUIDv7, and we speak no LDAP | Accepted |
| [0003](0003-hash-chained-event-log.md) | A hash-chained audit journal, not event sourcing | Accepted |
| [0004](0004-postgresql-is-the-only-datastore.md) | PostgreSQL 19 is the only datastore | Accepted |
| [0005](0005-cedar-as-the-single-decision-point.md) | Cedar is the single authorization decision point | Accepted |
| [0006](0006-ssh-certificates-for-host-access.md) | Linux host access uses short-lived SSH certificates | Accepted |
| [0007](0007-no-saml.md) | Cardinal will not implement SAML | Accepted |
| [0008](0008-single-binary-go-and-embedded-react.md) | One Go binary with an embedded React UI | Accepted |

## Conventions

- **Numbered sequentially, never renumbered.** Links must stay stable.
- **Never edit an accepted ADR's decision.** Supersede it with a new one and
  mark the old `Superseded by ADR-XXXX`. The record of what we believed and why
  is the point.
- **Statuses:** `Proposed` · `Accepted` · `Superseded by ADR-XXXX` · `Deprecated`
- Write one when a choice is expensive to reverse, surprising to a newcomer, or
  likely to be questioned in six months. Not for routine implementation detail.

## Open questions not yet decided

These need ADRs before the phases that depend on them:

- **GDPR erasure vs. the append-only hash chain** (blocks production use).
  Append-only plus hash chaining means erasure cannot simply delete rows.
  Personal data in event payloads must be pseudonymised or stored by reference
  so the referenced record can be redacted while the chain stays intact. This
  constrains payload design — decide before Phase 1 writes many event types.
- **Break-glass mechanism** (blocks Phase 1). Must work with the database down.
- **Secret and key management** — where the SSH CA private key and attribute
  encryption keys live (file, KMS, HSM, Vault). Blocks Phase 4.
