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
| [0009](0009-recovery-and-break-glass.md) | Account recovery and break-glass | Accepted; break-glass half superseded by 0014 |
| [0010](0010-personal-data-and-erasure.md) | Personal data never enters the audit journal | Accepted |
| [0011](0011-consent-is-per-client-and-off-by-default.md) | OIDC consent is per-client and off by default | Accepted |
| [0012](0012-the-directory-administers-itself-through-cedar.md) | The directory administers itself through Cedar | Accepted |
| [0013](0013-enrollment-invitations.md) | Enrollment invitations replace break-glass as the bootstrap path | Accepted |
| [0014](0014-break-glass-removed.md) | Break-glass removed; the CLI is the recovery path | Accepted |
| [0015](0015-dual-control-recovery.md) | Recovery takes two administrators | Accepted |
| [0016](0016-cardinal-serves-its-own-discovery-document.md) | Cardinal serves its own discovery document | Accepted |
| [0017](0017-prompt-and-max-age-are-honoured.md) | `prompt` and `max_age` are honoured, not accepted | Accepted |
| [0018](0018-access-tokens-are-a-weaker-credential.md) | Access tokens are a weaker credential, not a second principal | Accepted |

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

- **Secret and key management** — where the SSH CA private key and attribute
  encryption keys live (file, KMS, HSM, Vault). Blocks Phase 4. The OIDC
  signing-key encryption key already lives in configuration rather than the
  database, so a database read alone is not enough; this question is about the
  rest.
- **Session revocation propagation** — `NOTIFY` is a hint, never a guarantee
  (ADR 0004). The read-time enforcement path needs specifying before Phase 2.
