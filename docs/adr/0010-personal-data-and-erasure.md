# ADR 0010: Personal data never enters the audit journal

- **Status:** Accepted
- **Date:** 2026-08-05

> **Amended 2026-08-09.** The table of where personal data lives was
> incomplete, and the omission caused a bug rather than merely describing one:
> `webauthn_credentials` was not listed, so erasure did not delete credentials,
> and an erased account could still be signed into with its passkey. Erasure now
> removes them and disables the account. The tombstone format recorded here was
> also wrong — it uses the whole id, not a prefix. Both are corrected below.

## Context

Two of Cardinal's commitments are in direct tension:

- **ADR 0003**: the audit journal is append-only and hash-chained. Rows cannot
  be deleted or modified without breaking the chain — that is precisely what
  makes it evidence.
- **GDPR Article 17**: a data subject may require erasure of their personal
  data. Cardinal is built by and for an EU organisation, so this is a legal
  obligation, not an aspiration.

Naively, these are irreconcilable: erasure demands deletion, and the chain
forbids it. Worse, the tension is invisible until the first erasure request
arrives — by which point years of events contain names, emails, and free-text
justifications, and the only remedies left are bad ones.

This must therefore be settled before Phase 1 starts writing many event types,
not after.

## Decision

**Personal data never enters the journal in the first place.**

Event payloads carry only **opaque identifiers and non-identifying facts**.
Personal data lives exclusively in mutable state tables (`entities`, and the
`reason` column on `group_members`), which can be redacted.

Erasure then becomes: **redact the referenced records, leave the chain
untouched.** The journal keeps proving what happened and when; it simply
loses the ability to say who, once the referenced identity is redacted.

This is standard pseudonymisation. A UUID linked to a living person is personal
data while the link exists; once the entity record is redacted, the UUID is no
longer attributable to anyone and the residual data is effectively anonymous.

### What may appear in a payload

Enforced in code, not by convention (`internal/directory/event/payload.go`):

| Permitted | Rationale |
|---|---|
| Entity IDs (`entity_id`, `group_id`, `member_id`) | Opaque; redaction severs the link |
| Timestamps (`from`, `until`, `revoked_at`) | Not identifying |
| Enumerations (`type`, `auth_method`) | Fixed vocabulary, cannot smuggle text |
| Booleans and integers (`device_bound`, `depth`) | Not identifying |

**Free-form strings are rejected outright.** Not discouraged, not reviewed —
rejected by `event.New`, which fails rather than writing an unsafe payload.

This matters because free text is where personal data actually arrives. Nobody
writes `payload["email"] = ...`; they write a `reason` field, and six months
later it contains *"covering for Jan while he's on sick leave"*.

### Where personal data does live

| Data | Location | Erasure |
|---|---|---|
| Name, display name, extension attributes | `entities` | Tombstoned in place |
| Grant justification (`reason`) | `group_members` | Nulled |
| IP address, user agent | `sessions` | Deleted outright (no append-only rule) |
| Public key, AAGUID | `webauthn_credentials` | Deleted outright |
| Home directory path | `posix_identities` | Rewritten to the tombstone |

The last two rows were missing until 0.3.0, and their absence was not merely a
documentation gap — it was the reason erasure did not remove them. A credential
looks like a security artefact rather than personal data, so nothing deleted
it. It is both: a public key is a unique, persistent identifier for a device a
particular person physically holds, and it stays that way for the life of the
authenticator.

Leaving it behind also left the access it grants. Erasure stamped `redacted_at`
and nothing else that mattered to authentication — it did not set `disabled_at`,
and the WebAuthn login path admits any entity whose `disabled_at` is NULL — so
an erased account could still be signed into with the passkey it always had.
**Erasure therefore disables the account as well.** An erasure that leaves a
working credential is not an erasure, for the same reason a reversible one is
not.

Redaction replaces `name` with a stable tombstone (`redacted-<id>`), clears
`display_name` and `attrs`, and stamps `redacted_at` and `disabled_at`. The row
survives so foreign keys from the journal still resolve — a dangling reference
would break audit queries and, ironically, make the system *less* accountable.

The tombstone carries the **whole** id, not a prefix of it. It took the first
eight characters until a test erased two accounts and the second one failed:
for a UUIDv7 those characters are the high bits of a millisecond timestamp and
change roughly every seven weeks, so every entity of a type erased within the
same window produced an identical tombstone and collided on
`entities_name_unique_per_type`. A GDPR request failing with a constraint
violation is not a class of bug to leave to chance. The id is already public —
it appears in the journal, which erasure deliberately cannot reach — so using
all of it discloses nothing.

## Alternatives considered

**Crypto-shredding**: encrypt personal data in payloads under a per-subject
key, then destroy the key. Legally well-regarded and it preserves payload
richness. Rejected as disproportionate here: it requires a per-subject key
hierarchy, key escrow, and rotation — significant permanent machinery — to
solve a problem that not putting the data there avoids entirely. Worth
revisiting only if payloads ever genuinely need personal content.

**Rewriting the chain on erasure**: delete rows and recompute all subsequent
hashes. Rejected outright. A journal that can be rewritten on request is not
evidence, and the capability itself becomes an attack target — an attacker who
can trigger "erasure" can launder their own activity.

**Truncating history periodically**: retain events for N months only. A useful
*complement* (partitioning already supports it), but not a solution: erasure
can be demanded well inside any sensible retention window.

**Relying on legitimate-interest exemptions**: security audit logs plausibly
fall under Article 17(3)(b)/(e). Rejected as the primary strategy — it is a
legal argument rather than a technical guarantee, it would need defending case
by case, and "we built it so the question doesn't arise" is a much stronger
position for a security product to hold.

## Consequences

**Good.** Erasure requests are satisfiable without touching the journal. The
chain's evidentiary value is never in tension with a legal obligation. The
constraint is enforced by the compiler and tests rather than by reviewer
vigilance.

**Costs.** Audit payloads are less immediately readable: reconstructing "who"
requires joining to `entities`, and after redaction that answer is
intentionally unavailable. Every new event type must express itself in IDs and
enumerations, which occasionally takes more thought than dropping a string in.

**This constrains the whole system, permanently.** Every future event type —
OIDC token issuance, SSH certificate issuance, policy decisions — must obey it.
The allowlist is the enforcement point, and adding a key to it is a decision
that deserves the same scrutiny as this ADR.

**Already applied retroactively.** The Phase 0 payloads carried `name` and
`reason`; both were removed when this ADR was written. Doing that now cost one
commit. Doing it after a year of production events would have meant either a
chain rewrite or a legal argument.
