# ADR 0002: Identity is an immutable UUIDv7, and we speak no LDAP

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

LDAP's original sin is that the Distinguished Name *is* the identity.
`uid=alonfils,ou=engineering,dc=example,dc=com` encodes who someone is, what
team they're on, and where they sit in a tree — all in the primary key.

Everything painful about LDAP follows from that:

- Renaming a person, or moving them between teams, changes their identity.
  Every reference to them breaks: group memberships, ACLs, application records.
- `modifyDN` exists to paper over this, and is where the sharp edges live.
- Schema is rigid and OID-based, because the DIT has to stay stable.
- Applications cache DNs, which then go stale in ways nobody notices until an
  authorization check silently fails open or closed.

The protocol has matching problems: simple bind puts credentials in plaintext on
the wire, ACL syntax is vendor-specific and untestable, and there is no standard
notion of MFA, rate limiting, or audit.

## Decision

**Identity is a UUIDv7, assigned once, never changed, never reused.** Names,
emails, team placement, and org structure are ordinary mutable attributes.

**Cardinal speaks no LDAP wire protocol at all** — not as a server. Egress is
OIDC, SCIM, gRPC/REST, and Traefik `forwardAuth`.

Note the asymmetry: Cardinal *reads* LDAP as a **client** during migration from
FreeIPA. Being an LDAP client is fine; being an LDAP server is what we refuse.

## Alternatives considered

**A read-only LDAP gateway.** Legacy clients bind and search; writes go through
the modern API. Covers most real LDAP usage and would ease migration. Rejected
for Cardinal's actual deployment target: the only FreeIPA dependency here is
Linux host login, and ADR 0006 replaces that with SSH certificates rather than
directory lookups. A gateway would exist to serve a need we designed away.

Worth revisiting if Cardinal is ever adopted somewhere with genuine legacy LDAP
consumers. The data model deliberately doesn't preclude it.

**Full read-write LDAPv3.** True drop-in replacement. Rejected — it would drag
DN-as-identity semantics back into a data model built specifically to escape
them, and `modifyDN` would have to be emulated against a schema with no DNs.

**Human-readable natural keys** (`login` as the primary key). Rejected for the
same reason as DNs: people change their names, and reusing a freed login would
silently transfer a former employee's history to a new hire.

## Consequences

**Good.** Renaming a person is an `UPDATE` to one attribute. Org restructuring
touches no identity. Audit history keeps resolving even after someone leaves and
their name is reused. No `modifyDN`, no stale-DN cache bugs, no plaintext binds.

**Costs.** No legacy LDAP client can talk to Cardinal — this is a hard migration
boundary, not a soft one. UUIDs are unfriendly in URLs and CLI output, so every
surface must resolve names to IDs for humans while storing only IDs.

**Soft delete, always.** Entities are disabled, never hard-deleted. A deleted
user's past grants still have to be explicable, and foreign keys from the audit
trail must keep resolving.
