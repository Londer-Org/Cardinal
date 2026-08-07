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

## Revisited, 2026-08-07

The alternatives section above said a read-only LDAP gateway was "worth
revisiting if Cardinal is ever adopted somewhere with genuine legacy LDAP
consumers", and rejected it on the assumption that host login was the only
FreeIPA dependency. Evidence from a real deployment arrived, and the assumption
was wrong: eight applications bind LDAP there — Redmine, Request Tracker, MISP,
TheHive, GitLab, FreePBX, Jenkins and OpenStack.

So the condition was met. The decision does not change, but the reasoning does,
and the original reason should not be left standing.

**There are two different things called "LDAP", and only one of them matters.**

*An application binding LDAP to authenticate its users.* This is what those
eight do, and it is being retired rather than extended — that site's own plan
moves each of them to native OIDC or to `forwardAuth`, describing the LDAP
arrangement in its own words as "a shared password but a separate login per
app… centralized authentication, not SSO". `forwardAuth` is strictly better
here and Cardinal already has it: the proxy authenticates, the application
needs no support at all, and the result is real single sign-on rather than one
password reused eight times. Building an LDAP server to serve this case would
be building toward the thing being abandoned.

*An identity provider binding LDAP to read the directory.* This is the case
that looked like it mattered, because every product in this space works this
way — Authelia takes a File or LDAP backend and nothing else, Keycloak is
deployed against FreeIPA, Univention pairs Keycloak with its own LDAP. Without
speaking LDAP, Cardinal cannot slot in as the directory behind any of them, and
must replace the whole stack at once rather than one layer at a time. That is a
real adoption cost and the strongest argument for a gateway.

**It fails anyway, for a reason that is not about principles.** Authelia's LDAP
backend expects the directory to hold the user's password: a service account
searches, then the password is validated against the directory. Cardinal has no
password column and will not have one. A passwordless directory cannot serve a
password-based portal, so the gateway would produce a stack that still could not
authenticate anybody. The incremental adoption path it appears to open is not
actually open.

**What would reopen this.** A consumer that (a) cannot be put behind a reverse
proxy, so `forwardAuth` does not reach it, and (b) can send an access token
where it thinks it is sending a password. The second half is now plausible in a
way it was not when this was first written: [ADR
0018](0018-access-tokens-are-a-weaker-credential.md) added a bearer credential
Cardinal *can* verify, so a simple bind could be checked without introducing a
password. Non-web infrastructure is where such a consumer would be found —
OpenStack's API, a PBX, anything doing service-account binds. Worth enumerating
before ruling it out permanently; not worth building on speculation.
