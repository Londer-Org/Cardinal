# ADR 0012: The directory administers itself through Cedar

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

[ADR 0005](0005-cedar-as-the-single-decision-point.md) claims one decision point
for four questions, and the fourth row of its table is the one that most
distinguishes Cardinal from what it replaces:

| Decision point | Replaces | Question |
|---|---|---|
| Admin API | LDAP ACLs | Can they modify this directory object? |

Until now that row was aspirational. `Cardinal::Action::"AdministerDirectory"`
existed and two `forbid` rules guarded it — one requiring fresh, device-bound
authentication, one excluding break-glass sessions — but nothing ever
*permitted* it and no code path ever evaluated it. Cedar is default-deny, so
the effective state was that nobody could administer anything, which was
invisible because nothing asked.

Making it real needs a permit rule, and a permit rule has to name a group. A
policy file shipped in the repository cannot reference a UUID generated at
install time, and [ADR 0002](0002-identity-is-an-immutable-uuid.md) rules out
referencing the group by its mutable name.

## Decision

**A built-in group, `directory-admins`, created by migration 0008 with a fixed
identifier `00000000-0000-7000-8000-00000000ad11`.** The shipped policy set
permits `AdministerDirectory` to its members, and every admin endpoint
evaluates that action before doing anything.

The identifier is deliberately not a real UUIDv7. It is recognisably synthetic,
so nobody reading a grant log mistakes it for something the system generated,
and it sorts to the front of any id-ordered listing. Its version and variant
bits are valid, so every `uuid` column accepts it.

It is declared in three places — `policy.AdminGroupID`, migration 0008, and
`policies/cardinal.cedar` — and a unit test asserts they agree. Changing one
without the others would silently stop administration working for everyone,
with no error to follow.

Four consequences worth stating:

1. **Membership is an ordinary grant.** `cardinal grant directory-admins alice`
   uses the same temporal membership machinery as everything else, so admin
   rights are time-boundable, audited, and revocable with `FOR PORTION OF` like
   any other access. "Alice is an admin for the duration of this incident" is
   expressible without a second mechanism.

2. **Nobody is a member after migration.** A migration that made the first
   account an administrator would be a backdoor with a changelog entry. The
   first grant is made with the CLI, which reaches the database directly.

3. **The forbids still win.** Membership is necessary, not sufficient: a Cedar
   `forbid` always beats a `permit`, so an admin on a synced passkey, an admin
   whose last authentication was ten minutes ago, and an admin in a break-glass
   session are all refused. That ordering is what makes the step-up rules
   trustworthy rather than advisory.

4. **Every refusal names the deciding policy**, in the response as well as the
   log. Where more than one rule fires, the message is chosen by what it implies
   about the fix rather than by Cedar's return order — a break-glass session
   trips the freshness rule too, but telling that user to "sign in again with
   your key" is a dead end, because no amount of re-authenticating makes an
   emergency session able to administer.

The UI reads a `canAdminister` flag from `/api/auth/me` to decide whether to
render the admin section. That is presentation only, re-evaluated per request;
the endpoints do not trust it.

## Consequences

**Good.** The fourth row of ADR 0005's table is now true. Administering the
directory is governed by the same reviewable, versioned, git-hosted policy set
as web access and host login, and "why was I denied?" is answerable for admin
actions through the decision explorer. LDAP's separate ACL language has no
counterpart here, which was the point.

**Costs.** A well-known identifier in a shipped policy file is unusual, and an
operator who deletes the group locks everyone out of administration — recoverable
only through the CLI. The table comment on `entities` says so.

**Not covered.** Per-object administration ("may edit this group but not that
one") is not expressible: admin actions evaluate against a single resource,
because inventing a resource hierarchy the policy set cannot use would suggest a
granularity that does not exist. Adding it later is a policy change plus a
resource argument, not a redesign.
