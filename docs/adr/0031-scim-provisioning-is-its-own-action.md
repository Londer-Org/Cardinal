# 31. SCIM provisioning is its own action, not administration

**Status:** accepted
**Date:** 2026-08-09

## Context

An identity provider — Entra, Okta, anything speaking SCIM — provisions accounts
into Cardinal. It presents a bearer token, unattended, forever.

Every administrative action in Cardinal is guarded by
`admin-requires-fresh-device-bound-auth`, a forbid written
`unless { principal.deviceBound && principal.authAgeSeconds <= 300 }`. An access
token is never device-bound, deliberately
([ADR 0018](0018-access-tokens-are-a-weaker-credential.md)) — so a SCIM client
authenticating with one is refused `ManageUsers`, and cannot create the accounts
it exists to create.

That refusal is correct for what it was written about: a person administering the
directory from a browser should hold a hardware key and have used it recently.
It is not a statement about a machine that will never hold one.

There is a further hazard, and it is the one that decided the shape of this.
Group membership is provisionable over SCIM, and `directory-admins` is a group.
A SCIM client able to PATCH any group is a path from "the IdP integration" to
"directory administrator" — the same escalation
[migration 0013](../schema.md) added `entities.system` to close, when it
observed that granting membership is `ManageUsers` and a user admin could
therefore grant themselves the broad tier.

## Decision

**Provisioning is its own Cedar action, `Provision`.** It is not covered by the
step-up forbid, which names its actions explicitly rather than matching broadly
— an explicitness the policy file already justified on the grounds that a
narrower tier escaping the rule would be a hole.

Two independent things must be true for a SCIM request to be honoured:

1. The access token was issued with the `scim` scope. Scopes cannot be changed
   on an existing token, so a token issued for anything else can never become a
   provisioning credential.
2. Policy permits `Provision` for the token's owner. The shipped rule names a
   group, `provisioners`, which is empty on a fresh install.

**A system group is never provisionable.** `entities.system` marks membership
that confers authority *inside* Cardinal. SCIM refuses to create, modify, or
change the membership of one, and says so. Whoever runs the IdP administers the
IdP; they do not thereby administer Cardinal.

**Three things stay outside SCIM entirely.** Credentials, because a passkey is
registered by its owner and by nobody else. POSIX numbers, because they are
permanent once served ([ADR 0029](0029-a-number-is-permanent-once-it-has-been-served.md))
and an IdP has no idea which are taken. And policy, because a provisioning
client changing the rules is the escalation this whole ADR exists to prevent.

## Consequences

**A provisioning token is powerful, and this is the honest statement of how
powerful.** It can create accounts, disable them, rename them, and move people
between non-system groups. That is what pointing an IdP at a directory means,
and pretending otherwise by requiring a passkey the machine cannot hold would
only produce a deployment that turns the check off.

What bounds it instead:

- It cannot make anybody a Cardinal administrator, because system groups are
  refused.
- It cannot authenticate as anybody. A provisioned account has no credential and
  cannot be signed into until its owner enrols one.
- Every change is in the hash-chained journal with the token's owner as actor,
  so "the IdP did this" and "a person did this" are distinguishable afterwards.
- The token is bounded in time like every other, and scoped to `scim` alone.

**The step-up rule now has a companion it must be read with.** Anyone auditing
`admin-requires-fresh-device-bound-auth` and concluding "no unattended
credential can change the directory" would be wrong. The rule below it is where
that stops being true, and it is in the shipped policy set where it can be seen
rather than in a special case in code.

**Refusing rather than partially applying.** SCIM PATCH is a list of operations,
and a request that touches one system group among five ordinary ones is refused
whole. A partial application would leave the IdP believing it had synchronised
while Cardinal disagreed — and the next reconciliation would try again forever.
