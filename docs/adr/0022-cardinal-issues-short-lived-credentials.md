# ADR 0022: Cardinal decides, then issues a short-lived credential

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

Two scope decisions were made on the same premise and it failed twice.

[ADR 0002](0002-identity-is-an-immutable-uuid.md) rejected an LDAP gateway
because "the only FreeIPA dependency here is Linux host login". The roadmap
declined DNS, Kerberos and an internal CA because they were "not used in the
target environment". Both are statements about one deployment, offered as
reasons for a general-purpose product — and when a second environment was
described, both premises turned out to be false. Eight applications bind LDAP
there, and the internal CA is named as a reason FreeIPA stays.

The LDAP decision survived on better reasoning. The CA one did not, and is
reversed in [ADR 0023](0023-x509-certificates-via-acme.md).

That is two near-misses from the same cause, so the underlying problem is worth
fixing rather than the instances: **there was no stated idea of what Cardinal is,
so every scope question had to be argued from the deployment it happened to be
looking at.** A product defined by one site's needs cannot answer a question
from a different site.

## Decision

One sentence, and everything else follows from it:

> **Cardinal decides whether something is allowed, issues a short-lived
> credential saying so, and records which rule decided.**

Every credential it produces is that shape:

| Credential | Decided by | Lives for | Verified by |
|---|---|---|---|
| Session | a passkey ceremony | 8h idle, 7d absolute | Cardinal, at read time |
| OIDC token | `AccessApplication` | 15 minutes | the relying party, offline |
| Access token | a policy check per request | its validity range | Cardinal, at read time |
| SSH certificate | `SSHLogin` | 5–15 minutes | `sshd`, offline |
| X.509 certificate | policy on the host identity | short | anything, offline |

The pattern is not an accident of implementation. It is what makes an outage
survivable: a credential already issued keeps working, so a host stays
reachable and an application stays usable while Cardinal is down. It is also
what makes the audit story possible, because issuance is a moment where a
decision can be recorded, and continuous checking is not.

## What this rules in

Anything shaped like *decide, then issue*. That is why the SSH CA and an X.509
CA belong here and did not look like they did when the question was "is
Cardinal a FreeIPA replacement" — they are the same machinery with different
encodings, over an identity Cardinal already holds.

## What this rules out, and what to use instead

Stated as decisions with alternatives, not as gaps to apologise for. Each is
declined because it is *not* decide-then-issue, which is a reason that survives
a change of environment.

| Declined | Why it is not this shape | Use instead |
|---|---|---|
| **DNS** | A name lookup is not a credential. FreeIPA owns DNS largely to publish Kerberos SRV records; with no Kerberos there is nothing to publish | Whatever already runs DNS |
| **Kerberos KDC** | Ticket-granting is continuous dependence on the KDC — the opposite property | SSH certificates ([ADR 0006](0006-ssh-certificates-for-host-access.md)) |
| **Windows domain** | Domain join is SMB, LDAP, Kerberos and Group Policy — a product, not a feature | Entra ID, or Univention |
| **SAML** | Would fit the shape; declined on security grounds instead ([ADR 0007](0007-no-saml.md)) | OIDC |
| **LDAP server** | A simple bind is a continuous credential check against a password Cardinal does not have ([ADR 0002](0002-identity-is-an-immutable-uuid.md)) | `forwardAuth`, or OIDC |
| **In-app permissions** | The application's own semantics, and a decision per action is the opposite of issuing one ([ADR 0019](0019-in-app-authorization.md)) | Group identifiers in the token or headers |

A site running Cardinal still runs DNS somewhere, and still needs something for
Windows endpoints. That is the honest position rather than a roadmap item:
**Cardinal replaces FreeIPA's identity, access and credential-issuance jobs, not
the suite.**

## Consequences

**Scope questions get answered rather than relitigated.** "Should Cardinal do
X?" becomes "is X a decision followed by a short-lived credential?" — which has
an answer that does not depend on whose deployment is being discussed.

**The declines need alternatives, and the comparison document has to stay
honest.** Saying "not in scope" without naming what to use instead is how a
project reads as evasive. [comparison.md](../comparison.md) exists for this and
is deliberately organised around when *not* to choose Cardinal.

**It does not license scope creep.** The shape is a filter, not a mandate:
something fitting it still has to be worth building, still has to be optional
where it can be, and still competes with everything else for one maintainer's
attention.
