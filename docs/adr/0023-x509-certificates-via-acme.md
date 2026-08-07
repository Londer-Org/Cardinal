# ADR 0023: Cardinal issues X.509 certificates, over ACME

- **Status:** Accepted — decided; implementation follows the SSH CA.
- **Date:** 2026-08-07
- **Reverses:** "Integrate `step-ca` if PKI is ever needed" (roadmap).

## Context

The roadmap declined an internal CA on the grounds that Kerberos, DNS and PKI
were "not used in the target environment". That is a statement about one
deployment, and it does not survive contact with a second: asked why FreeIPA
would be kept even after moving to modern SSO, an experienced operator answered
*"that one is very useful for linux servers, k8s certificates"*.

The certificate authority is a substantial part of what keeps FreeIPA installed.
Declining it does not remove the need; it means every Cardinal deployment either
keeps FreeIPA for one job, or runs a second system for it.

That second system was the stated plan — `step-ca`, which is a good CA. The
problem is what it does not have. **A CA's hard question is not signing, it is
knowing who is asking and whether they should have it.** `step-ca` has no
directory, so it has to be told: provisioners, tokens, a separate policy
expressed in a second language, and no connection to the group membership and
temporal grants that already govern everything else. Two stateful systems, two
places policy lives, and a decision log that stops at the boundary.

Meanwhile Cardinal is already building a certificate authority for SSH, and the
expensive parts are the parts it shares:

| A CA needs | Cardinal already has, or is building |
|---|---|
| To know who is asking | Host enrollment — hosts are directory entities with their own identity (Phase 4) |
| To decide whether to issue | Cedar, with the decision logged and the rule named |
| Somewhere safe for the key | `crypto.Signer` behind configurable custody ([ADR 0021](0021-ssh-ca-key-custody.md)) |
| Short lifetimes and renewal | The design premise of every credential it issues ([ADR 0022](0022-cardinal-issues-short-lived-credentials.md)) |
| An audit trail | A hash-chained journal |

What is left is encoding, and Go's `crypto/x509` does that.

## Decision

**Cardinal issues X.509 certificates for hosts and services, reusing the
identity, policy, key custody and audit it needs anyway for SSH.**

**The interface is ACME** ([RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)),
not a bespoke API. `cert-manager` speaks ACME, so does every web server and host
agent worth using. A consumer points at Cardinal instead of Let's Encrypt and
learns nothing new — which is the difference between a feature people adopt and
one they read about.

**Issuance is a policy decision like any other.** An enrolled host asking for a
certificate for a name it is entitled to gets one; the request is evaluated by
Cedar, and the decision is logged naming the rule. That is the part no other CA
in this space does, and it is free here because the machinery exists.

**It is optional.** A deployment that already has a CA keeps it. Nothing else in
Cardinal depends on this being enabled.

## Alternatives considered

**Keep `step-ca` as the plan.** Rejected above: it moves the hard part — who may
have a certificate for what — into a second system with no view of the
directory, and re-splits a policy story this project exists to unify. It remains
the right answer for anyone who wants a CA and not a directory.

**Implement a bespoke issuance API.** Simpler to build and worse to adopt. ACME
already exists in every consumer; a bespoke protocol would need a client per
language, which is the mistake [ADR 0019](0019-in-app-authorization.md) rejected
for the same reason.

**Do nothing and accept the gap.** Defensible and was the position until now. It
fails the general-purpose test: it leaves the most commonly cited reason for
keeping FreeIPA untouched, and answers "why do I still need FreeIPA?" with
"because we decided our first deployment did not need that part".

## Consequences

**The CA key becomes the second highest-stakes secret**, alongside the SSH CA
key. ADR 0021's reasoning transfers directly and so should its conclusions:
`crypto.Signer`, its own encryption key, PKCS#11 supported for anyone with an
HSM, and rotation designed in from the start. X.509 is easier than SSH here in
one respect — it *does* support intermediates, so an offline root signing a
short-lived online intermediate is available, and should be the recommended
shape rather than a long-lived key sitting in a database.

**Trust distribution is a new problem.** An internal CA is worthless until the
root is trusted, and getting it into system trust stores, container images, JVM
keystores and browsers is the part that makes people give up. `cardinal-agent`
can place it on enrolled Linux hosts; everything else is documentation and
honesty about the work involved.

**Scope discipline matters more here than usual.** X.509 has an enormous surface
— CRLs, OCSP, name constraints, path length, key usage, SCTs. The commitment is
short-lived certificates for enrolled hosts and services over ACME. Revocation
for a certificate measured in hours is renewal refusal, not a CRL, and that
should stay true rather than drifting into building a general-purpose PKI.

**It does not make Cardinal a FreeIPA replacement.** DNS remains out of scope,
Windows remains out of scope, and a site needing those still needs them. This
closes one of the three reasons FreeIPA survives a migration, not all three.
