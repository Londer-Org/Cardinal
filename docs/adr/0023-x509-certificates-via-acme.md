# ADR 0023: Cardinal issues X.509 certificates, over ACME

- **Status:** Accepted — implemented.
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

## What the implementation settled (2026-08-07)

**Authorizations are born valid, and no challenge is ever issued.** The whole
apparatus of http-01 and dns-01 exists to establish that a stranger controls a
name. The client here is an enrolled host that proved which host it is, and the
names it may hold are in the directory — so there is nothing left to
demonstrate. RFC 8555 §7.1.6 permits this and every client handles it: lego
logs `authorization already valid; skipping challenge` and goes straight to
finalize.

**External Account Binding is how an account acquires an identity.** An ACME
account is anonymous by construction — a key the client generated. §7.3.4's
binding is the standard way to attach it to something out of band, it is what
cert-manager, lego, certbot and acme.sh all support, and the alternative was
carrying Cardinal's own host signature through a protocol with nowhere to put
it. `cardinal host acme-credentials <host>` issues one; it is single use, like
a host enrollment token and for the same reason.

**Nothing on the certificate comes from the CSR except the public key.** A CSR
carries a subject and SANs, and both are what the client would *like*. The names
issued are the ones the order was authorised for, which Cardinal took from the
directory. Asking for another machine's name is refused with
`rejectedIdentifier` and a message naming the fix.

**ACME needs its own public URL.** §6.1 requires HTTPS and clients enforce it —
lego refuses an http directory outright. Every URL in the directory document is
absolute, so a deployment terminating TLS elsewhere, or reaching ACME through a
different ingress, has to say where. `x509.public_url` defaults to
`server.public_url` and startup refuses anything that is not https.

There is a bootstrapping fact here worth stating plainly: **Cardinal's own ACME
endpoint cannot get its certificate from Cardinal's ACME.** The first
certificate always comes from somewhere else.

**Verified against a client nobody here wrote.** `make verify-acme` drives the
whole flow with lego: obtain, refuse another machine's name, issue an entitled
alias, and refuse to reuse a spent credential. Everything else in this project's
test suite is Cardinal agreeing with Cardinal; this is the only check that says
an outside implementation will talk to it, which is the entire claim above.

**Whether an existing root can be imported is open.** The SSH side generates its
own key because there is rarely an existing SSH CA to adopt. X.509 is the
opposite: most organisations already have a root they intend to keep, and
"Cardinal generates it or nothing" would be a poor reason to run a second CA
alongside. Importing a root — or, better, an intermediate signed by one that
stays offline — should be supported, and the shape of that is not yet decided.

**It does not make Cardinal a FreeIPA replacement.** DNS remains out of scope,
Windows remains out of scope, and a site needing those still needs them. This
closes one of the three reasons FreeIPA survives a migration, not all three.
