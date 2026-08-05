# ADR 0009: Account recovery and break-glass

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

Cardinal has no passwords (ADR 0002). Passkeys are excellent until someone's
laptop is stolen, and then the question is how they get back in — without that
recovery path becoming the weakest link in the whole system.

Three different problems get conflated under "recovery", and they have
different answers:

| Problem | Cardinal state | Example |
|---|---|---|
| **Account recovery** | Up and healthy | "I lost my laptop" |
| **Break-glass** | Degraded, or admin access lost | "Nobody can administer the directory" |
| **Disaster recovery** | Database gone | "The volume is corrupt" |

## Decision

Four layers, each solving one problem. Crucially, **the mechanism that solves
one must not weaken the others.**

### Layer 1 — Prevent lockout

An account is not fully enrolled until it has **two registered passkeys**,
ideally on separate devices (laptop platform authenticator plus a hardware
security key kept elsewhere). Most recovery events simply never happen.

### Layer 2 — Account recovery, while Cardinal is up

- **Recovery codes**: high-entropy, single-use, hashed with Argon2id, shown
  once at enrollment.
- **Recovery email** for ordinary users only, as one signal among several —
  never for administrators, never alone. See the amendment below for the
  conditions attached.
- **Admin-mediated re-enrollment under dual control**: two administrators must
  independently approve restoring a third party's access. This is what stops
  a single compromised (or coerced) admin account from taking over any
  identity in the directory.
- **TOTP** is supported as an *additional* factor and as a migration aid — see
  below — but is never on its own sufficient to recover an account, and never
  sufficient for administrative actions.

### Layer 3 — Break-glass

The break-glass credential is an **Ed25519 keypair generated offline at
bootstrap**. The private key is printed or written to removable media and
stored physically; it never exists on the server. Cardinal holds only the
**public key, in its configuration file — deliberately not in the database.**

That placement is the whole design:

- A database compromise cannot substitute an attacker's break-glass key.
- A database *restore* cannot silently roll the key back to an older value.
- Verification does not depend on directory state being readable.

`cardinal break-glass` signs a server-issued challenge with the offline key and
receives a **15-minute emergency administrative session**. Every use emits an
alert-severity event and must page a human. Break-glass that nobody notices is
just a backdoor.

For the highest-privilege operations (disabling the audit log, rotating the
break-glass key itself), **two distinct break-glass keys must sign**.

### Layer 4 — Disaster recovery

`pgBackRest` PITR, plus `make restore-drill`, which restores to a scratch
database and verifies the audit hash chain. Already implemented.

## On recovery email: optional, constrained, and self-policing

**Amended 2026-08-05**, before implementation. The original text rejected
recovery email outright, on the assumption that email would authenticate
*through* Cardinal. That assumption is deployment-specific, and Cardinal is a
general-purpose product: it cannot know what any given operator's email is, who
runs it, or how it is secured. The conclusion is therefore restated as a rule
Cardinal can enforce for **any** environment, rather than a verdict derived from
one.

### The governing principle

> **A recovery channel must not depend on the system being recovered.**

That is the whole rule, and it is environment-independent. Whether email is
self-hosted, Google Workspace, Microsoft 365, or a third-party provider, the
question is identical: *if Cardinal is unavailable or compromised, can this
channel still be reached, and can it still be trusted?*

The dependency is rarely present on day one. It is usually **created later**,
when someone federates the mail provider to Cardinal for SSO — a change made for
entirely unrelated reasons, by someone not thinking about account recovery. The
recovery path then breaks precisely when it is needed, and nobody notices until
the day it matters.

This is not hypothetical for any particular vendor. Every major mail platform
supports third-party IdP SSO over SAML or OIDC, and Cardinal becomes an OIDC
provider in Phase 3. Any deployment can walk into this.

### Cardinal enforces it rather than documenting it

A warning in a document is not a control. Cardinal therefore **detects the
circular dependency itself**:

- Recovery email is **opt-in and off by default**.
- The operator configures which email domains are acceptable for recovery.
- **At startup and at OIDC client registration, Cardinal refuses to serve a
  relying party whose domain is also configured as a recovery-email domain.**
  Creating the loop becomes an error, not a silent regression.

An operator who genuinely wants both must remove the recovery domain
deliberately, which is exactly the moment to think about it.

### What the operator is accepting

Recovery email is permitted for **ordinary users** as one signal in a recovery
flow. Enabling it means accepting, knowingly:

1. **The mail provider becomes a root of trust for Cardinal recovery.** Whoever
   controls a mailbox can recover the corresponding account. Strong providers
   with enforced security keys make this defensible; weak ones make it a
   liability. Cardinal cannot judge this, so the operator must.
2. **Mail administrators implicitly become Cardinal administrators.** Anyone who
   can read or reset a user's mailbox can intercept a recovery message. This is
   a genuine privilege-escalation path and must be named, not discovered.
3. **It remains a bearer channel** with no cryptographic binding to a person.

Consequence (2) is why the limits below are not configurable.

### What recovery email may never do

- **Recover an administrator's account.** Consequence (2) makes this circular —
  it would place Cardinal's administrative tier beneath the mail platform's.
  Admin recovery stays dual-control (Layer 2) or break-glass (Layer 3).
- **Serve as break-glass.** Determining the address requires reading the
  database, which is exactly what may be unavailable.
- **Act alone.** One signal in a recovery flow, never a single-factor
  password-reset link.

Email is also used in the safe direction, as a **notification** channel:
recovery attempts, break-glass use, and credential changes all raise alerts.
Notification over an unauthenticated channel is sound; authorization is not.

## On TOTP: supported, but positioned carefully

TOTP earns its place for two concrete reasons:

- **Migration.** FreeIPA supports TOTP and users may already have it enrolled,
  so it smooths the transition rather than demanding everyone adopt passkeys on
  day one.
- **Coverage.** It gives a second factor to anyone who has not yet enrolled a
  second passkey.

Its limits are stated explicitly because they are easy to forget:

- **It is a shared secret.** The server must store material that permits
  impersonation; a database dump yields working credentials. Passkeys are
  asymmetric and have no such property.
- **It is phishable.** A convincing prompt harvests a TOTP code just as it
  harvests a password. This is the exact attack class passkeys eliminate.
- **It requires the database.** Useless for break-glass.

Therefore: TOTP may satisfy a second-factor requirement for ordinary users. It
**may not** authorize administrative actions, approve dual-control recovery, or
serve as break-glass. Cedar policy enforces this — `auth_method` and
`device_bound` are part of the session context precisely so a policy can demand
a device-bound passkey for privileged operations.

## Consequences

**Good.** No single credential, mailbox, or administrator can take over the
directory. Break-glass works when the database has been restored or is
untrusted, because its root of trust lives in configuration rather than data.

**Costs.** Bootstrap becomes a genuine ceremony: generate the key, record it
physically, store it somewhere with controlled access. That is friction, and
it is the correct amount of friction for the credential that can do anything.

**Operational obligations, non-negotiable:**

- **Test break-glass quarterly.** An untested emergency procedure is not a
  procedure. It belongs on a calendar with the restore drill.
- **Two people must be able to reach the offline key.** One person holding the
  only copy converts a recovery mechanism into a bus-factor risk.
- **Alert on every use, loudly.** Silent break-glass is a backdoor.

**Open, deferred to Phase 1 implementation:** whether to split the break-glass
key with Shamir's Secret Sharing (k-of-n) rather than issuing n independent
keys. Splitting enforces multi-party recovery cryptographically; independent
keys are far simpler to operate and to test. Simplicity likely wins, but the
decision needs the implementation in front of it.
