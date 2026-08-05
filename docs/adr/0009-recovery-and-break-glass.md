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

## On recovery email: rejected as an authentication path

Recovery email was considered and is **deliberately not implemented**. Three
reasons, the first of which is decisive for Cardinal specifically:

1. **Circular dependency.** Cardinal's purpose is to be the SSO provider for
   company services — including email. If email access authenticates through
   Cardinal, then "Cardinal is broken" implies "email is unreachable", and the
   recovery channel is unavailable in precisely the scenario it exists for.
   This is the classic identity-system deadlock and it is not theoretical.
2. **It downgrades the entire system to mailbox control.** A passkey is
   phishing-resistant and hardware-bound. Email is a bearer channel with no
   cryptographic binding to anyone. Adding it as a recovery path means the
   real authentication strength of every account — including administrators —
   is that of its mailbox. Building AAL3 authentication behind an AAL1
   recovery path is self-defeating.
3. **It cannot satisfy the break-glass requirement anyway.** Determining where
   to send the message requires reading the database, which is exactly what
   may be unavailable.

Email *is* used, but only in the opposite direction: as a **notification**
channel. Recovery attempts, break-glass use, and credential changes generate
alerts. Notification is a safe use of an unauthenticated channel; authorization
is not.

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
