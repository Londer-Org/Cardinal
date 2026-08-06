# ADR 0013: Enrollment invitations, and break-glass demoted to emergencies

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

Cardinal could create accounts and it could authenticate them, and there was no
path between the two. `cardinal user create` produced an account with no
credential, and the only route to a first passkey was break-glass — the offline
Ed25519 key that can assume *any* account.

So onboarding a colleague meant one of:

- handing them the break-glass key, which is the credential that can impersonate
  the entire directory; or
- an administrator break-glassing into the new account and registering a passkey
  the administrator physically possesses, which is not that person's credential
  in any meaningful sense.

Both are worse than the problem. This was not a missing convenience — it was the
reason Cardinal could not have a second user.

[ADR 0009](0009-recovery-and-break-glass.md) describes break-glass as a recovery
mechanism and says it should be rare and alarming. It was instead the ordinary
path, which is exactly how a mechanism stops being alarming.

The obvious industry answer is a generated first-use password: create the
account, send a temporary password, force a change at first sign-in. It is
familiar to every IT team. It is also a credential that exists off the user's
device, travels through a channel Cardinal does not control, is phishable and
replayable until used, and tends to be reused. Cardinal has no password column
and this is not the feature that adds one.

## Decision

**An enrollment invitation: a single-use, short-lived, revocable token
authorising exactly one act — registering a passkey on one named account.**

It is designed on the assumption that it *will* be sent over an untrusted
channel, because it will be:

- **Single use**, enforced by consume-and-return in one SQL statement rather than
  check-then-mark, so two requests racing the same link cannot both enrol. Two
  credentials on one account, one of them an attacker's, is worse than a failed
  enrollment because nothing looks wrong afterwards.
- **Short-lived** — 24 hours by default. Long enough for someone asleep or in
  another timezone; short enough that a link in a chat backlog is dead.
- **Revocable**, and superseded automatically when another is issued for the
  same account. Two live links would make "revoke it" ambiguous, which is the
  worst property to discover while revoking one in a hurry.
- **Hashed at rest.** Only sha256 is stored. A backup, a replica or an injection
  elsewhere must not yield a working credential.
- **No session.** Redeeming registers a credential and nothing else. The user
  then signs in with the passkey they just made, which proves it works while they
  are still in front of the screen. An invitation is therefore never a way to
  obtain a session, only a way to obtain the ability to create one.
- **Uniform refusals.** Expired, revoked, spent and never-existed all return the
  same message, so the endpoint cannot be used to ask whether an account exists.

Issuing one is `AdministerDirectory`, because anyone who can issue an invitation
can take over the named account.

The invitation is also **where an account stops being blank**: the enrollment
screen takes the user's own display name and email. Without that, new accounts
arrive in every connected application as a UUID and nothing else, and there is
no later moment at which anyone thinks to fix it.

**Break-glass is demoted, not removed.** It stops being the bootstrap path and
returns to being what ADR 0009 always described: the emergency key. It stays
because invitations cannot replace it — an invitation must be issued by an
authenticated administrator, so if every administrator loses every device there
is nobody left to issue one. That is the lockout the offline key exists for, and
it is listed as a top risk in the project plan. Removing it would trade a
recoverable disaster for an unrecoverable one.

## Consequences

**Good.** Cardinal can onboard a second person. Break-glass becomes rare enough
that a warning-level log about it is worth alerting on, which is the property
ADR 0009 wanted and could not have while it was also the front door. No password
exists at any point.

**Costs.** A bearer token in a chat message is a real if bounded risk: whoever
holds it within the window can become that account. The mitigations above bound
it, and revocation plus the audit trail make misuse visible after the fact — but
an invitation intercepted and redeemed before its recipient notices is an
account takeover, and no amount of TTL tuning changes that. It is the same trade
every invitation system makes, and materially better than a password that does
not expire and can be reused elsewhere.

**Also.** Issuing an invitation for an account that already has credentials is
permitted, because that is how someone who lost every device gets back in. It is
logged at warning level and the enrollment screen says so, since it is
indistinguishable from an account takeover by shape alone.

**Not covered.** First-run setup — creating the very first administrator without
break-glass — is still open. Invitations narrow it: once one administrator
exists, everyone else arrives this way.
