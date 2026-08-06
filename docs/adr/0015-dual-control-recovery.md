# ADR 0015: Recovery takes two administrators

- **Status:** Accepted
- **Date:** 2026-08-06
- **Fixes:** a privilege escalation introduced by the admin tiers, found the
  same day.

## Context

[ADR 0013](0013-enrollment-invitations.md) made enrollment invitations the way
an account gets its first passkey, and noted in passing that issuing one for an
account that *already* has credentials is legitimate — it is how someone who
lost every device gets back in — while being "indistinguishable from an account
takeover by shape alone". It was logged at warning level and left as a single
administrator's decision.

Splitting administration into tiers ([user-admins and security-admins]) made
that unsafe rather than merely uncomfortable. Issuing invitations is onboarding,
so it sat with `user-admins`. Which meant:

1. a `user-admins` member issues an invitation for a `directory-admins` account;
2. opens the link, registers a passkey;
3. is now that administrator.

The narrow tier contained a path to the broad one, so the split bought nothing.
This was confirmed against the running stack before it was fixed: the endpoint
returned `201` with a working link for a directory-admin.

The same problem exists without tiers, in a weaker form: any single
administrator could take over any other account, including a colleague's,
leaving only a log entry.

## Decision

**The two cases are separated by what they actually are.**

- **Onboarding** — the account has no credentials. Nobody can sign in to it
  anyway, and somebody had to create it. **Single control**, `ManageUsers`.
- **Recovery** — the account can already sign in. **Two distinct administrators
  holding `AdministerDirectory`**, neither of them the subject.

`POST /api/invitations` now refuses an enrolled account and says what to do
instead. Recovery is its own flow: one administrator opens a request with a
reason, and a second approves it. The second approval issues the invitation and
returns the link once.

The details that make it dual control rather than the appearance of it:

- **The requester's own request is their approval.** Two people, not two
  clicks. Making them press a second button teaches only that the second press
  is a formality.
- **A duplicate approval is a conflict, not a no-op.** Silently accepting it
  would let one administrator believe they had satisfied the threshold.
- **Nobody may request or approve their own recovery**, enforced by a database
  constraint as well as in code. Someone who can authenticate does not need
  recovering, so a self-request is a live session minting a second credential
  without a second person.
- **One open request per account**, so "cancel it" is never ambiguous.
- **Requests expire** after 72 hours: long enough for a colleague in another
  timezone, short enough that nobody approves a request they no longer recall.
- **`user-admins` cannot approve.** Recovery can mint a credential on an
  administrator's account, so it needs the tier that already has full authority
  — otherwise the fix reopens the hole it closed.

Threshold is two, deliberately not three. Three is safer and also means an
organisation with two administrators can recover nothing, which is how a control
gets removed rather than followed.

## Consequences

**Good.** The tiers are real: no path from `user-admins` to `directory-admins`.
Taking over a colleague's account needs a second person who has to be told why,
and the reason is recorded where an approver reads it. This is also what
replaces the role separation break-glass used to offer ([ADR 0014]) — recovery
without shell access to the host, but requiring two people rather than one
sealed envelope.

**Costs.** A lone administrator cannot recover anyone through the API. That is
the intended shape of dual control, and the escape hatch is unchanged and
deliberate: `cardinal invite` on the host still works, because database access
is already the credential of last resort (ADR 0014). An organisation with one
administrator gets no separation of duties from this, and could not have.

**Not covered.** The approver sees a reason typed by the requester and takes it
on trust. Cardinal cannot verify that the person really lost their laptop, and
should not pretend to — the control here is that a second human is on the hook,
not that the claim was checked.

[user-admins and security-admins]: 0012-the-directory-administers-itself-through-cedar.md
[ADR 0014]: 0014-break-glass-removed.md
