# ADR 0018: Access tokens are a weaker credential, not a second principal

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

A browser has a session cookie. A script has neither a browser nor a passkey,
and had nothing at all — so anything automated had to be routed *around*
Cardinal. The shape it takes in practice is a proxy rule matching the
Authorization header and sending API traffic straight to the application:

```yaml
- match: Host(`app.example`) && HeaderRegexp(`Authorization`, `^Bearer app_`)
  priority: 20          # higher than the authenticated route
  services: [ app ]     # no forwardAuth middleware
```

That works, and it costs three things. The application has to validate the
credential itself, which is exactly the responsibility forwardAuth exists to
take away. A routing regex becomes a security boundary. And — worst for this
project — the request never reaches a policy decision, so the one class of
traffic that runs unattended is the one class absent from the decision log. A
product whose case is "every decision names the rule that made it" cannot have
a blind spot where the automation lives.

## Decision

Cardinal accepts `Authorization: Bearer <token>` at the same endpoints it
accepts a session cookie, so there is nothing to route around. One rule, no
priorities, and the application still reads `X-Auth-Request-*` and nothing else.

A token is presented to the rest of the system as a `Session`, so claims
projection, policy evaluation and decision logging work unchanged. Two fields
carry the entire security argument:

- **`DeviceBound` is false, always.** `admin-requires-fresh-device-bound-auth`
  and `ssh-requires-device-bound` are both written
  `unless { principal.deviceBound && … }`, so a token is refused every
  administrative action and every SSH certificate **by policy that already
  existed**. No new rule was written for this feature.

- **`AuthAt` is when the token was issued**, not when it was used. A token typed
  into a pipeline months ago has not authenticated anyone recently, and
  reporting otherwise would make `authAgeSeconds` — which every freshness rule
  is built on — a fiction.

The consequence is worth stating plainly: **a token cannot do the most dangerous
things its owner can**, even when its owner is a full directory administrator.
That is a property of the policy rather than of the token table, which is why it
holds for rules nobody has written yet.

### Correction: that last sentence was wrong, and it cost something

It holds for every route that *asks* Cedar. Credential self-service never did.
Managing your own passkeys, recovery codes and tokens has no resource to
authorize against — only the caller's own account — so the whole surface sat
behind bare `requireAuth`, and a token reached all of it.

Found while building the console's token page, by a test written to assert this
document's claim. What a token could do, measured against a running stack:

| Request | Effect |
|---|---|
| `POST /api/recovery/codes` | Read ten account-recovery credentials, **and invalidate the owner's in the same statement** |
| `POST /api/credentials/register/begin` | Start attaching a passkey of the holder's choosing |
| `DELETE /api/credentials/{id}` | Revoke the owner's passkeys |
| `POST /api/tokens` | Mint its own successor, so revoking the leaked token achieved nothing |

A string in a CI variable was one request away from owning the account it was
scoped to serve — and the recovery-code path was worse than a takeover, because
it removed the owner's way back at the same time.

The fix is `requireDeviceBound`, a precondition on the credential sitting beside
`requireAuth` rather than a Cedar rule. Two reasons it is code:

- **Nothing varies.** Cedar answers "may this principal do this to that
  resource". Here the answer is the same for every principal and every resource,
  which makes it a property of the credential, like `requireAuth` and CSRF.
- **A policy set is editable and this must not be.** An administrator who
  published a set without the rule would hand every leaked token in the fleet an
  account takeover, and the mistake would look like an ordinary policy change in
  review.

The general lesson is the one worth keeping: **"the policy forbids it" is only
true where the policy is consulted.** Any route that does not reach the decision
point is outside every guarantee expressed there, and reasoning from the policy
alone will not reveal which routes those are. Only asking the running system
does.

## Consequences

CSRF is skipped for a token-authenticated request, because nothing attaches an
Authorization header on a browser's behalf the way it attaches a cookie — which
is the entire premise of CSRF. The test is *what authenticated this request*,
not whether a header is present: skipping on mere presence would let a page that
can add a header switch the protection off. `authenticate()` prefers the cookie
for the same reason, so a request carrying both is cookie-authenticated and
still checked.

Tokens die with their account. Disabling a user revokes their tokens as well as
their sessions — more urgently, in fact, since a session ends within hours on
its own whereas a token in someone's pipeline keeps working until its expiry
with nothing on screen to suggest it.

The token's **name stays out of the event journal**. It is free text the owner
wrote, the journal is the one place erasure cannot reach (ADR 0010), and the
payload allowlist refused it — correctly. The name lives on the row, where
redaction can reach it; only the opaque id goes into the chain.

### Not addressed here

**Scopes.** A token today can do anything its owner can that policy permits
without a device-bound credential, which is a broad grant for something living
in a CI variable. The right answer is a scope list on the token surfaced to
Cedar as context, so policy can require one per action. It is not here because a
half-designed scope model is worse than an explicit "this is the owner, minus
the dangerous things" — but the broad grant is real and should not be forgotten.

**Service accounts.** A token is a *human* automating their own access. A
non-human identity is a different thing and the plan already says it should use
`private_key_jwt` with no shared secret. Blurring the two would make a token the
way around the passkey requirement, which is precisely what the device-bound
rule exists to prevent.
