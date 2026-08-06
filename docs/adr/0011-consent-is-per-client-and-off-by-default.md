# ADR 0011: Consent is per-client and off by default

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

OpenID Connect providers show a consent screen: *"Application X wants to see
your name and email — Allow / Cancel."* Google and GitHub show one for every
third-party application, and it is the mechanism most people picture when they
hear "OAuth".

Cardinal is an internal identity provider. Most applications behind it are run
by the same organisation that runs Cardinal, for employees who have no
meaningful choice about using them. Asking an employee whether the company
intranet may see their name is not a decision — it is a dialog between them and
the button that makes it go away.

That matters beyond ergonomics. A prompt shown on every sign-in trains people to
click through without reading, and the click is then recorded as agreement. The
system ends up holding evidence of a decision nobody made, which is worse than
holding no evidence at all — under GDPR in particular, consent that was not
freely given and informed is not consent, but a stored record of it looks
exactly like one.

Keycloak takes the same position: consent is a per-client switch, default off.

## Decision

**Consent is a per-client flag, `require_consent`, defaulting to false.** It is
set at registration with `cardinal app register -consent`.

Four properties follow, and each is load-bearing:

1. **Asked once, not every time.** Standing consent is recorded per
   (subject, client). A later authorization requesting the same scopes or fewer
   completes silently. An application that widens its request is asked again —
   that is the moment where the answer might genuinely differ, and so the only
   moment a prompt carries information.

2. **Enforced on every path that can complete an authorization**, not in the
   UI. There are three: the single-sign-on hand-off at `/oidc/login`, the SPA's
   resume endpoint, and the consent decision itself. All three call one
   function. The first implementation checked only the resume endpoint, which
   left single sign-on — an already-signed-in user, the common case — completing
   silently; an end-to-end test caught it before the code was committed.

3. **Withdrawable, and withdrawal revokes the client's tokens.** Consent that
   cannot be taken back is a click, not a decision. Withdrawal that leaves live
   access and refresh tokens behind is meaningless for the rest of their
   lifetime: the application keeps working, which is exactly what the user just
   asked it not to do.

4. **Re-granting after withdrawal replaces the scope list rather than merging
   into it.** Merging into a *live* agreement is right — agreeing to something
   new must not silently drop something the application still relies on. Merging
   into a *withdrawn* one would resurrect scopes the user took back and never saw
   the second time, making withdrawal a pause. A store test caught this; the
   first implementation had it wrong.

Scope descriptions are rendered server-side, so the consent record and the
screen that produced it cannot drift apart. Unrecognised scopes are shown as
their raw name rather than hidden — hiding one would mean consenting to
something invisible.

## Consequences

**Good.** Internal applications sign users in without ceremony, so the prompt
retains meaning when it does appear. Third-party integrations get a real
consent flow, a standing record, and a place to withdraw it. The default is the
one that does not manufacture false evidence of agreement.

**Costs.** An operator who wants Google-style consent everywhere must set the
flag per client; there is no global switch. That is deliberate — a global
"always ask" would recreate exactly the click-through problem this decision
exists to avoid.

**Not covered.** Per-scope consent (agreeing to some scopes and refusing
others) is not implemented. The authorization either proceeds with what was
requested or does not proceed. Partial grants need the client to handle a
narrower grant than it asked for, and most do not; offering the choice would
mostly produce applications that break in ways the user cannot diagnose.
