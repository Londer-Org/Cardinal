# ADR 0017: `prompt` and `max_age` are honoured, not accepted

- **Status:** Accepted
- **Date:** 2026-08-06
- **Found by:** the OpenID Foundation conformance suite
  (`oidcc-prompt-login`, `oidcc-prompt-none-not-logged-in`, `oidcc-max-age-1`).

## Context

An authorization request can constrain *how* the user is authenticated, not
only *who* they are:

| Parameter | Meaning |
|---|---|
| `prompt=login` | authenticate again, whatever session exists |
| `prompt=none` | show the user nothing; if that makes completion impossible, return `login_required` |
| `max_age=N` | the authentication must be no older than N seconds |

Cardinal accepted all three and stored none of them. Every request completed
from whatever session happened to exist, and `prompt=none` was satisfied by
rendering a sign-in page — the one thing the parameter forbids.

That is not a missing feature. It is a false answer. A client sends
`prompt=login` before something that matters — a payment, a privilege change, a
destructive action — and asks the identity provider to witness a fresh ceremony.
Answering "yes, they authenticated" from a session established that morning
tells it something untrue about a decision it is making on that basis.

## Decision

The parameters are stored with the authorization request (migration 0015) and
evaluated at completion time rather than at arrival, because the session may be
re-authenticated in between — which is the entire point of asking.

- `prompt=login`, or a `max_age` the session no longer satisfies, sends the user
  to a step-up. Cardinal already had the machinery: proving the key again
  without minting a new session.
- `prompt=none` on a request that would need any interaction redirects to the
  client with `error=login_required`, carrying `state` so the client can match
  it to the request it made.

Enforced on **both** the redirect path and `/api/oidc/resume`. Resume is
reachable directly, so a rule applied only where the browser is sent is a rule
that anything skipping the SPA can skip — the same bypass consent had, and it
is worth stating that this class of mistake has now happened twice.

## Consequences

`max_age` is clamped when stored. It arrives as an unbounded unsigned integer
and is compared as a `time.Duration`, which counts nanoseconds in an `int64` and
overflows past roughly 292 years; a wrapped negative would silently invert the
meaning, turning "any age is acceptable" into "always re-authenticate". Sixty-
eight years is beyond any real policy and well clear of the boundary.

The re-authentication screen names the application that asked. A security-key
prompt appearing for no visible reason during an ordinary sign-in is one people
learn to click through, which is the opposite of what the parameter is for.

Two of the three conformance tests now pass outright. `oidcc-prompt-login` and
`oidcc-max-age-1` end at `REVIEW` — the suite confirms *"the server must ask the
user to login for a second time"* and Cardinal does, but the step is completed
by a human uploading a screenshot and cannot be automated. `oidcc-max-age-10000`
passing matters as much as `max-age-1`: it proves the bound is a comparison
rather than a blanket re-authentication, which would have satisfied one test by
breaking the other.
