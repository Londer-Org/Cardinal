---
name: red-team
description: Attack Cardinal on purpose — forge identity headers, escalate scopes, cross tenants, inject, overflow, confuse types — across the API, agent, OIDC, SCIM, SSF and the console. Use before a release, after touching an authorization or disclosure path, or when reviewing a new endpoint.
---

# Attack it deliberately

Cardinal decides who reaches what. A defect here is not a bug report, it is
somebody else's incident. Run this against the stack (`make e2e-up` or the lab),
not against reasoning about the code.

Every finding needs three things: the request that did it, the response that
proves it, and a regression test. A finding without a reproduction is a
suspicion.

## Rules

- Attack your own stack only. The lab and the example stack, never a deployment
  you do not own.
- Prefer the real client — `curl`, the CLI, a browser — over a unit test. The
  interesting failures live between components.
- A refusal is not a pass until you have checked *why*. A 403 for the wrong
  reason becomes a 200 when that reason changes.

## Identity and headers (the trust boundary)

The forwardAuth model has applications trust `X-Auth-Request-*` because only the
proxy can reach them. That is a network property; nothing in the code enforces
it.

- Send `X-Auth-Request-Preferred-Username: attacker` and
  `X-Auth-Request-Groups: directory-admins` to a protected route. The proxy must
  overwrite them.
- Send the same to a route *without* forwardAuth. Without a strip middleware the
  application believes you — this was live in the lab.
- Send a header the proxy forwards but Cardinal does not always set. Anything in
  `authResponseHeaders` that Cardinal omits passes through from the client.

## Authorization

- **Cross-tenant by identifier.** Acknowledge another receiver's SSF events by
  quoting its `jti`; read another person's tokens, sessions or credentials by id.
- **Scope escalation.** Use a token scoped `identity` against `/api/policy`,
  SCIM, `/ssf/poll`, forwardAuth. Each must refuse and name the missing scope.
- **Device-bound bypass.** Attempt an administrative action with an access
  token. Policy refuses it because tokens are never device-bound — confirm the
  refusal is that forbid and not an accident of routing.
- **Disclosure.** Does an application receive groups that have nothing to do
  with it? Does narrowing a projection change what Cedar *decides*? It must not.
- **Unregistered resource.** A hostname nothing claims must be refused before
  policy, not classified into a default.

## Injection and malformed input

- Parameterised queries throughout — grep for string concatenation into SQL.
  `fmt.Sprintf` near a query is the thing to look for.
- Entity names reach sudoers, SSH principals and Cedar identifiers. Try `0`,
  `root`, `..`, a newline, a quote, a very long name, and names differing only
  by case or Unicode normalisation.
- JSON bodies: wrong types (`"maxEvents": "many"`), nulls, deep nesting, a 10MB
  body, duplicate keys, an array where an object belongs.
- Path and query: traversal in any slug that reaches the filesystem, an
  identifier that is not a UUID, a UUID that exists but belongs to somebody
  else.

## Protocol surfaces

- **OIDC**: `redirect_uri` unregistered, wildcarded, with a fragment or a
  different port; missing PKCE; replayed code; `state`/`nonce` omitted; an ID
  token verified against the wrong issuer or audience.
- **SSF**: cleartext endpoint; a poll credential used against another stream;
  `setErrs` naming events belonging to somebody else.
- **SCIM**: PATCH a system group; provision into `directory-admins`.
- **ACME/agent**: enrol twice, replay an enrolment token, request a certificate
  for a host you do not own.
- **SSRF**: anywhere Cardinal is given a URL it will fetch or post to — the SSF
  push endpoint above all. Try `127.0.0.1`, `169.254.169.254`, and a redirect to
  either.

## The console

- Every mutation needs `X-Cardinal-CSRF`; try without, with a stale one, and
  cross-origin.
- Audit anything rendered with `dangerouslySetInnerHTML`.
- The zod boundary: send a response shape the client does not expect and check
  it fails at the parse rather than three components later.
- Long values, RTL overrides and emoji in display names, group names, reasons.
- Rate limits on enrolment, recovery and login. Confirm the limiter counts what
  you think it counts.

## Report

Rank by what an attacker gets, not by how clever the input was. For each: the
reproduction, the evidence, the fix, and the test that fails without the fix.
Then run [sabotage-tests](../sabotage-tests/SKILL.md) against that test.
