# Examples

A working Cardinal deployment: PostgreSQL, Cardinal, Traefik, and an
application that knows nothing about authentication.

The end-to-end test suite drives this same stack, so it stays honest. A demo
nobody runs rots into a liability; a stack CI exercises keeps working.

```sh
make e2e-up        # build and start everything
make e2e           # run the end-to-end tests against it
make e2e-down      # stop and remove
```

Two applications, protected two different ways:

- <http://app.localhost:8100> — knows nothing about authentication; Traefik asks
  Cardinal on its behalf via `forwardAuth`.
- <http://client.localhost:8100> — speaks OpenID Connect itself, and needs no
  proxy in front of it.

Both send you to Cardinal to sign in. The first lands on a page showing the
identity headers that arrived; the second shows the claims from an ID token it
verified against Cardinal's published JWKS.

## What is here

| Path | Purpose |
|---|---|
| `protected-app/` | ~120 lines that read `X-Auth-Request-*` and render them. Deliberately boring — this is what people copy. |
| `oidc-client/` | An OpenID Connect relying party using **coreos/go-oidc** — deliberately a different library from the provider's own, so satisfying it is evidence rather than self-agreement. |
| `traefik/dynamic.yml` | The `forwardAuth` middleware. The comments are the interesting part. |
| `compose.yml` | The whole stack |
| `cardinal.e2e.toml` | Configuration, annotated |

## ⚠️ `e2e-break-glass.key`

**A break-glass private key, committed to git on purpose.**

It exists so this stack is reproducible without a setup ritual. It grants
emergency access to any account *in this throwaway stack* and nowhere else,
because the matching public key appears only in `cardinal.e2e.toml`.

Never reuse it. Generate your own with `cardinal break-glass generate` and keep
the private half offline — see [ADR 0009](../docs/adr/0009-recovery-and-break-glass.md).

## Two things the protected app demonstrates

**It performs no authentication.** It trusts `X-Auth-Request-*` completely,
which is safe only because it is unreachable except through Traefik. That is a
network property, and no amount of application code can enforce it. This is why
`compose.yml` deliberately does not publish its port.

**Traefik forwards only the headers named in `authResponseHeaders`.** Anything
Cardinal sets that is not listed is silently dropped — far and away the most
common cause of "it worked with curl but not through the proxy".

`open.localhost:8100` routes to the same application with the middleware
removed, so you can see it fail closed. Never do that in a real deployment.
