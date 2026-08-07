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

## One-time setup

Two things, both once, both checked by `make e2e-check` before anything starts.

```sh
sudo apt install mkcert libnss3-tools   # macOS: brew install mkcert
mkcert -install                         # a local CA in your trust store
make hosts                              # prints the /etc/hosts line to add
```

**Why a real domain and a real certificate**, since a demo asking for both
deserves a reason:

Passkeys need a secure context. The only plain-http origins browsers consider
trustworthy are `localhost`, `127.0.0.1` and `*.localhost` — and those are
exactly the names that cannot carry a parent-domain cookie, because a `Domain`
attribute that is a public suffix gets discarded and `localhost` is one. A
parent-domain cookie is what makes signing in at `id.` also count at `app.`,
which is the whole forwardAuth demo.

So: passkeys or single sign-on, pick one — unless the stack is served over
HTTPS on a domain the browser will scope a cookie to. That is the only
arrangement where both work, and it is also what production looks like.

This stack ran on `http://*.localhost` with `cookie_domain = "localhost"` for
months. Every browser silently threw the session cookie away, so nobody could
sign in, while the Go end-to-end suite passed — `net/http/cookiejar` accepts
what browsers refuse. `mkcert -uninstall` removes the CA again when you are
done.

Two applications, protected two different ways:

- <https://app.cardinal.test:8443> — knows nothing about authentication; Traefik asks
  Cardinal on its behalf via `forwardAuth`.
- <https://client.cardinal.test:8443> — speaks OpenID Connect itself, and needs no
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

## How the suite signs in

There is no non-interactive way to authenticate: the only credential Cardinal
accepts is a passkey, and tapping one needs a human. So the end-to-end tests
seed a session row directly, containing exactly what a passkey sign-in produces.

This used to be done with a committed break-glass key. Removing break-glass
([ADR 0014](../docs/adr/0014-break-glass-removed.md)) took that away, and
seeding is the more honest replacement — it skips the same ceremony without a
production mechanism existing partly to make tests convenient.

## Two things the protected app demonstrates

**It performs no authentication.** It trusts `X-Auth-Request-*` completely,
which is safe only because it is unreachable except through Traefik. That is a
network property, and no amount of application code can enforce it. This is why
`compose.yml` deliberately does not publish its port.

**Traefik forwards only the headers named in `authResponseHeaders`.** Anything
Cardinal sets that is not listed is silently dropped — far and away the most
common cause of "it worked with curl but not through the proxy".

`open.cardinal.test:8443` routes to the same application with the middleware
removed, so you can see it fail closed. Never do that in a real deployment.

## Trying the consent screen

The relying party is registered as a first-party application, so it signs you in
without asking anything — which is the default and the point of
[ADR 0011](../docs/adr/0011-consent-is-per-client-and-off-by-default.md). To see
the other path, register a client that must ask:

```sh
docker compose -f examples/compose.yml exec cardinal \
  cardinal app register partner-app \
    -display 'A third-party integration' \
    -redirect 'https://client.cardinal.test:8443/callback' \
    -dev-mode -consent \
    -scopes 'openid,profile,email' \
    -config /etc/cardinal/cardinal.toml
```

Start an authorization against that client id and Cardinal stops to ask before
releasing anything. Agree once and it stops asking; the agreement then appears
under **Access → Connected applications**, where withdrawing it also revokes the
application's tokens.

`cardinal app list` shows the flag in a `CONSENT` column, so which applications
ask is visible without reading the database.
