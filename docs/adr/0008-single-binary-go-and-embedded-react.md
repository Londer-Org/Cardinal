# ADR 0008: One Go binary with an embedded React UI

- **Status:** Accepted, with one part corrected in place — see the note under
  *API-first*, which describes what was built rather than what was decided.
- **Date:** 2026-08-05

## Context

Cardinal replaces three systems (FreeIPA, Keycloak, an auth proxy) with one. If
deploying it means running a backend, a separate frontend server, a reverse
proxy and a database, that promise is hollow.

## Decision

**Go for the backend. React 19 for the admin UI, compiled at build time and
embedded into the binary via `embed.FS`.** One binary, one database.

Go over Rust: the ecosystem for this exact domain is markedly richer —
`zitadel/oidc` (OpenID Foundation *certified*), `go-webauthn/webauthn`,
`cedar-policy/cedar-go`, `pgx`. Rust would mean writing more from scratch for a
project with part-time hours. Both are memory-safe; Go's GC is irrelevant at an
internal IdP's scale.

Three roles from one codebase (the Consul/Nomad model):
`cardinal server` · `cardinal-agent` · `cardinal` (CLI).

### API-first, without exception

The REST/gRPC admin API is the **only** mutation path. The CLI and web UI are
both clients of it, with no privileged back door.

This is a security decision as much as an architectural one: it makes the API
the single reviewable authorization boundary (governed by Cedar, per ADR 0005),
rather than having three surfaces that each need their own checks.

> **This is not what was built, and the difference is load-bearing.** The
> console is an API client and every request it makes is evaluated by Cedar.
> The CLI is not: it takes `-dsn` (or `CARDINAL_DSN`), connects to PostgreSQL
> and issues statements. No policy is consulted on that path, because there is
> no authenticated principal on it — there is a database credential.
>
> That turned out to be necessary rather than accidental. Enrolling the first
> passkey needs a session and getting a session needs a passkey;
> [ADR 0014](0014-break-glass-removed.md) removed the offline break-glass key
> precisely *because* `cardinal invite <admin>` against the database already
> was the last resort, making a second one strictly worse. A CLI that could
> only speak to a running, policy-governed API could not have played that role,
> and something else would have had to.
>
> So the honest statement of the architecture is: **the API is the only
> mutation path reachable over the network, and the database credential is
> administrative access by another door.** Shell access to the host is
> administrative access to the directory. That is a supportable position — it
> is roughly where `psql` sits relative to any application — but it is not
> "no privileged back door", and documentation that claimed otherwise was
> telling operators something false about their threat model.
>
> Two consequences worth naming rather than leaving to be discovered:
>
> - CLI actions are not policy-governed, so a policy set that refuses somebody
>   administration does not refuse them anything on that path.
> - CLI actions do not record a truthful actor. Entity creation records none,
>   and a grant currently records the member as its own granter. The chain is
>   intact; the attribution on that path is wrong, and it is filed as a defect
>   rather than defended.

- OpenAPI is **generated from the Go handlers** and checked in — it produces
  both the public API docs and the frontend's TypeScript types.
- **zod schemas are generated from the OpenAPI spec, never hand-written.**
  Hand-maintained validation drifts from the server, and in an identity system
  that drift is a security bug.

### TypeScript strictness is enforced, not aspirational

`any` is **banned outright**. `unknown` is permitted in exactly one place: as
the input to a zod `.parse()` at a trust boundary. Once parsed, everything
downstream is fully typed. **Untyped data never travels more than one line from
where it entered.**

`tsconfig`: `strict` plus `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`, `noImplicitOverride`, `noImplicitReturns`,
`noFallthroughCasesInSwitch`, `verbatimModuleSyntax`.

ESLint **as errors**: `no-explicit-any`, the full `no-unsafe-*` family,
`no-floating-promises`, `switch-exhaustiveness-check`. CI fails on any of them.

The reasoning: a security product whose frontend quietly casts around its own
type system is worse than one with no types at all — it *looks* safe.

## Alternatives considered

**Rust everywhere.** Stronger compile-time guarantees, no GC, and Kanidm proves
it works for this domain. Rejected on ecosystem and velocity for part-time work.

**Hybrid Go + Rust** (Rust for crypto/parsing hot paths). Rejected: doubles CI,
build, and debugging surface for a benefit that doesn't exist at this scale,
especially now that no LDAP BER parser is needed (ADR 0002).

**Separate frontend deployment.** Standard for SaaS. Rejected: it makes the
deployment story two things instead of one, and adds a CORS and CSRF surface
that embedding avoids entirely.

**Server-rendered Go templates.** Simplest, no build step. Rejected: the audit
explorer and decision explorer are genuinely interactive, table-heavy views that
would fight against templates.

## Consequences

**Good.** `docker run` one image, point it at Postgres, done. No CORS. No
version skew between frontend and backend — they ship as one artifact. The CLI
cannot drift from the UI because both go through the same API.

**Costs.** The release build needs Node as well as Go, so CI has two toolchains.
Frontend and backend version together, so a CSS fix requires a full release —
acceptable for an internal tool, and the price of the single-artifact property.

**Distribution has one deliberate exception.** `cardinal-agent` ships as
`.deb`/`.rpm` with a systemd unit rather than a container: it writes
`/etc/sudoers.d/`, serves a varlink socket `nss-systemd` must reach, and must
survive a reboot before any container runtime starts. Containerising it would
require host PID/network namespaces and extensive bind mounts — all the
operational cost of a container with none of the isolation.
