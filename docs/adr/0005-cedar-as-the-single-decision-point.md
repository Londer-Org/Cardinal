# ADR 0005: Cedar is the single authorization decision point

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

The environment Cardinal replaces runs three incompatible authorization
languages:

- **LDAP ACLs** (`olcAccess` / 389-ds `aci`) — vendor-specific, positional,
  arcane, and impossible to unit-test
- **FreeIPA HBAC and sudo rules** — a separate model again, managed through a
  different tool
- **Keycloak role mappers and scopes** — a third model, stored in a database and
  edited through a web UI, so changes are invisible to code review

None can be diffed, tested in CI, or reasoned about together. Worst of all,
**none can explain a denial.** "Why can't I access this?" is answered by a
human reading three different configurations.

## Decision

**One Cedar policy set governs every authorization decision**, embedded via
[`cedar-policy/cedar-go`](https://github.com/cedar-policy/cedar-go) — the
official Go implementation, pure Go with no FFI, CNCF sandbox.

Four decision points, one engine:

| Decision point | Replaces | Question |
|---|---|---|
| Traefik `forwardAuth` | oauth2-proxy + Keycloak mappers | Can they reach this URL? |
| SSH certificate issuance | FreeIPA HBAC | Can they log into this host, as whom? |
| sudoers rendering | FreeIPA sudo rules | What can they run as root there? |
| Admin API | LDAP ACLs | Can they modify this directory object? |

That last row matters most: **Cardinal's own access control is the same engine
as everything else.** There is no separate, privileged, untestable ACL language
guarding the directory itself.

Policies live in **git**, are validated against a declared Cedar schema in CI,
are unit-tested with explicit allow/deny cases, and are loaded into PostgreSQL
with a version. Cedar entities are projected from the directory: the principal
plus their transitive groups, roles, and attributes.

**Every decision is logged with the policy ID that made it.** Explainability is
a product feature, not a debugging aid — the Phase 2 decision explorer UI is
built directly on this.

## Alternatives considered

**Groups and roles only.** Simplest, ships fastest. Rejected: it hits a ceiling
immediately at requirements like *"contractors may reach staging during business
hours from a managed device."* Cardinal would then grow an ad-hoc condition
language — badly, and without Cedar's analyzability.

**Build a Zanzibar/ReBAC engine.** Maximum power and the strongest theoretical
differentiator. Rejected as a serious project in its own right that would
compete with the directory for the entire budget.

**OpenFGA or SpiceDB as a separate service.** Battle-tested ReBAC. Rejected: a
second stateful system to operate, directly contradicting ADR 0004 and the
"one system" goal.

**Open Policy Agent / Rego.** Mature and widely deployed. Rejected in favour of
Cedar for its formally-specified semantics, its validator (policies are checked
against a schema rather than failing at runtime), and its far gentler learning
curve — Rego's evaluation model is a recurring source of subtle authorization
bugs.

## Consequences

**Good.** One language to learn, review, and test. Policies are diffable in pull
requests. Denials are explainable. Authorization logic is testable without
standing up the whole system.

**Costs.** Cedar is a real dependency on the critical path of every request —
its correctness is Cardinal's correctness. Projecting directory state into Cedar
entities on every decision needs caching (invalidated per ADR 0004), and that
cache is security-sensitive: a stale entity projection is an authorization bug.

**Policy evaluation must fail closed.** If policy cannot be loaded or evaluated,
the answer is deny. The one exception is the host agent's offline cache
(ADR 0006), which serves last-known-good policy by design — an explicit,
documented trade to keep SSH working during a directory outage.
