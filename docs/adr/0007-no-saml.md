# ADR 0007: Cardinal will not implement SAML

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

Keycloak, which Cardinal replaces, is a SAML 2.0 identity provider. Enterprise
SaaS integrations have historically required SAML, and any "Keycloak
replacement" is expected to offer it.

A competent Go library exists ([`zitadel/saml`](https://github.com/zitadel/saml)),
so this is not a question of feasibility.

## Decision

**Cardinal does not implement SAML. This is cut, not deferred** — there is no
"bonus phase" where it appears.

Reasons, in order of weight:

1. **SAML's XML signature handling is a notorious source of authentication
   bypass vulnerabilities.** XML canonicalisation, XML Signature wrapping, and
   entity expansion have produced a long, recurring history of full auth-bypass
   CVEs across essentially every implementation, including mature ones. For a
   security product maintained by one person, *not shipping an XML signature
   verifier is a security win*, not a feature gap.
2. **OIDC covers everything modern.** Nothing in the target environment requires
   SAML.
3. **Attack surface is permanent; convenience is temporary.** Every SAML
   endpoint would need maintenance and monitoring for the life of the project.

## Consequences

**Good.** A materially smaller and safer attack surface. No XML parsing on any
authentication path. Less code, fewer dependencies, less to audit.

**Costs.** Any SaaS application that speaks only SAML cannot integrate with
Cardinal directly. If that need ever arises, the right answer is a **separate,
isolated SAML-to-OIDC bridge** — so that XML parsing lives in its own process
with its own blast radius, and Cardinal's core is never exposed to it.

**One design constraint remains, and it is not about SAML.** The layer resolving
a subject into attributes stays **protocol-agnostic**: `Subject → attributes +
transitive groups + policy results`, in its own package, importing no protocol
types.

That isn't speculative generality for a SAML that isn't coming. It has four real
consumers today:

| Consumer | Consumes the projection as |
|---|---|
| OIDC provider | ID-token / userinfo claims |
| Traefik `forwardAuth` | `X-Auth-Request-*` headers |
| SCIM server | User/Group resource attributes |
| SSH certificate issuance | Certificate principals and extensions |

Four serializers over one resolution path. A CI check asserts this package
imports no protocol packages.
