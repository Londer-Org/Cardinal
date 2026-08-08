# Roadmap

Cardinal is **pre-1.0 and not production ready**. There is no stable API, no
upgrade path between versions, and no security audit. This page says what works,
what does not, and what is deliberately not being built.

Two documents already linked here and neither existed until the documentation
site was first built with broken links treated as errors — which is a small
example of the thing this project keeps finding: a claim nobody could follow is
indistinguishable from a claim that is false.

## Phases

Each phase is independently useful. Stopping after Phase 3 leaves a working
single sign-on provider; stopping after Phase 4 leaves that plus Linux host
access.

| Phase | Deliverable | State |
|---|---|---|
| **0 — Foundations** | `cardinal user create` works; temporal membership is queryable | ✅ |
| **1 — Authentication** | You sign in with a passkey, in a real browser | ✅ |
| **2 — Authorization** | An internal app behind Traefik, protected by Cardinal, with a decision explorer | ✅ |
| **3 — OpenID Connect** | A real application points at Cardinal instead of Keycloak | ✅ |
| **4 — Linux host access** | One host runs with no other directory agent | ✅ |
| **5 — Consolidation** | Usable by somebody who is not the author | in progress |

Phase 5 is SCIM, SSF/CAEP events, an audit explorer with point-in-time queries,
a documentation site, hardening and coverage work, and a stated API-stability
policy for 1.0.

## Known gaps

Honest, and referenced from [the threat model](docs/threat-model.md) and
[the integration guide](docs/integration.md).

| Gap | Consequence | Phase |
|---|---|---|
| No security audit | Nobody outside this project has looked at the cryptography, the session handling or the policy evaluation | before 1.0 |
| No token scopes | An access token can do anything its owner can that policy permits without a device-bound credential — a broad grant for something living in a CI variable ([ADR 0018](docs/adr/0018-access-tokens-are-a-weaker-credential.md)) | 5 |
| PostgreSQL 19 is not GA | The temporal model uses `FOR PORTION OF`, which is 19-only, and beta behaviour has already changed once between betas | blocks production |
| No SCIM | Provisioning into downstream applications is manual | 5 |
| No SSF/CAEP | A revocation here does not propagate to applications; they learn at their next token refresh | 5 |
| Single writer | PostgreSQL streaming replication with manual promotion. Deliberate — split-brain in an identity store means two primaries accepting credential writes | revisit with a team on call |
| No automated failover | Same reason. A misconfigured automatic failover is more dangerous than none | revisit |

## Deliberately not building

These are decisions, not omissions, and each is recorded with its reasoning.

- **LDAP wire protocol.** A clean break. Integration is OIDC, SCIM, gRPC and
  `forwardAuth`. The reasoning is in
  [ADR 0002](docs/adr/0002-identity-is-an-immutable-uuid.md): LDAP's original
  sin is that the DN *is* the identity, and every other complaint about it is
  downstream of that.
- **SAML.** Cut rather than deferred ([ADR 0007](docs/adr/0007-no-saml.md)).
  OIDC covers everything modern, and SAML's XML signature handling is a
  well-known source of authentication bypasses.
- **Kerberos KDC and integrated DNS.** The two highest-risk workstreams;
  writing a KDC alone would have dwarfed the project.
- **RADIUS.** PostgreSQL removed its own RADIUS support as unfixably insecure
  over UDP. RADSEC only, if ever.
- **Passwords.** Not discouraged — there is no password column. What replaces
  the emergency one is
  [ADR 0014](docs/adr/0014-break-glass-removed.md): break-glass was removed
  because the CLI already performed the same recovery, and two credentials of
  last resort are worse than one.
- **Multi-master replication.** PostgreSQL streaming replication with a single
  writer is simpler and more correct.

## If you need something today

[Kanidm](https://github.com/kanidm/kanidm) is the closest thing to Cardinal and
is further along. If you need a working identity platform now, deploy that. The
[comparison](docs/comparison.md) says where Cardinal differs and where it is the
wrong choice.
