# Cardinal

A directory and identity platform built on Go and PostgreSQL, where **identity is
immutable**, **access is time-bounded by default**, and **every authorization
decision can explain itself**.

> **Status: pre-1.0, under active development. Not production ready.**
> There is no stable API, no upgrade path between versions, and no security
> audit yet. Please don't deploy this to anything you care about.

## Why this exists

LDAP's original sin is that the DN *is* the identity. Rename a user or move them
between organisational units and every reference to them breaks. Directory
schemas are rigid, the ACL languages are vendor-specific and untestable, and
credentials cross the wire in plaintext on a simple bind.

Cardinal takes the opposite position on each of those:

| | LDAP / FreeIPA / Keycloak | Cardinal |
|---|---|---|
| Identity | The DN — changes when you rename or move | An immutable UUIDv7; names are ordinary attributes |
| Access grants | Permanent until someone remembers to remove them | Carry a validity period the database enforces |
| "Who had access in March?" | Log archaeology, if you kept the logs | `WHERE valid_period @> '2026-03-01'` |
| Authorization | LDAP ACLs + HBAC + role mappers — three languages, none testable | One Cedar policy set, versioned in git and unit-tested |
| "Why was I denied?" | Unanswerable | Every decision records the policy that made it |
| Credentials | Passwords, plaintext on simple bind | Passkeys only. There is no password column |
| Host login | Directory lookup at every login | Short-lived SSH certificates; hosts never call the directory |

## Design

Three ideas carry most of the weight:

**Identity is a UUIDv7 that never changes and is never reused.** Names, emails
and group placement are mutable attributes hanging off it. Renaming a person is
an `UPDATE`, not a migration.

**Access grants are temporal.** Group membership carries a `tstzrange`, so a
time-boxed grant is an `INSERT` with a bounded range and expiry is enforced by
the query rather than a cron job that might not run. Early revocation is
`DELETE ... FOR PORTION OF`, which truncates the range while preserving the
historical fact that the grant existed and why.

**One policy engine decides everything.** [Cedar](https://www.cedarpolicy.com/)
governs web access via Traefik `forwardAuth`, SSH certificate issuance, sudo
rules, and Cardinal's own admin API — so the directory's access control is the
same reviewable, testable policy set as everything else.

## Requirements

- **PostgreSQL 19+** — the temporal model uses `FOR PORTION OF`, which is 19-only
- Go 1.25+
- Docker (for the development database and integration tests)

Postgres is the only datastore. There is no Redis, no message broker, and no
second database.

## Development

```sh
docker compose up -d          # PostgreSQL 19 on port 5433
make migrate                  # apply migrations
make test                     # unit + integration tests
```

Integration tests run against a real PostgreSQL via testcontainers. They are not
optional and cannot be mocked: `WITHOUT OVERLAPS` and `FOR PORTION OF` are
database semantics, and the temporal model is only correct if it is tested
against a real engine.

## Prior art

[**Kanidm**](https://github.com/kanidm/kanidm) is the closest thing to Cardinal
and is further along — Rust, passkey-first, self-hosted, with OAuth2/OIDC and
Unix host integration. If you need a working identity platform today, deploy
Kanidm rather than this. Cardinal differs in using PostgreSQL as its substrate
(for SQL, transactions, streaming replication and PITR), in making time-bounded
access a data-model primitive, and in using Cedar as a single decision point
across web, SSH, sudo and admin surfaces.

Also worth knowing: [Zitadel](https://github.com/zitadel/zitadel) (Go,
event-sourced), [Authentik](https://goauthentik.io/) (Python), and
[Keycloak](https://www.keycloak.org/) (Java).

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not
open a public issue for a security problem.

## License

Apache-2.0. See [LICENSE](LICENSE).
