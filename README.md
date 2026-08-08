<img src="assets/cardinal-mark.svg" alt="" width="88" align="left" hspace="16" vspace="4">

# Cardinal

A directory and identity platform built on Go and PostgreSQL, where **identity is
immutable**, **access is time-bounded by default**, and **every authorization
decision can explain itself**.

<br clear="left">

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
governs web access via Traefik `forwardAuth`, sign-in to each OIDC application,
SSH certificate issuance, sudo rules, and Cardinal's own admin API — so the
directory's access control is the same reviewable, testable policy set as
everything else. Every decision is logged with the rule that produced it, so
"why was I denied?" has an answer neither FreeIPA nor Keycloak can give.

## Requirements

- **PostgreSQL 19+** — the temporal model uses `FOR PORTION OF`, which is 19-only
- Go 1.25+
- Docker (for the development database and integration tests)

Postgres is the only datastore. There is no Redis, no message broker, and no
second database.

## Development

```sh
make help                     # every target, with a one-line description
docker compose up -d          # PostgreSQL 19 on port 5433
make migrate                  # apply migrations
make test                     # Go unit + integration tests
make ui-check                 # frontend typecheck + lint
```

That is enough for the directory core and the CLI. Everything involving a
browser — the admin console, passkeys, single sign-on — needs the example stack,
which has a **one-time setup** described below.

See **[docs/first-run.md](docs/first-run.md)** for a ten-minute walkthrough.

### The example stack

`examples/` is a complete deployment: PostgreSQL, Cardinal, Traefik, an
application that knows nothing about authentication, and an OIDC relying party
that speaks the protocol itself. The end-to-end suite drives this same stack, so
it does not rot.

It is a fixture, and stays small on purpose. For a full deployment to stand up by
hand, break, and demo — Kubernetes, separate namespaces with the isolation
actually enforced, and a Linux machine joined to it over the network — see
[cardinal-lab](https://github.com/Londer-Org/cardinal-lab).

```sh
sudo apt install mkcert libnss3-tools   # macOS: brew install mkcert
mkcert -install                         # a local CA in your trust store
make hosts                              # prints the /etc/hosts line to add

make e2e-check                          # verifies both of the above
make e2e-up                             # build and start everything
make e2e                                # run the end-to-end tests against it
make e2e-down                           # stop and remove
```

Then <https://id.cardinal.test:8443>.

**Why a real domain and a trusted certificate**, since asking a new contributor
for both deserves a reason. Two requirements pull in opposite directions:

- **Passkeys need a secure context.** The only plain-`http` origins browsers
  treat as trustworthy are `localhost`, `127.0.0.1` and `*.localhost`.
- **Single sign-on needs a parent-domain cookie**, so that signing in at `id.`
  also counts at `app.`. Browsers discard a `Domain` attribute that is a public
  suffix — and `localhost` is one.

Those sets do not overlap. Measured against Chrome rather than reasoned about:

| Origin | `PublicKeyCredential` | Parent-domain cookie |
|---|---|---|
| `http://*.localhost` | ✅ | ❌ discarded |
| `http://*.cardinal.test` | ❌ undefined | ✅ |
| `https://*.cardinal.test`, self-signed | ❌ undefined | ✅ |
| `https://*.cardinal.test`, **trusted** | ✅ | ✅ |

One row works, which is why the stack is HTTPS on a domain your browser will
scope a cookie to. It is also what production looks like, so the example is not
a special mode: it runs without `-dev`, with `Secure` cookies and the full CSP.

`mkcert -uninstall` removes the CA again. `.test` is reserved by IANA for
exactly this, so the hostnames resolve nowhere but your machine.

**If something else already uses port 8443**, move the whole stack:

```sh
make e2e-up CARDINAL_PORT=8643
make e2e     CARDINAL_PORT=8643
```

Everything that dials the stack reads that variable, including the end-to-end
suite — which matters more than it sounds. Two containers can both claim a
published port and the last one to start wins, silently, leaving the other
running and unreachable. `make e2e-up` now fails and names the container holding
the port rather than reporting success against a stack nothing can reach.

> This is worth knowing because Cardinal got it wrong. The stack ran on
> `http://*.localhost` with `cookie_domain = "localhost"` for months: every
> browser silently threw the session cookie away, so nobody could sign in and no
> mutation succeeded — while the entire Go suite passed, because
> `net/http/cookiejar` accepts what browsers refuse. Configuration validation now
> rejects a single-label `cookie_domain` at startup.

### Verification

Unit tests say the code agrees with itself. These say it agrees with something
that was not written here, which is the only kind of check that can catch a
whole design being wrong.

| Command | What actually answers |
|---|---|
| `make test` | Real PostgreSQL via testcontainers. `WITHOUT OVERLAPS` and `FOR PORTION OF` are database semantics and cannot be mocked |
| `make e2e` | Real Traefik decides which headers it forwards, not our reading of the docs |
| `make verify-passkey` | A real browser performs the WebAuthn ceremony and checks the origin against the relying party |
| `make verify-host` | Real `getent`, `id`, `sudo` and a real `ssh` client, in a container |
| `make verify-acme` | [lego](https://github.com/go-acme/lego) — an ACME client nobody here wrote — obtains a certificate |
| `make verify-package` | The real `.deb`, installed on a machine that has never heard of Cardinal |
| `make ui-contrast` | Contrast measured from painted pixels in both themes, not eyeballed |
| `make restore-drill` | A backup restored into a scratch database, with the audit chain re-verified |

Several of these exist because the thing they check was once confidently wrong
in a way no unit test could have seen: `nss-systemd` does not validate a field a
comment claimed it did, a broken `sudoers.d` file does not brick `sudo`, and an
admin console nobody could sign in to passed every test it had.


### A single instance

With no proxy and no second host:

```sh
cp cardinal.example.toml cardinal.toml   # set rp_id and origins
make release                             # UI + binary, one artifact
make migrate
./bin/cardinal init you                  # admin + policy + enrollment link
./bin/cardinal serve -config cardinal.toml -dev
```

Open the link, register a passkey, sign in. There is no password at any point,
and no emergency key to store — recovery is another `cardinal invite` from the
host ([ADR 0014](docs/adr/0014-break-glass-removed.md)).

`-dev` is right *here* and wrong almost everywhere else. It relaxes cookie
`Secure` and the CSP so a single instance can be reached over plain `http` on
`localhost`, which browsers treat as a secure context — so passkeys work without
TLS, and nothing in this arrangement needs a cookie to reach a second hostname
(`cookie_domain` stays empty, which is host-only and correct here). The moment
either of those stops being true, as in the example stack above, it needs real
TLS instead.

`make release` compiles the React UI and embeds it in the binary, so deployment
is one file plus a database. The container image is distroless, static and runs
as nonroot.

### Releasing

One file holds the version. `make bump-patch|bump-minor|bump-major` rewrites it,
regenerates `internal/version`, snapshots the documentation for the version being
left behind, commits, and tags:

```sh
make bump-minor          # 0.1.0 -> 0.2.0, tagged v0.2.0
git push && git push origin v0.2.0
```

Pushing the tag runs the release workflow, which re-runs the whole test suite —
including end-to-end — before publishing anything, then builds the archives,
the `.deb` and `.rpm`, and multi-architecture images to
`londerbe/cardinal:0.2.0` and `:latest`.

The number is a **constant compiled in**, not derived from the tag, and the
release refuses to publish if the two disagree. That is not belt-and-braces:
`.goreleaser.yaml` previously injected `-X main.version` into a symbol no package
declared, and Go discards an `-X` for an unknown symbol silently — so every
release binary would have carried no version at all, indefinitely, because
nothing anywhere asked a binary what it was. `cardinal version`, `/api/health`
and the console's sidebar all report it now.

`make bump` refuses on a dirty tree, and builds the documentation site before
snapshotting it — a snapshot freezes whatever the docs say at that moment, so a
broken link committed there is broken in that version forever.

### Documentation

| Document | What it answers |
|---|---|
| [architecture.md](docs/architecture.md) | How Cardinal is built: packages, request path, the four decision points |
| [integration.md](docs/integration.md) | How other systems talk to it, and where the trust boundaries are |
| [schema.md](docs/schema.md) | Every table, one diagram per domain — generated by `make schema` |
| [certificate-authorities.md](docs/certificate-authorities.md) | How the SSH CA keys are generated, sealed, rotated — and what an attacker gets |
| [comparison.md](docs/comparison.md) | Authelia, Keycloak, FreeIPA, Kanidm — and where Cardinal is the wrong choice |
| [threat-model.md](docs/threat-model.md) | What it defends against, and the gaps it does not |
| [adr/](docs/adr/) | Why things are the way they are |
| [ROADMAP.md](ROADMAP.md) | What works, what does not, and what is deliberately not being built |

The published site is at <https://londer-org.github.io/Cardinal/>, built from
this same `docs/` directory with a version picker — the sources are not copied
into `website/`, because a second copy is the one that goes stale.

The development tools have their own notes: [tools/uishot/](tools/uishot/) covers
the screenshot and contrast checker, including the two bugs that once had it
report "all meet WCAG AA" about a page it had not measured.

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

## Brand

The mark is a compass rose — cardinal directions. Files live in
[`assets/`](assets/): `cardinal-mark.svg` is the icon alone,
`cardinal-logo.svg` includes the wordmark. The admin UI inlines a variant whose
navy is `currentColor`, so it stays legible on a dark background.

## License

Apache-2.0. See [LICENSE](LICENSE).
