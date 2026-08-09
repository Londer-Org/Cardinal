# Changelog

What changed, and whether it should change what you do. Newest first.

Written by hand rather than generated from commit subjects. A generated list
cannot say "this one is a security fix, upgrade" — and for an identity system
that distinction is the only reason to read a changelog at all. **Security**
entries are what to read if you read nothing else.

Cardinal is pre-1.0: there is no supported upgrade path between versions, and
the API can change in any release. Migrations are expand-only, so the previous
build keeps working against a newer schema and rolling back is redeploying the
old image.

## 0.3.1 — 2026-08-09

Documentation and metadata only. No code, no schema change, and no behaviour
difference from 0.3.0 — so there is nothing to do on upgrade beyond taking the
newer image if you want the corrected licence text in it.

It exists because the things it corrects are read from the released artefact
rather than from the repository's main branch, and 0.3.0 shipped with the
copyright naming an individual and no changelog at all.

### Changed

- The copyright is held by **Londer** rather than by an individual. Apache-2.0
  grants rights on behalf of whoever owns the work, so naming a person where
  the owner is a company makes the grant ambiguous to a careful reader.
- The README states plainly that Cardinal is **not a Londer product**: not
  sold, not offered as a service, not covered by any support agreement, and
  provided without warranty. It also says that development may stop at any
  point, because "published by a company and looks active" is the inference
  people otherwise make.
- This changelog exists, covering 0.1.0 onward.
- `.goreleaser.yaml` no longer filters commit subjects by Conventional Commits
  prefixes, which this repository's convention forbids — so the filters
  excluded nothing while making the generated notes look filtered.

## 0.3.0 — 2026-08-09

An audit release. Nothing new was built for users; four security bugs were
found and fixed, and four checks were added so that the shape of bug fails the
build rather than waiting for the next audit.

### Security

- **Signing out left its access tokens alive.** Ending a session did not revoke
  the OIDC access tokens issued from it, so they stayed valid for their full
  lifetime after "sign out". Every path that closes a session now revokes them
  in the same transaction. **If you have been running this, treat tokens issued
  before upgrading as outstanding.**
- **The token signing key could not be rotated.** The rotation existed but had
  no caller, so the key that can forge a token for every registered application
  had no way to be replaced. `cardinal oidc key rotate` does it, with a grace
  period derived from the longest token lifetime in use.
- **An erased account kept a working passkey.** Erasure under GDPR Article 17
  cleared personal data and deleted sessions, but left the credentials and
  never set `disabled_at` — and the login path gates on `disabled_at` alone.
  Erasure now deletes credentials and disables the account, and the login path
  refuses a redacted entity. **Re-run erasure for anyone erased on an earlier
  version**; the earlier erasure did not remove their ability to sign in.
- **An entity could be named `0`.** `getent passwd 0` returns root, and shadow
  mode runs exactly that with an entity's name, so the numbers offered for
  adoption would have been root's. All-digit names are refused.

### Added

- `cardinal oidc key list` and `cardinal oidc key rotate`.
- `cardinal decisions` — the decision log from a terminal, naming the rule that
  decided. The question gets asked during an incident, when the console may be
  one of the things that is broken.
- `cardinal config` — the effective configuration and where each value came
  from. Settings that are accepted and read by nothing are always listed.
- `cardinal history <group> <member> -at <RFC3339>` — was this member in this
  group at that instant. The query existed since the first migration and had no
  way to be invoked.

### Changed

- Erasure now records what it removes in `entities.redacted_at`'s comment, and
  [ADR 0010](docs/adr/0010-personal-data-and-erasure.md) lists credentials and
  POSIX home directories as personal data, which it had not.
- Documentation that had stopped being true: the X.509 authority was described
  as "not built yet" a release after it shipped, and the roadmap claimed every
  audit finding had been dealt with.

### Internal

- `internal/arch` fails the build when an exported method has no caller outside
  its own tests, when a handler is never routed, when a console view is never
  imported, and when the shipped policy set names a group no migration creates.
  Each was verified by introducing the fault it looks for.
- `docs/schema.md` has a freshness check. It had gone three migrations stale.
- The end-to-end suite can run twice within fifteen minutes again.
- First tests for `internal/directory`, `internal/directory/temporal`,
  `internal/directory/posix`, `internal/host/machine`, `internal/ca/x509ca` and
  `internal/server/auth`.

## 0.2.0 — 2026-08-09

### Security

- **forwardAuth decided nothing.** `audienceFor` classified every hostname as
  `"staff"`, so the rule permitting staff applications permitted every
  authenticated principal to reach every protected URL. Web access is now
  decided from the application the hostname resolves to.
- **Five group identifiers no migration created.** Three of eleven shipped
  policy rules — SSH, sudo, web access — named groups that did not exist, and a
  Cedar rule naming a non-existent group never matches. Because Cedar is
  default-deny, they refused everyone and looked like policy working.
- Decisions that no policy produced were dropped rather than logged, so the
  decision log was missing exactly the refusals hardest to explain.

### Added

- `cardinal policy rule` composes rules instead of requiring Cedar by hand, and
  `cardinal policy test -dsn` reports rules naming groups or applications that
  do not exist.
- The default policy set ships inside the binary, so a first run is not
  default-deny by accident.
- The console lists applications rather than OpenID Connect clients, so an
  application behind the proxy is visible and retirable.

### Changed

- Every configuration setting is read by something, or is gone.
  `recovery.email_enabled` was removed rather than implemented — ADR 0009 rules
  out email as a recovery channel, so the flag could only ever have lied.
- `database.max_conns` and `conn_max_lifetime` reach pgx, which they did not.
- The documentation site left this repository for
  [cardinal-website](https://github.com/Londer-Org/cardinal-website).

## 0.1.0 — 2026-08-08

First release. Phases 0 through 4: the directory core with immutable UUID
identity and temporal membership, passkey authentication with recovery codes
and dual-control recovery, Cedar authorization behind Traefik `forwardAuth`
with a decision explorer, an OpenID Connect provider, and Linux host access —
`cardinal-agent`, POSIX identity over systemd's userdb, sudoers rendering, SSH
certificates and X.509 over ACME.

Container images at `londerbe/cardinal`, plus `.deb`, `.rpm` and tarballs for
Linux and macOS.
