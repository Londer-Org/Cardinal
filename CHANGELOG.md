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

## Unreleased

### Added

- **A terminal can be signed in from a device that is not the one running it.**
  The existing flow has the console redirect approval to a loopback listener on
  the machine running the CLI, which does not need a browser to exist — it needs
  the browser and the CLI to share a loopback interface. That is false the
  moment the terminal is on a server you are SSH'd into: the approval goes to
  `127.0.0.1` on whatever machine the browser runs on, and the terminal waits
  for something that cannot arrive.

  Now the terminal asks first, prints a short code, and polls. Somebody with a
  browser — a laptop, a phone — opens `/cli-login`, enters the code, sees where
  the request came from, and approves it.

  The CLI picks a flow and says which: loopback where the browser can reach this
  machine, the code otherwise.

  **What the new flow gives up, stated because it matters.** Loopback approval
  is delivered to the machine that asked, so nobody can talk you into approving
  *their* terminal. This one can be phished, which is the known weakness of the
  shape. Against it: a five-minute window, approval that still requires a
  device-bound session, and a screen that shows the address the request came
  from **as the server saw it** — never a name the terminal chose, because
  "approve the code from web-01" is exactly the sentence an attacker would like
  to arrange.

### Fixed

- **The journal no longer invents who made a change from the command line.**
  `cardinal grant engineers alice` recorded alice as her own granter, because
  `granted_by` is `NOT NULL` and her identifier was to hand. No query could tell
  that from a real self-grant, so an auditor asking who put alice in engineers
  was told "alice" and had no way to know the answer was made up. Creating an
  entity recorded no actor at all.

  Both now name `direct-database`, a system service account created by migration
  0035 that means exactly what it says: the change came through the command line
  against the database, where there is no authenticated person. It has no
  passkeys and cannot be signed into.

  Attribution nobody can check is worse than none, because it reads as evidence.
  Changes made through the API still record the person who made them.

### Changed

- **The published image no longer contains the administrative CLI.** It used to
  be the entrypoint, and the configuration it reads carries the connection
  string, so a shell in a running container was an unauthenticated
  administrator in one command with nothing to discover.

  The server is now `cardinal-server`, holding `serve`, `migrate`, `init` and
  `config` — what has to reach the database before anybody can sign in.
  `cardinal` is the administrative CLI and is distributed separately.

  What this buys, stated exactly: whoever holds the database credential still
  owns the directory, because psql exists and nothing here can prevent that. It
  raises the cost from "type the command you already know" to "know the
  credential and bring a tool", and it stops the running server from being the
  tool.

  **On upgrade:** anywhere you run `cardinal migrate`, `cardinal init`,
  `cardinal serve` or `cardinal config`, run `cardinal-server` instead. The
  container's entrypoint changed with it, so a deployment that passes `serve`
  or `migrate` as the command keeps working unchanged.

### Fixed

- **Cardinal would have stopped accepting every change on 1 January 2028.**
  The `events` and `decisions` tables are partitioned by time, their partitions
  were created by hand covering 2026 and 2027, and nothing created more. Every
  mutation writes its journal entry in the same transaction as the change it
  records, so a row that routed to no partition failed — and took the grant,
  the credential or the session with it. Not a degradation: no writes at all.

  Yearly partitions now run to the end of 2035, and each table has a `DEFAULT`
  partition behind them so running out slows things down instead of stopping
  them. The server warns at startup when a table has under two years of
  partitions left, and warns differently once rows are landing in the backstop,
  which is the point at which adding the proper partition means moving them
  first.

  Nothing to do on upgrade beyond running `cardinal migrate`.

### Added

- **An application can be told only about the groups that concern it.** Until
  now every application behind forwardAuth, and every relying party asking for
  the `groups` scope, received every group the person belonged to. An internal
  wiki learned that somebody was in `hr-investigations`, and the payload grew
  with the size of the directory rather than with the needs of the application.

  ```sh
  cardinal group create aura-admins -app aura   # a group that belongs to an app
  cardinal app groups mode aura owned           # tell it about those, and no more
  cardinal app groups allow aura engineers      # plus one it does not own
  cardinal app groups show aura                 # what it is told about, and why
  ```

  The same is on the application's page in the console. A system group is never
  projected: membership of `directory-admins` is authority inside Cardinal, not
  a role in somebody else's application.

  **This changes what an application is told, never what Cardinal decides.**
  Policy is evaluated against the full membership either way, so narrowing a
  projection can neither refuse nor admit anybody
  ([ADR 0032](docs/adr/0032-an-application-sees-the-groups-it-owns.md)).

  Nothing to do on upgrade: every application starts in `all`, which is the
  behaviour it had. Rolling back to a build without this **widens** the claim
  again, which is a disclosure change rather than a failure — `docs/upgrading.md`
  says so.

## 0.4.0 — 2026-08-10

Security events stop being a thing you configure blind and hope about. The
console shows every receiver and whether delivery is working, and a receiver
that Cardinal cannot reach — behind NAT, on a laptop, in a CI job — can now
collect its events instead of needing an inbound path opened to it.

Nothing to do on upgrade. The schema change is expand-only as always, existing
streams keep pushing exactly as they did, and no configuration key changed.

### Added

- **A receiver can collect security events instead of being pushed them**
  (RFC 8936). Push asks the receiver to run an HTTPS endpoint Cardinal can
  reach, which is reasonable for a service in the same network and impossible
  for one behind NAT, on a laptop, in a CI job, or anywhere nobody will open an
  inbound path to a security event handler. Those receivers could not be told
  about a revocation at all.

  ```sh
  cardinal ssf stream add aura -delivery poll
  cardinal ssf token aura     # the receiver's own credential, shown once
  ```

  The receiver then `POST`s to `/ssf/poll` with that token as a bearer, and
  acknowledges by the `jti` each event is keyed by. Acknowledging is separate
  from receiving, so a receiver that crashes between the two is handed the same
  events again rather than losing them. The token delivered is byte for byte
  the one push would have sent, and `/.well-known/ssf-configuration` now
  advertises both methods and the polling endpoint.

  The credential is issued to the application rather than to the person who
  configured the stream, carries a new `events` scope, and can read that
  receiver's queued events and nothing else. The console offers the choice when
  adding a receiver and says which method each one uses.

  Stream management over the API is still not implemented — a receiver cannot
  create its own stream — and the configuration document still says so.

- **The console configures Shared Signals streams.** Integrations › Security
  events lists every receiver, what it subscribes to, whether it is delivering
  or paused, and how many events are queued or have exhausted their attempts —
  plus the issuer and JWKS a receiver author always asks for. Adding, pausing
  and removing are there too. It was the last piece of administration that
  existed only as a CLI command, which made the whole subsystem invisible: a
  transmitter nobody watches is one that stops working quietly.

  Behind `ManageApplications` rather than an action of its own, since a stream
  belongs to an application — so no migration and no policy change.

### Internal

- `make verify-rollback` runs published releases against a schema this build
  migrated, and asserts they serve. Rolling back has always been "redeploy the
  old image and nothing else", resting on migrations being expand-only — a rule
  enforced per migration, with the pairing itself only ever checked by reading.
  0.1.0 and 0.2.0 both serve against the current schema. Verified in the other
  direction too: marking a migration breaking makes 0.2.0 refuse to start, and
  the check reports it.

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
  refuses a redacted entity. **If you erased anyone on an earlier version**,
  their passkeys are still stored. They cannot sign in — the login path
  refuses a redacted entity — but a public key is personal data in its own
  right, and re-running `cardinal redact` cannot remove it: erasure renames
  the entity to a tombstone and guards itself on `redacted_at IS NULL`, so
  the old login no longer resolves and the update would match nothing.
  [docs/upgrading.md](docs/upgrading.md) has the query that says whether you
  are affected and the delete that clears it. This entry previously said to
  re-run erasure, which was written without being tried.
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
