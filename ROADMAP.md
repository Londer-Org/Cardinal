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
a presentation and documentation site, hardening and coverage work, and a stated
API-stability policy for 1.0. The audit explorer is built. The site moved out of
this repository: a Docusaurus build on GitHub Pages lived in `website/` and is
gone, replaced by
[cardinal-website](https://github.com/Londer-Org/cardinal-website), which is
presentation as well as documentation and has no reason to be versioned
alongside the server.

Everything that audit found has been dealt with. The last three went in 0.2.0:
the pool settings reach pgx, the two purge routines are called, and
`recovery.email_enabled` was removed rather than implemented — ADR 0009 rules
out email as a recovery channel, so a flag enabling one could only ever have
been a lie.

That paragraph used to end "and the table below is empty of open rows for the
first time", which lasted exactly until the next audit. A second pass before
0.3.0 found four more, three of them the same shape and two of them
security-relevant: signing out did not revoke the access tokens the session had
issued, the key that signs every token could not be rotated at all, an erased
account kept a working passkey, and an entity could be named `0` — which
`getent passwd` reads as a user id, so shadow mode would have compared it
against root. They are in the table below with the rest.

The lesson is not that the audit missed things. It is that "the table is empty"
is a statement about when somebody last looked, and reads as a statement about
the code. Four of the six had a test that passed.

The same audit run against the shipped policy set found a fourth variant of the
pattern, and the worst one so far: not code wired to nothing, but code wired to
a constant. `audienceFor` classified every hostname as `"staff"` and the rule
matching on it therefore permitted everyone everywhere, while three other rules
named groups no migration created and so permitted nobody anywhere. Both
directions of wrong, both invisible, both shipped in 0.1.0. What they have in
common with the earlier three is that every test passed.

## Built but unreachable

The most useful thing an audit of this project finds: something implemented,
tested, and wired to nothing. It passes every test it has, and no user can get
to it. Every row below is now closed — kept rather than deleted, because the
list is also the argument for running the audit again.

| Thing | State | Consequence |
|---|---|---|
| ~~Recovery codes cannot be redeemed~~ | **Fixed.** A code now redeems into a short-lived enrollment at `/recover` | Not a session: credential self-service is behind `requireDeviceBound`, so a session minted from a string on paper could not register the passkey recovery exists to register |
| ~~SSH certificates had no client~~ | **Fixed.** `cardinal ssh [user@]host` borrows the console's passkey through a loopback handoff | Building it found two more of the same shape: a session was not accepted as a bearer token anywhere, and CSRF exempted requests by auth method rather than by how they authenticated |
| ~~Email recovery was configured, not implemented~~ | **Removed.** `recovery.email_enabled` is gone; `email_domains` remains and now gates the circular-recovery check on its own | ADR 0009 rules out email as a recovery channel, so the flag could only ever lie. The check it gated was real and was off for everyone: enrollment and recovery links *are* mailed, so federating the mailbox domain is still refused |
| ~~`database.max_conns`, `conn_max_lifetime`~~ | **Fixed.** `store.OpenWithLimits` applies them, unless the DSN sets `pool_max_conns` itself | An operator tuning a busy deployment silently got pgx's defaults — max(4, NumCPU) connections — while the configuration page showed the number they had chosen |
| ~~`PurgeACMENonces`, `PurgeExpiredOIDCFlows`~~ | **Fixed.** Both run in `backgroundMaintenance`; the nonce window is one constant shared with the consume path | ACME nonces and spent OIDC flows accumulated for the life of a deployment. Never a correctness problem, because every read enforces expiry — which is exactly why nobody noticed |
| ~~`audienceFor` decided nothing~~ | **Fixed.** forwardAuth resolves the hostname to an application and asks about that entity's group membership | It returned `"staff"` for every hostname, so the shipped rule permitting staff applications permitted every authenticated principal to reach every protected URL — a rule that read as though it classified and was a constant |
| ~~Five group identifiers no migration created~~ | **Fixed.** Migration 0027 creates them, and `cardinal policy test -dsn` reports any that go missing | Three of eleven shipped rules — SSH, sudo, web access — could never match. Cedar is default-deny, so they refused everyone and looked like policy working |
| ~~`X-Auth-Request-Group-Ids` never arrived~~ | **Fixed.** Added to `authResponseHeaders` in the example Traefik config | Cardinal set it on every response and Traefik dropped it, so the header applications are told to branch on reached nothing. The test asserting it passed by reading Cardinal's response instead of the application's |
| ~~Access tokens had no scopes~~ | **Fixed.** A token is issued for one or more of identity, applications, profile, decisions, policy — required, never defaulted, and unchangeable afterwards | Policy refused a token administration and SSH certificates (ADR 0018) and nothing else: the decision log, the active policy set, the owner's own profile and every application they could reach were all on the table for a string in a CI variable |
| ~~Agent and server versions were invisible to each other~~ | **Fixed.** Every response carries `X-Cardinal-Version`, the agent sends its own in `User-Agent`, and `cardinal-agent doctor` compares them | A newer agent asking for a route the server lacks got a 404, reported it as a fetch failure and went on serving its cache. Everything on the host kept working, so nothing was reported until the cache was all that was left |
| ~~Agents did not receive CA trust~~ | **Fixed.** The trusted authorities ride the assignment the agent already polls, and it writes `/etc/ssh/cardinal_user_ca.pub` plus the drop-in naming it | `TrustedUserCAKeys` was a manual step, so rotating the authority was a fleet-wide operation nobody performs — in practice the first key was the only key, and the rotation machinery had nothing to converge on |
| ~~The console could not manage forwardAuth-only applications~~ | **Fixed.** The list is application entities, with hostnames and an optional OIDC registration | It was keyed on `client_id`, so an application behind the proxy appeared nowhere — and retiring went through the OIDC client, so one could be created from the console and never retired from it |
| ~~Signing out left the tokens it had issued alive~~ | **Fixed.** Every path that closes a session revokes its OIDC tokens in the same transaction, through an unexported helper reachable no other way | `RevokeTokensForSession` was written, tested, and documented "Called on sign-out". Nothing called it, so signing out closed the session and left every access token minted from it valid for its full lifetime. The test that should have caught it called the helper directly, proving the helper worked while nothing used it |
| ~~The OIDC signing key could not be rotated~~ | **Fixed.** `cardinal oidc key rotate`, with the grace period derived from the longest token lifetime any client is configured with | The SSH and X.509 authorities have had rotate commands since they were built. The key that can forge a token for every application and sign a security event to every receiver had none: the rotation existed, wrapped in a `Provider` method nothing called |
| ~~An erased account kept a working passkey~~ | **Fixed.** Erasure deletes credentials and disables the account; the login path also refuses a redacted entity | Erasure stamped `redacted_at` and never set `disabled_at`, and the WebAuthn path gates on `disabled_at` alone. A public key is personal data in its own right, and [ADR 0010](docs/adr/0010-personal-data-and-erasure.md) had not listed it — the documentation gap *was* the bug |
| ~~An entity could be named `0`~~ | **Fixed.** All-digit names are refused, and the package that validates them has tests for the first time | Measured: `getent passwd 0` prints root, and shadow mode runs exactly that with an entity's name — so the numbers offered for adoption would have been root's. Entity names reach sudoers, SSH principals and Cedar identifiers unescaped, and nothing held the pattern to that |

How they are found: every HTTP route checked for a caller in the console, the
CLI, the agent or the tests; every exported store method checked for a caller
outside its own package; every config field checked for a read.

Four of those checks no longer depend on anybody remembering. `internal/arch`
fails the build when an exported method is called from nowhere but its own
tests, when a handler is declared and never routed, when a console view is never
imported, and when the shipped policy set names a group no migration creates —
the last being the check that would have caught three of the eleven rules that
shipped in 0.1.0. Each was verified by introducing exactly the fault it looks
for, because a guard nobody has seen fail is a guard nobody should trust.

What they cannot catch is the `audienceFor` variant. Code wired to a constant is
reachable, routed and wrong, and no structural check sees it. That one still
needs somebody reading, which is part of the argument for the security audit in
the gaps below.

## Known gaps

Honest, and referenced from [the threat model](docs/threat-model.md) and
[the integration guide](docs/integration.md).

| Gap | Consequence | Phase |
|---|---|---|
| No security audit | Nobody outside this project has looked at the cryptography, the session handling or the policy evaluation | before 1.0 |
| PostgreSQL 19 is not GA | The temporal model uses `FOR PORTION OF`, which is 19-only, and beta behaviour has already changed once between betas | blocks production |
| No SCIM client | Cardinal receives provisioning but does not push it outward; downstream applications are still provisioned by hand | 5 |
| SSF has no poll delivery and no stream management API | Cardinal pushes (RFC 8935) to streams an administrator configures. A receiver that expects to poll, or to create its own stream, cannot — the configuration document says so rather than leaving it to be discovered | 5 |
| SSF streams are configured only from the CLI | The console has no view for them, so deciding which applications hear about a revocation is the one piece of administration that cannot be done from the browser. Unlike the row above this is a missing admin surface rather than a missing protocol half | 5 |
| Single writer | PostgreSQL streaming replication with manual promotion. Deliberate — split-brain in an identity store means two primaries accepting credential writes | revisit with a team on call |
| No automated failover | Same reason. A misconfigured automatic failover is more dangerous than none | revisit |
| No N-1 compatibility test | Nothing runs the previous release against a schema migrated by the current one. The expand-only rule is what makes it safe, and the rule is enforced per migration — the pairing is checked by reading | when there are two releases |
| Windows is client-only | Passkeys, OIDC and OpenSSH work. There is no managed-host path and no domain join: the agent needs systemd's userdb, sudoers and sshd config | not planned |

## Open questions

Not gaps — decisions nobody has made yet.

**Should the console help build policy rules?** What remains of a question that
turned out to be mostly a bug report. Policy was already the most editable thing
here — Cedar in the database, versioned, activated and rolled back from the
console, picked up by every server within ten seconds — and the binary now
carries the default set, so a deployment running the published image is not
missing anything a source checkout has.

What was actually wrong was the starting point, and it was worse than assuming
too much. Three of eleven shipped rules named group identifiers no migration
created, so every rule governing SSH, sudo and web access was inert; Cedar is
default-deny, so they refused everyone and looked like policy working. The
web-access rule matched on a `context.audience` computed by a function that
ignored the hostname and returned `"staff"` for all of them, so it permitted
every authenticated principal to reach every protected URL while reading as
though it discriminated. Both are fixed: the groups are created by migration
0027, the audience is gone in favour of the application's own group membership,
and `cardinal policy test -dsn` plus a warning on every policy load report a
rule naming something the directory does not have.

**Answered.** The console and the CLI now compose the four rules that carry the
weight — who may reach a site, sign in to an application, log into machines, and
become root — from a form. A composed rule becomes text in the same Cedar
document, published as an ordinary version and rolled back like any other, so
nothing here is a second source of truth. Everything the builder does not
recognise passes through byte for byte, comments included.

What stays hand-written is deliberate: the forbids and the administration tiers.
Those are the guardrails the composable rules sit inside, and removing one from
a form is not something a button should do. Publishing an edited policy file
still does, which is the right amount of friction for changing a guardrail.

Worth separating from a related misreading, because they have different answers:
the forwardAuth endpoint is not Traefik-specific. It emits the `X-Auth-Request-*`
convention that nginx `auth_request`, Caddy, Envoy and HAProxy all consume. The
Traefik coupling is in the examples and the lab, not the product.

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
