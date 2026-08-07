# Roadmap

Living document. Updated as work lands, not as it's planned.

**Legend:** ✅ done · 🔨 in progress · ⬜ not started · 🚧 blocked · ❓ needs a decision

**Current position:** Phase 3 nearly complete. A browser can now sign in to a
third-party application through Cardinal end to end: authorization code flow
with PKCE, resumed across sign-in, with `state` and `nonce` preserved, and
consent asked for where the application is not first-party, and applications
managed from the admin UI. Remaining in Phase 3: the OpenID Foundation
conformance suite.

Phases 0–2 complete. Phase 1 still owes TOTP, recovery-email delivery, and
dual-control recovery. See [docs/first-run.md](docs/first-run.md) to try it.

**Not yet verified by a human:** a real passkey in a real browser. Everything up
to that boundary is tested; WebAuthn's failure modes are browser-side and need
someone with a device.

---

## Phase 0 — Foundations

**Goal:** `cardinal user create` works, and temporal membership is queryable.

| | Item | Notes |
|---|---|---|
| ✅ | Repo, Apache-2.0 licence, SECURITY.md, .gitignore | |
| ✅ | PostgreSQL 19 beta 2 dev environment | Port **5433** (5432 is taken by another project) |
| ✅ | **PG19 feature verification** | All temporal features confirmed working — see below |
| ✅ | Foundation migration | entities, schema registry, temporal membership, event log, sessions |
| ✅ | ADRs 0001–0010 | [docs/adr](docs/adr/) |
| ✅ | Entity engine (Go) | UUIDv7 identity, typed entities, soft delete |
| ✅ | Temporal membership + recursive-CTE resolver | Cycle-safe; expired links break inheritance |
| ✅ | Hash-chained event log (Go) | Length-prefixed encoding; tampering + deletion both detected |
| ✅ | testcontainers integration harness | 14 integration tests, green under `-race` |
| ✅ | `cardinal` admin CLI | **Phase 0 deliverable — working end to end** |
| ✅ | CI pipeline | lint · vet · gofumpt · govulncheck · tidy check · PG matrix |
| ⬜ | Schema registry enforcement (Go) | Table exists; validation logic not yet wired |
| ✅ | Backup + restore verification | `make restore-drill` — verified tampering is caught in a restored dump |
| ➖ | ~~Break-glass design~~ | [ADR 0009](docs/adr/0009-recovery-and-break-glass.md), removed by [ADR 0014](docs/adr/0014-break-glass-removed.md). Recovery is `cardinal invite <admin>` on the host |
| ✅ | **GDPR erasure vs. append-only chain** | [ADR 0010](docs/adr/0010-personal-data-and-erasure.md) — enforced in code, `cardinal redact` works |
| ✅ | Threat model document | [docs/threat-model.md](docs/threat-model.md) — includes an honest known-gaps list |

### Verified against `postgres:19beta2` (2026-08-05)

The core thesis was tested before any Go was written:

- `WITHOUT OVERLAPS` rejects overlapping grants, accepts adjacent ones ✅
- `DELETE FOR PORTION OF` truncates a range on early revocation, **preserving
  who granted it and why** ✅
- `UPDATE FOR PORTION OF` splits one row into three ✅
- Point-in-time queries correct across a revocation boundary ✅
- Append-only rules hold — `UPDATE 0`, `DELETE 0` ✅
- `uuidv7()`, `ON CONFLICT DO SELECT`, `base64url`, `SKIP LOCKED`,
  `LISTEN`/`NOTIFY`, `CREATE PROPERTY GRAPH` all confirmed ✅

**Gotchas found the hard way** (recorded in [ADR 0001](docs/adr/0001-temporal-access-model.md)):

1. **`btree_gist` is mandatory.** `WITHOUT OVERLAPS` compiles to a GiST
   exclusion constraint and `uuid` has no default GiST opclass in core.
2. **`REPACK (CONCURRENTLY) tbl`** — parenthesised. `REPACK CONCURRENTLY tbl` is
   a syntax error.
3. **PG18+ Docker images** mount at `/var/lib/postgresql`, *not* `.../data`.
4. **No partial index can express "currently valid"** — `now()` is STABLE, not
   IMMUTABLE. Use a composite GiST over `(scalar, range)`.

---

## Phase 1 — Authentication

**Goal:** log in with a passkey, in a real browser.

| | Item |
|---|---|
| ✅ | WebAuthn — registration and login ceremonies, discoverable (usernameless) login, clone detection |
| ➖ | ~~Break-glass~~ — **removed** (ADR 0014). Invitations took over the bootstrap role; the CLI already performed the same recovery unauthenticated, so it was a second internet-facing credential of last resort. Its "works with the database down" promise was never true — challenges were persisted in the database |
| ⬜ | TOTP (migration aid + second factor; never for admin actions) |
| ⬜ | Recovery email delivery (config + circularity guard done; SMTP sending pending) |
| ✅ | Config loading — no unsafe defaults; enforces the recovery/IdP circularity rule |
| ✅ | Session management + CSRF — hashed tokens, read-time revocation, double-submit CSRF, security headers |
| ✅ | **Session lifetime is configurable** — `[sessions] idle`/`absolute`, defaulting to 8 hours and 7 days. Validated against each other, since a cap inside the idle window makes the idle setting silently do nothing |
| ✅ | **Sliding sessions with an absolute cap** — the idle window moves while a session is used, so nobody is signed out mid-task because of when they started; the cap is never extended, so everyone re-authenticates eventually and a stolen token cannot be kept alive by using it |
| ✅ | **Step-up asks in place** — a dialog wherever the user is, rather than the section emptying and leaving them to find the passkeys page |
| ✅ | **Step-up re-authentication** — prove the key again without a new session. The freshness rule had been in the policy since Phase 0 with no way to satisfy it on demand: `auth_at` was set once, at sign-in, so administration expired five minutes later mid-task and only a full sign-out restored it |
| ✅ | Recovery codes (Argon2id, single-use) and ≥2 passkeys enforced |
| ✅ | **Dual-control admin recovery** (ADR 0015) — two distinct administrators, neither the subject, to restore an account that can already sign in. Fixed a real escalation: issuing invitations sat with `user-admins`, so one could mint a link for a `directory-admins` account and become them |
| ✅ | **First-run setup** — `cardinal init <login>` publishes the policy, creates the administrator and prints an enrollment link. Refuses on a directory that already has administrators, and is deliberately not part of `migrate`: every upgrade would otherwise carry code that can mint one |
| ✅ | **Enrollment invitations** (ADR 0013) — single-use, 24h, revocable, hashed at rest, no session granted; the enrollment screen is also where a user sets their own name and email. **Recovery is `cardinal invite <admin>` on the host** (ADR 0014) |
| ✅ | **Self-service profile** — display name and email, with the recovery/IdP circularity guard applied here too. The login stays administrative |
| ✅ | Rate limiting — fixed-window, fails closed, trusted-proxy aware |
| ✅ | Frontend — React 19, Vite 7, Tailwind v4, **shadcn/ui (vendored)**, TanStack Query, zod, strict TS with `any` banned |
| ✅ | `embed.FS` release build — `make release` yields one self-contained binary |
| ✅ | Container image — distroless, nonroot, static, 23 MB |

> **Resolved.** [ADR 0009](docs/adr/0009-recovery-and-break-glass.md) settles
> recovery before authentication is built. Recovery email was considered and
> **rejected**: Cardinal is meant to be the SSO provider for email, so
> "Cardinal is down" would imply "recovery channel unreachable".

---

## Phase 2 — Authorization + Traefik

**Goal:** an internal app sits behind Traefik, protected by Cardinal. *The
first genuinely useful milestone.*

| | Item |
|---|---|
| ✅ | `cedar-go` integration — named policies, fail-closed, evaluation errors surfaced |
| ✅ | Policy storage + versioning — publish/activate separated, document frozen by trigger, rollback is one command |
| ✅ | **Claims projection** — protocol-agnostic, import constraint enforced by test |
| ✅ | `forwardAuth` endpoint — identity headers, login redirect with open-redirect guard |
| ✅ | Decision logging — every decision names the policy that made it |
| ✅ | **Decision explorer** — decisions name the rule that decided; clicking it shows the rule text |
| ✅ | **End-to-end stack with real Traefik** — 13 tests, `make e2e-up && make e2e` |

### The end-to-end stack

Framed as a **test that happens to be demoable**, not a demo. A demo nobody runs
rots into a liability; a stack CI exercises stays honest.

It has now found five defects no unit test could, listed here because the
pattern is the point — every one compiled and passed the unit suite:

- **Sessions need a parent-domain cookie.** A cookie set at `id.example.com` is
  never sent to `app.example.com`, so forwardAuth SSO simply did not work. Added
  `server.cookie_domain`, with its cost documented — such a cookie reaches every
  subdomain.
- **There was no way to apply the schema in a container.** Migrations were a
  Makefile `psql` loop, which works on a laptop and not at all for a deployment.
  Added `cardinal migrate`, embedding the migrations in the binary.
- **Registration accepted redirect URIs the provider then refused.** Cardinal
  treated any `*.localhost` host as loopback; RFC 8252 means literal
  `127.0.0.1`/`::1`, and the provider enforces the narrow reading — so a client
  could be registered that could never complete a login.
- **Clients were granted scopes they were not registered for.** The library
  treats standard OIDC scopes as always permissible, so a client registered for
  `openid profile` could request `offline_access` and receive a refresh token
  nobody approved. Cardinal now narrows scopes at the authorization request.
- **Refresh-token rotation had never actually run.** It worked, but nothing had
  exercised it; the test that does also caught that `oauth2.TokenSource` only
  refreshes an *expired* token, which had made rotation look broken.

```
examples/
  protected-app/   ~60 lines reading X-Auth-Request-* headers and rendering them.
                   Deliberately boring: this is what people copy when integrating,
                   and anything clever in it gets cargo-culted.
  traefik/         compose + dynamic config wiring forwardAuth
test/e2e/          drives it: sign in, hit a protected route, assert
```

It closes a gap the current tests cannot: forwardAuth has only ever been
exercised with hand-crafted `X-Forwarded-*` headers. Real Traefik decides which
headers it sends, how it treats a 204 against a 200, and forwards only the
response headers named in `authResponseHeaders` — a whole class of integration
bug that is invisible today.

In-repo rather than a separate repository, deliberately: if the header contract
changes, an in-repo example breaks in CI immediately, whereas a separate one
drifts silently until someone follows stale documentation.

Grows with the phases — an OIDC relying party in Phase 3, a container acting as
an enrolled host in Phase 4 — so the same stack keeps proving the newest thing
works.

---

## Phase 3 — OIDC provider

**Goal:** point a real application at Cardinal instead of Keycloak.

| | Item |
|---|---|
| ✅ | **Applications are directory entities** — a client can be a group member, a policy subject, and appear in the audit trail like a person |
| ✅ | Client registration — opaque client_id, Argon2id secrets, PKCE required for every client type |
| ✅ | Redirect-URI validation — wildcards, fragments and plain http refused; loopback permitted per RFC 8252 |
| ✅ | **Recovery/IdP circularity guard now enforced** at client registration (ADR 0009) |
| ✅ | Authorization-code storage — single-use enforced in one statement, codes hashed at rest |
| ✅ | Token storage — refresh tokens hashed and revocable; sign-out kills issued tokens |
| ✅ | Signing keys — RSA, encrypted at rest with a config-held key, rotation with a verification grace period |
| ✅ | `op.Storage` adapter — compile-time assertion, claims from the shared projection |
| ✅ | Authorization code flow with PKCE — verified end to end; wrong verifier and replayed code both refused |
| ✅ | Discovery, JWKS, token, userinfo, introspection, revocation |
| ✅ | Frontend resumes an OIDC flow after sign-in — browser login works end to end |
| ✅ | **An OIDC relying party in the e2e stack** — coreos/go-oidc, an independent client library; 5 tests |
| ✅ | **Consent** — per-client and off by default (ADR 0011); enforced on every completion path, withdrawable, and withdrawal revokes the client's tokens |
| ✅ | **Client management UI** — register, inspect and retire relying parties from the admin UI; secret shown once |
| ✅ | **Directory admin UI** — people and groups from the browser: who exists, who can sign in, and membership granted or revoked **with an expiry**. The temporal model was the flagship of the data model and reachable only from the CLI, so in practice every grant made through the product was unbounded |
| ✅ | **The admin API is Cedar-gated** (ADR 0012) — `directory-admins` is a built-in group, membership is an ordinary temporal grant, and every refusal names the deciding policy |
| ✅ | **System groups vs application groups** — membership of a system group confers authority inside Cardinal, so granting one needs `AdministerDirectory`. Closed a third escalation: a `user-admin` could grant themselves `directory-admins`. Other groups may belong to an application, so `aura-users` sits beside `aura` |
| ✅ | **Administration is tiered** — `user-admins` (people, groups, invitations) and `security-admins` (OIDC applications) alongside `directory-admins`, which stays the superset. Nobody is migrated, so narrowing is deliberate. Step-up covers every admin action, not just the broad one |
| ✅ | **Who may use which application** — an `AccessApplication` decision enforced on every path that can complete an authorization, logged, and named in the refusal. Ships permissive, because Cedar is default-deny and a version that locked everyone out of everything on upgrade is not a safe default |
| ✅ | **A navigable console** — sidebar, breadcrumbs and server-paginated tables. The URL, the sidebar and the breadcrumb trail are read from one navigation model rather than three that agree until someone adds a route; they already disagreed, with the sidebar filing People under Directory while the breadcrumb said Admin. Tables fill the viewport and scroll their rows under a sticky header, so the search box and the pagination stay reachable in a long list |
| ✅ | **A home page** — what needs your attention first, where everything is second. Gated on entitlement *and* freshness, which is not the same test: `canManageUsers` reports what a fresh key would allow, deliberately, so sections do not vanish when authentication goes stale — so gating on it alone meant a stale administrator was met by a security-key prompt for the crime of loading a page. Console reads are filtered out of its decision list; every table this UI draws is itself an authorized action, and they buried everything that meant anything |
| ✅ | **A palette taken from the mark** — contrast computed rather than eyeballed, which changed a decision: the dark-mode primary takes dark text at 6.4:1 because white on it falls to 2.9:1. Fixed a defect hiding in plain sight — the sidebar palette was never defined, and an undefined custom property compiles to nothing rather than to something wrong, so the console had no hover and no highlight on the page you were on |
| ✅ | **Account enrollment for a new user** — done in Phase 1 via invitations (ADR 0013) |
| ✅ | **OpenID Foundation conformance suite** — run locally against a TLS-fronted instance. The **config certification plan passes outright** (34 checks, no failures). Of the basic plan's 35 modules: 19 pass, 6 warn, 5 are skipped as not offered, 4 need a human to upload a screenshot of a page the suite already confirmed was shown, and 1 needs a per-variant client block the suite's config takes rather than anything Cardinal does — that capability (`client_secret_post`) was verified by hand instead. **No module fails on Cardinal's behaviour.** Found and fixed two real defects: a discovery document describing the library rather than this deployment ([ADR 0016](docs/adr/0016-cardinal-serves-its-own-discovery-document.md)), and `prompt`/`max_age` accepted but never honoured ([ADR 0017](docs/adr/0017-prompt-and-max-age-are-honoured.md)). The suite's own browser automation cannot sign in here — it fills a username and password, and Cardinal has neither — so the browser half is driven by a virtual WebAuthn authenticator |

---

## Phase 3.5 — Machine and API access

**Goal:** a script reaches an internal application without routing around
Cardinal.

| | Item |
|---|---|
| ✅ | **Personal access tokens** ([ADR 0018](docs/adr/0018-access-tokens-are-a-weaker-credential.md)) — `Authorization: Bearer` accepted wherever a session cookie is, so the proxy needs no rule sending API traffic around the auth check and the application still reads only `X-Auth-Request-*`. A token is never device-bound, so `admin-requires-fresh-device-bound-auth` and `ssh-requires-device-bound` refuse it every administrative action and every SSH certificate — **with no new policy written**. Verified by sabotage: flipping that one field turns the refusals into 200s |
| ✅ | **Applications get a stable group identifier** — the `groups` claim and `X-Auth-Request-Groups` carried only names, so every application downstream keyed its permission logic on a mutable string. That is LDAP's DN problem ([ADR 0002](docs/adr/0002-identity-is-an-immutable-uuid.md)) reappearing one layer out, solved inside Cardinal and reintroduced at the boundary. `group_ids` and `X-Auth-Request-Group-Ids` now travel alongside, additively. Fixed *before* a rename operation exists, which is the only cheap moment to fix it |
| ⬜ | **Token scopes** — a token can currently do anything its owner can that does not need a device-bound credential, which is broad for something in a CI variable. Wanted: a scope list surfaced to Cedar as context |
| ⬜ | **Service accounts** — non-human identities with `private_key_jwt`. Deliberately separate from tokens, or a token becomes the way around the passkey requirement |
| ❓ | **In-app authorization** ([ADR 0019](docs/adr/0019-in-app-authorization.md), *proposed*) — bringing an application's own permissions under Cedar, evaluated locally by `cardinal-agent` rather than by a call per action, with thin client packages over a local socket so adding a language is small. Optional by construction: an application that ignores it behaves exactly as today. **Not started, and question 5 in the ADR should be answered on a real application first** — roles carried in the token may cover enough of the need to make the rest unnecessary |

---

## Phase 4 — Linux host access

**Goal:** one host runs with no SSSD. *Largest and riskiest phase.*

| | Item |
|---|---|
| ✅ | **SSH certificate authority** — Ed25519 keys sealed under their own encryption key, published before they sign and rotated with a grace period, because `TrustedUserCAKeys` holds several at once ([ADR 0021](docs/adr/0021-ssh-ca-key-custody.md)). Issuance records who got what, for which host, under which key; the certificate itself is not stored, since it lasts minutes and a copy would be somewhere to steal one from. Verified against `ssh-keygen` rather than only against the Go library |
| ✅ | **Host access is decided by policy** — a host is a directory entity, so "which machines" is group membership and the local account travels in the context. `POST /api/ssh/certificate` resolves the host, asks Cedar, logs the decision, and issues only what the rule permitted. Refusals carry the explanation, not just rule names: "no policy grants this" and "explicitly forbidden by X" need different actions and look identical otherwise |
| ⬜ | Host enrollment — a machine proving *which* host it is, needed by the agent and by ACME |
| ⬜ | `cardinal-agent` — serves POSIX identity over varlink (ADR 0020), renders sudoers, caches for offline |
| ✅ | **systemd-userdbd validated** ([ADR 0020](docs/adr/0020-posix-identity-over-varlink.md)) — the interface is three varlink methods over NUL-terminated JSON, implementable in ~200 lines of Go with no dependency and no C. Proven end to end: `getent passwd`, lookup by uid, group lookup and `id` all resolve a user that exists only in a Go process. **The NSS module fallback is dropped** |
| ⬜ | sudoers rendering (`visudo -c` before atomic install) |
| ⬜ | Offline cache |
| ⬜ | **Shadow mode** — the critical migration feature |
| ⬜ | FreeIPA importer |
| ⬜ | `.deb`/`.rpm` via goreleaser |
| ⬜ | **X.509 certificates over ACME** ([ADR 0023](docs/adr/0023-x509-certificates-via-acme.md)) — after the SSH CA, since it reuses the same host identity, `crypto.Signer` custody, policy decision and audit trail. Closes one of the three reasons FreeIPA survives a migration; DNS and Windows remain out of scope |
| ✅ | **CA key custody decided** ([ADR 0021](docs/adr/0021-ssh-ca-key-custody.md)) — the signing path takes a `crypto.Signer`, so the key material is configuration rather than a permanent choice. Default is envelope encryption in the database under its *own* key, PKCS#11 supported for anyone with an HSM, TPM sealing rejected because it would bind issuance to one host and break the standby failover plan. Rotation designed in from the start, since `TrustedUserCAKeys` holds several keys and the agent manages that file |

---

## Phase 5 — Consolidation

**Goal:** usable by someone who isn't Arthur.

| | Item |
|---|---|
| ⬜ | SCIM server + client |
| ⬜ | SSF/CAEP event stream |
| ⬜ | Full admin console, audit explorer |
| ⬜ | Docs site |
| ⬜ | 1.0 API stability commitment |

---

## Explicitly not building

Recorded so these don't get relitigated:

- **SAML** — [ADR 0007](docs/adr/0007-no-saml.md). XML signature verification is
  an auth-bypass minefield.
- **LDAP server** — [ADR 0002](docs/adr/0002-identity-is-an-immutable-uuid.md).
  Reading LDAP as a *client* during migration is fine.
- **Kerberos KDC and DNS** — neither is a decision followed by a short-lived
  credential ([ADR 0022](docs/adr/0022-cardinal-issues-short-lived-credentials.md)).
  A ticket-granting service is continuous dependence on the KDC, which is the
  property SSH certificates exist to avoid; DNS is a name lookup. Run DNS
  wherever it already runs.
- ~~**Internal CA** — integrate `step-ca`~~ **reversed**
  ([ADR 0023](docs/adr/0023-x509-certificates-via-acme.md)). The original reason
  was "not used in the target environment", which is a statement about one
  deployment — and the internal CA turns out to be among the most commonly cited
  reasons FreeIPA survives a migration. Cardinal issues X.509 over ACME, reusing
  the host identity, policy, key custody and audit it needs anyway for SSH.
- **RADIUS** — PostgreSQL 19 removed its own RADIUS support as unfixably
  insecure over UDP. Take the hint.
- **Redis / any second datastore** —
  [ADR 0004](docs/adr/0004-postgresql-is-the-only-datastore.md). If ever
  revisited: Valkey (BSD), not Redis (AGPLv3).
- **Multi-master replication** — single writer, streaming replication.

## Known security gaps

Tracked openly, from [the threat model](docs/threat-model.md):

| Gap | Consequence | Phase |
|---|---|---|
| No external anchor for the hash chain | A superuser could rewrite it wholesale and pass validation | Post-1.0 |
| No decision cache yet, so nothing to invalidate | When the agent caches offline, a cached decision could outlive a revocation | Phase 4 |
| SSH CA key custody is only as strong as the host | Decided ([ADR 0021](docs/adr/0021-ssh-ca-key-custody.md)): by default an attacker holding both the database and the configuration file holds the CA. Mitigated by 5–15 minute certificates, logged issuance and automated rotation; PKCS#11 available for deployments wanting more | Ongoing |
| No account lockout | Nothing guessable is unlimited today; reopens with TOTP | With TOTP |
| The `sensitive` flag is declared and unread | The registry lets an operator mark an attribute sensitive; nothing encrypts or redacts on it | Phase 1 |
| An application is two Cedar resources depending on the door | `forwardAuth` decides against `Application::"<host>"` and OIDC against `Application::"<registered name>"`, because nothing links a registered application to the hostnames it answers on. An application using both integration styles needs a policy under each name, and granting one does not grant the other | Phase 5 |
| No `acr` claim, and no assurance levels defined | A client sending `acr_values` gets no `acr` back. Cardinal has the raw material — a device-bound passkey is a stronger assertion than a synced one — but has not defined what its levels *mean*, and inventing one would assert an assurance it has not specified. Same reasoning as refusing to claim `email_verified` | Phase 5 |
| Replayed authorization codes do not revoke tokens already issued | OIDC Core says the server MUST deny the replay (it does) and SHOULD revoke tokens issued from that code (it does not). `oidc_tokens` has no link back to the authorization request, so the fix is a column plus plumbing through token creation | Phase 5 |
| No external security review | Self-assessment only | Before production |

## Standing risks

| Risk | Mitigation |
|---|---|
| PG19 not GA until ~Sept/Oct 2026 | Pinned to `19beta2`; no production release before GA, then full re-test |
| Locking ourselves out | ≥2 passkeys enforced; recovery is `cardinal invite <admin>` on the host, which needs database access rather than a second internet-facing credential (ADR 0014). Rehearse it, do not assume it |
| Kanidm may already solve this | Deploy it and confirm — one day of evaluation against months of build |
| Scope is large for part-time | Every phase is independently useful; stopping after Phase 3 still leaves a working SSO IdP |
