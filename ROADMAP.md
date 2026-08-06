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
| ✅ | **Break-glass design** | [ADR 0009](docs/adr/0009-recovery-and-break-glass.md) — offline key, public half in config not the DB |
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
| ✅ | Break-glass — keypair, ceremony, challenge/response, HTTP endpoints, UI flow. **Emergencies only** since ADR 0013; enrollment invitations took over the bootstrap path it was being misused for |
| ⬜ | TOTP (migration aid + second factor; never for admin actions) |
| ⬜ | Recovery email delivery (config + circularity guard done; SMTP sending pending) |
| ✅ | Config loading — no unsafe defaults; enforces the recovery/IdP circularity rule |
| ✅ | Session management + CSRF — hashed tokens, read-time revocation, double-submit CSRF, security headers |
| ✅ | Recovery codes (Argon2id, single-use) and ≥2 passkeys enforced |
| ⬜ | Dual-control admin recovery |
| ⬜ | **First-run setup — creating the first administrator deliberately** rather than by break-glassing into an account the CLI made |
| ✅ | **Enrollment invitations** (ADR 0013) — single-use, 24h, revocable, hashed at rest, no session granted; the enrollment screen is also where a user sets their own name and email. Break-glass is demoted to emergencies, which is what ADR 0009 always said it was |
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
| ✅ | **The admin API is Cedar-gated** (ADR 0012) — `directory-admins` is a built-in group, membership is an ordinary temporal grant, and every refusal names the deciding policy |
| ⬜ | **Who may use which application** — an `AccessApplication` decision at `/oidc/authorize`, so a policy can say only `grafana-users` may sign in to Grafana. **Currently any authenticated user can sign in to any registered application.** The claims carry `groups` so an app can enforce its own rules, but Cardinal does not gate it, and that is the first thing anyone coming from Keycloak will look for |
| ✅ | **Account enrollment for a new user** — done in Phase 1 via invitations (ADR 0013) |
| ⬜ | OpenID Foundation conformance suite |

---

## Phase 4 — Linux host access

**Goal:** one host runs with no SSSD. *Largest and riskiest phase.*

| | Item |
|---|---|
| ⬜ | SSH certificate authority |
| ⬜ | Host enrollment |
| ⬜ | `cardinal-agent` |
| ❓ | **systemd-userdbd spike** — validate before committing; fallback is an NSS module |
| ⬜ | sudoers rendering (`visudo -c` before atomic install) |
| ⬜ | Offline cache |
| ⬜ | **Shadow mode** — the critical migration feature |
| ⬜ | FreeIPA importer |
| ⬜ | `.deb`/`.rpm` via goreleaser |
| ❓ | **Key management** — where the CA private key lives |

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
- **Kerberos KDC, DNS, internal CA** — not used in the target environment.
  Integrate `step-ca` if PKI is ever needed.
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
| Session revocation propagation unspecified | A cached decision could outlive a revocation | Blocks Phase 2 |
| SSH CA key management undecided | Highest-stakes remaining decision | Blocks Phase 4 |
| No rate limiting or lockout | Online guessing against TOTP | Phase 1 |
| `sensitive` attribute flag not enforced | The registry declares it; nothing encrypts yet | Phase 1 |
| No external security review | Self-assessment only | Before production |

## Standing risks

| Risk | Mitigation |
|---|---|
| PG19 not GA until ~Sept/Oct 2026 | Pinned to `19beta2`; no production release before GA, then full re-test |
| Locking ourselves out | Break-glass designed in Phase 0, tested quarterly |
| Kanidm may already solve this | Deploy it and confirm — one day of evaluation against months of build |
| Scope is large for part-time | Every phase is independently useful; stopping after Phase 3 still leaves a working SSO IdP |
