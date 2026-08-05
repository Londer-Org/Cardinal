# Roadmap

Living document. Updated as work lands, not as it's planned.

**Legend:** ✅ done · 🔨 in progress · ⬜ not started · 🚧 blocked · ❓ needs a decision

**Current position:** Phase 0 substantially complete — directory core, temporal membership, audit chain and CLI all working against real PostgreSQL 19.

---

## Phase 0 — Foundations

**Goal:** `cardinal user create` works, and temporal membership is queryable.

| | Item | Notes |
|---|---|---|
| ✅ | Repo, Apache-2.0 licence, SECURITY.md, .gitignore | |
| ✅ | PostgreSQL 19 beta 2 dev environment | Port **5433** (5432 is taken by another project) |
| ✅ | **PG19 feature verification** | All temporal features confirmed working — see below |
| ✅ | Foundation migration | entities, schema registry, temporal membership, event log, sessions |
| ✅ | ADRs 0001–0008 | [docs/adr](docs/adr/) |
| ✅ | Entity engine (Go) | UUIDv7 identity, typed entities, soft delete |
| ✅ | Temporal membership + recursive-CTE resolver | Cycle-safe; expired links break inheritance |
| ✅ | Hash-chained event log (Go) | Length-prefixed encoding; tampering + deletion both detected |
| ✅ | testcontainers integration harness | 14 integration tests, green under `-race` |
| ✅ | `cardinal` admin CLI | **Phase 0 deliverable — working end to end** |
| ✅ | CI pipeline | lint · vet · gofumpt · govulncheck · tidy check · PG matrix |
| ⬜ | Schema registry enforcement (Go) | Table exists; validation logic not yet wired |
| ⬜ | Threat model document | |
| ⬜ | Backup + restore verification | Restore, then validate the hash chain |
| ❓ | **Break-glass design** | Blocks Phase 1. Must work with the database down |
| ❓ | **GDPR erasure vs. append-only chain** | Constrains event payload design — decide early |

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
| 🚧 | WebAuthn registration and login — *blocked on break-glass design* |
| ⬜ | Session management + CSRF |
| ⬜ | Recovery codes, ≥2 passkeys enforced |
| ⬜ | Dual-control admin recovery |
| ⬜ | Frontend stack (React 19, Vite, Tailwind v4, shadcn/ui, TanStack, generated zod, strict-TS CI gates) |
| ⬜ | `embed.FS` release build + first container image |

> **Blocker:** don't build authentication before deciding how to recover from
> it. Passwordless plus self-hosted is exactly the setup where people lock
> themselves out of their own directory.

---

## Phase 2 — Authorization + Traefik

**Goal:** an internal app sits behind Traefik, protected by Cardinal. *The
first genuinely useful milestone.*

| | Item |
|---|---|
| ⬜ | `cedar-go` integration |
| ⬜ | Policy storage, versioning, CI test suite |
| ⬜ | **Protocol-agnostic claims projection** (four consumers — [ADR 0007](docs/adr/0007-no-saml.md)) |
| ⬜ | `forwardAuth` endpoint |
| ⬜ | Decision logging with policy attribution |
| ⬜ | **Decision explorer UI** — "why was this denied?" |

---

## Phase 3 — OIDC provider

**Goal:** point a real application at Cardinal instead of Keycloak.

| | Item |
|---|---|
| ⬜ | `zitadel/oidc` integration |
| ⬜ | Client management UI, consent |
| ⬜ | PKCE + `private_key_jwt` |
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

## Standing risks

| Risk | Mitigation |
|---|---|
| PG19 not GA until ~Sept/Oct 2026 | Pinned to `19beta2`; no production release before GA, then full re-test |
| Locking ourselves out | Break-glass designed in Phase 0, tested quarterly |
| Kanidm may already solve this | Deploy it and confirm — one day of evaluation against months of build |
| Scope is large for part-time | Every phase is independently useful; stopping after Phase 3 still leaves a working SSO IdP |
