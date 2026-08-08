# Threat model

**Status:** living document, revised per phase. Last revised 2026-08-05 (Phase 0).

Cardinal authenticates people and authorises access to production systems. A
compromise here is a compromise of everything that trusts it, so this document
exists to make the assumptions explicit — particularly the uncomfortable ones.

It is deliberately not exhaustive. An exhaustive threat model that nobody reads
protects nothing. This covers the paths an attacker would actually take.

---

## What we are protecting

In descending order of consequence:

| Asset | Why it matters | Where it lives |
|---|---|---|
| **Database credential** | Grants everything: the CLI reaches Postgres directly and can issue an enrollment invitation for any account | Treat as the credential of last resort. Cardinal used to have a second one — an offline break-glass key — until [ADR 0014](adr/0014-break-glass-removed.md) removed it as redundant and internet-facing |
| **SSH certificate authority key** | Signs certificates for every host in the fleet | Phase 4 — key management undecided |
| **Authorization policy** | Decides who reaches what | Cedar policies in git, loaded into Postgres |
| **Temporal grants** | The authoritative record of who has access | `group_members` |
| **Audit journal** | Evidence of what happened | `events`, hash-chained |
| **Credentials** | Passkey public keys, TOTP secrets, session tokens | Postgres |
| **Personal data** | Legal obligation, and dignity | `entities`, `sessions` |

Note the ordering: **policy outranks credentials.** Stealing one person's
passkey compromises one account. Editing a policy compromises the model itself,
and does so quietly.

---

## Who we are defending against

| Adversary | Capability | Taken seriously? |
|---|---|---|
| **External unauthenticated** | Network reach to public endpoints | Yes — primary |
| **Phishing attacker** | Can deceive any user, convincingly | Yes — primary |
| **Compromised user account** | Valid session, one person's privileges | Yes — primary |
| **Compromised host** | Root on one enrolled Linux host | Yes — Phase 4 |
| **Malicious/compromised admin** | Full Cardinal administrative rights | Partially — see below |
| **Database-level attacker** | Direct SQL access, not application-level | Partially — detection, not prevention |
| **Google Workspace super-admin** | Can read any mailbox | **Named, accepted** (ADR 0009) |
| **Nation-state with server access** | Root on the Cardinal host | No — out of scope |

**On malicious administrators.** Full prevention is impossible: an admin who can
change policy can grant themselves anything. Cardinal narrows this rather than
solving it — dual control for recovery, step-up authentication for privileged
actions, and an audit journal an admin cannot silently edit. **An admin can
still do damage; they cannot do it invisibly.** That is the honest claim.

**On database-level attackers.** Someone with direct SQL access can alter state.
Append-only rules block the ordinary path, but a superuser can disable them.
The hash chain converts this from *undetectable tampering* into *detected
tampering* — a downgrade of the attacker's position, not an exclusion.

---

## Attack paths, and what stands in the way

### 1. Steal a credential and authenticate as someone else

*Phishing, credential stuffing, replay.*

- **No passwords exist** (ADR 0002). There is nothing to stuff or reuse.
- **Passkeys are origin-bound**, so a convincing lookalike site cannot harvest a
  usable credential. This is the single largest security gain over FreeIPA and
  Keycloak.
- **TOTP is phishable and is treated as such** (ADR 0009): permitted as a second
  factor and a migration aid, never for administrative actions.
- Session tokens are stored hashed, so a database read yields nothing usable.

**Residual risk:** real-time relay against TOTP. Accepted, and bounded by TOTP
never authorising anything privileged.

### 2. Recover an account you don't own

The recovery path is the classic weak underside of strong authentication.

- Administrator recovery requires **dual control** — two admins, independently.
- Recovery email is **never sufficient alone** and **never for administrators**
  (ADR 0009).
- Recovery codes are single-use and Argon2id-hashed.

**Residual risk:** a Google Workspace compromise reaches ordinary users'
recovery email. Accepted and documented, with the SSO tripwire in ADR 0009.

### 3. Keep access after it should have ended

The failure mode that makes real breaches expensive: access that outlives its
justification.

- Grants carry validity periods enforced by **every read**, not by a sweeper job
  whose failure would silently *extend* access (ADR 0001).
- **Inherited access cannot outlive the membership granting it** — an expired
  intermediate link breaks the chain. Tested explicitly; getting it wrong would
  be a silent authorization bypass invisible to direct-membership testing.
- Disabled groups confer nothing, immediately.

**Residual risk:** cached authorization decisions. `NOTIFY` is a hint, never a
guarantee (ADR 0004), so **revocation must also be enforced at read time.**
Specifying that path is an open question blocking Phase 2.

### 4. Escalate privilege

- Cardinal's own administrative API is governed by the **same Cedar policy
  engine** as everything else (ADR 0005) — no separate, weaker ACL language.
- Privileged actions require **fresh, device-bound** authentication; `auth_method`
  and `device_bound` are carried in session context precisely so policy can
  demand it.
- Self-membership is rejected by constraint; cyclic groups terminate.

**Residual risk:** a policy bug granting more than intended. Mitigated by
policies being versioned in git, unit-tested, and validated against a schema in
CI — not by trusting them to be right.

### 5. Cover your tracks

- The journal is append-only, enforced by **database rules** rather than
  application discipline.
- Each record hashes its predecessor, so modification and deletion are both
  detected — including deletion from the middle, which a naive per-row integrity
  check would miss.
- Chain validation runs after every restore, so a tampered backup is caught.

**Residual risk:** an attacker with superuser access could disable the rules,
tamper, and recompute the entire chain forward. Detecting that requires an
external anchor — periodically publishing the chain tip somewhere Cardinal
cannot reach. **Not yet implemented; it is the main gap in the audit story.**

### 6. Compromise a host and pivot

*Phase 4, but the design already constrains it.*

- Hosts hold **no bind credential** — only a CA public key. A compromised host
  cannot enumerate the directory, which is the standard LDAP pivot.
- Certificates expire in 5–15 minutes, so stolen ones have negligible value.
- Host identity is a directory entity, so a compromised host can be excluded by
  policy immediately.

**Residual risk:** compromise of the SSH CA key would be catastrophic —
fleet-wide, silent, and hard to recover from. Key management is an open
question and is the highest-stakes decision remaining in Phase 4.

### 7. Deny service

- Cardinal being down means nobody authenticates anywhere. This is inherent to
  centralised identity and is why availability is a phase-0 constraint.
- **Hosts survive it**: issued certificates stay valid and the agent serves
  cached identity, so a Cardinal outage does not lock anyone out of SSH.
- **Rate limiting shipped** — fixed-window, fails closed, proxy-aware, on login
  and recovery. Account lockout did not, and is not currently needed: a passkey
  cannot be guessed, and the one guessable secret left is a recovery code, which
  is capped. Revisit when TOTP arrives.

**Residual risk:** database loss. Mitigated by PITR plus a restore drill that
also verifies chain integrity — the restore path is proven, not assumed.

---

## Assumptions we are making

Stated plainly, because unexamined assumptions are where threat models fail:

1. **The Cardinal host is not compromised.** Root there defeats everything.
2. **PostgreSQL superuser access is restricted** to a small, trusted set.
3. **Host and database access is treated as the credential of last resort** —
   anyone with it can issue an enrollment invitation for any account, so it is
   guarded, logged, and held by more than one person.
4. **Google Workspace is well-administered** — accepted as a dependency for
   ordinary-user recovery (ADR 0009).
5. **Hosts have working NTP.** Short-lived certificates depend on time, so clock
   skew becomes security-relevant.
6. **TLS is terminated correctly**, whether at Traefik or Cardinal.

---

## Known gaps

Honest list, tracked in [ROADMAP.md](https://github.com/Londer-Org/Cardinal/blob/main/ROADMAP.md):

| Gap | Consequence | Phase |
|---|---|---|
| **No external anchor for the hash chain** | A superuser could rewrite it whole and pass validation | Post-1.0 |
| **No decision cache yet, so nothing to invalidate** | When the agent caches offline, a cached decision could outlive a revocation | Phase 4 |
| **SSH CA key management undecided** | Highest-stakes remaining decision | Blocks Phase 4 |
| **No account lockout** | Nothing guessable is unlimited today — passkeys cannot be guessed and recovery codes are capped at 5 per 15 minutes. Reopens the moment TOTP exists | With TOTP |
| **The `sensitive` flag is declared and unread** | The registry lets an operator mark an attribute sensitive; no code encrypts or redacts on it, so the flag promises something nothing delivers | Phase 1 |
| **No external security review** | Self-assessment only | Before production |

The last one matters most. This document is written by the person who wrote the
code, which is exactly the wrong person to find its blind spots.
