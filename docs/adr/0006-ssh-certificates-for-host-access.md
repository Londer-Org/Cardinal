# ADR 0006: Linux host access uses short-lived SSH certificates

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

FreeIPA's real value in the target environment is Linux host login: SSSD
providing POSIX identity, HBAC deciding who may log into which host, centralised
sudo rules, and SSH key distribution.

SSSD speaks LDAP and Kerberos. ADR 0002 rules out being an LDAP server, and
writing a Kerberos KDC is a large, high-risk project we've explicitly excluded.
So the like-for-like replacement path is closed, by choice.

The conventional model has real drawbacks anyway: **every login requires the
directory to be reachable.** A directory outage locks everyone out of every
host. Credentials are long-lived. A compromised host holds a bind credential
that can enumerate the entire directory.

## Decision

**Stop doing directory lookups at login time. Authorize at credential
*issuance*; the host only verifies a signature.**

1. User runs `cardinal ssh web-01.prod`
2. CLI authenticates with a passkey
3. Server evaluates Cedar (ADR 0005): *may this person log into this host, as
   which local users?*
4. Server issues a **5–15 minute SSH certificate** whose principals encode the
   authorized logins
5. `sshd` validates it against `TrustedUserCAKeys` — no network call, no
   directory, no Kerberos

**HBAC becomes Cedar policy at issuance time.** Sudo rules become Cedar policy
rendered to `/etc/sudoers.d/`.

`cardinal-agent` on each host provides:

- **Host enrollment** — the host is a first-class directory entity with its own
  identity and keypair, joinable to groups (`env:prod`, `role:web`) and usable
  as a Cedar resource
- **POSIX identity** via systemd's `io.systemd.UserDatabase` varlink interface,
  consumed by `nss-systemd`. This is the supported modern replacement for
  `nss_ldap` and means **no C NSS module to write**
- **Sudo rendering** — validated with `visudo -c` *before* atomic install
- **Host certificates**, so users verify hosts via `@cert-authority`, killing
  TOFU host-key warnings fleet-wide
- **Offline cache** of policy and identity with a TTL

## Why this is better, not merely different

- **Works when Cardinal is down.** Issued certificates remain valid, and the
  agent serves cached identity. A directory outage does not lock anyone out.
- **Credentials expire on their own.** No key rotation project, no orphaned
  `authorized_keys` entries on a host nobody remembers.
- **A compromised host cannot enumerate the directory.** It holds no bind
  credential — only a CA public key.
- **Every access is centrally logged at issuance**, before it happens, rather
  than reconstructed from host logs afterwards.

## Alternatives considered

**Run an LDAP server after all, for SSSD only.** Rejected: it reintroduces
everything ADR 0002 exists to avoid, for one consumer, and keeps the
directory on the critical path of every login.

**Push `authorized_keys` files by configuration management.** Simple and common.
Rejected: keys are long-lived, revocation is a fleet-wide push that can partially
fail, and there is no per-session record of *why* access was granted.

**Deploy Teleport.** A mature product implementing this model. A legitimate
choice for someone who wants it working today — but it is a separate system with
its own identity model, which contradicts the one-system goal.

## Consequences

**Good.** Hosts survive directory outages. Credentials self-expire. Host key
verification works properly. Access decisions are policy-driven and explainable.

**Costs.** Every host needs an agent — an operational footprint FreeIPA also
has, but ours to build and support. The systemd-userdbd approach **must be
spiked before committing**; the fallback is a small NSS module or managed
`/etc/passwd` entries. Clock skew becomes security-relevant, since short-lived
certificates depend on time; hosts need working NTP.

**Break-glass is non-negotiable.** `cardinal-agent` must be *structurally
incapable* of removing local root access, enforced in code and tested against
every failure mode including being killed mid-write. A directory that can lock
you out of your own fleet is worse than the problem it solves.

**Migration requires shadow mode.** Hosts run SSSD and `cardinal-agent` in
parallel, with the agent logging what it *would* decide without enforcing, until
decisions match exactly. This is the single most important migration feature and
is planned as part of Phase 4, not as an afterthought.
