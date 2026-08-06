# ADR 0014: Break-glass is removed; the CLI is the recovery path

- **Status:** Accepted
- **Date:** 2026-08-06
- **Amends:** [ADR 0009](0009-recovery-and-break-glass.md), whose break-glass
  half no longer describes the system. Its reasoning about recovery email, the
  IdP circularity rule, and never storing recoverable credentials all stand.

## Context

[ADR 0009](0009-recovery-and-break-glass.md) introduced an offline Ed25519 key
whose holder could open a short emergency session as any account. It existed
because of a circularity: enrolling a first passkey needed a session, and
getting a session needed a passkey. Break-glass broke that circle, and so became
the ordinary bootstrap path — which is precisely how a mechanism meant to be
rare and alarming stops being either.

[ADR 0013](0013-enrollment-invitations.md) gave that job to enrollment
invitations. The question then became whether break-glass was still worth its
cost as a pure recovery mechanism. Two findings settled it.

**The CLI already performs the same recovery, with no authentication at all.**
`cardinal invite <admin>` reaches the database directly and issues an enrollment
link. Anyone able to run it can already become any user. Break-glass was
therefore never the last resort — the database credential is, and always was.
Keeping break-glass meant maintaining a *second* credential of last resort, one
reachable from any browser on the internet rather than from a shell on the host.

**The property that justified having both was never true.** The project plan
required "a documented, tested break-glass procedure that works with the
database down". The ceremony persisted challenges in `break_glass_challenges`,
so it required exactly the component that might be unavailable. Break-glass has
never worked with the database down. What actually covers that case is restoring
from backup, which ADR 0009 also specifies and which is unaffected.

What remained was narrow: recovery from a browser, by someone holding the sealed
key, who has no shell access to the host. Real, but not worth a permanently
internet-facing credential that can impersonate any user.

## Decision

**Break-glass is removed.** Recovery is:

```sh
cardinal invite <admin-login>     # on the host, with database access
```

The holder registers a passkey and signs in. It is loud — issuing an invitation
for an account that already has credentials logs at warning level and warns on
the terminal — single-use, time-boxed and revocable.

Removed: the keypair and its ceremony, `break_glass_challenges`, the
`/api/auth/break-glass/*` endpoints, the `cardinal break-glass` command, the
emergency-access UI, the `break_glass` configuration section, the `Emergency`
session concept, and the two Cedar `forbid` rules that existed to contain it.

The audit action `breakglass.used` is no longer emitted, but journals written
before this removal still contain it. The string must never be reused, because
it appears in hashes that cannot be rewritten.

## Consequences

**Good.** One credential of last resort instead of two, and the one that remains
is not internet-facing: it requires shell access to the host. A smaller attack
surface, no offline key to store, test, rotate or lose, and no `emergency` flag
that every future policy must remember to forbid — that flag was a permanent tax
on a policy set meant to be readable.

The e2e suite previously signed in via break-glass, which was the only
non-interactive path. It now seeds a session row directly. That is more honest:
it skips the same ceremony without a production mechanism existing partly to
make tests convenient.

**Costs.** Recovery now requires shell or database access to the host. An
organisation where the person responsible for the directory is not the person
responsible for the server loses the ability to separate those roles. If that
becomes a real requirement, the answer is dual-control admin recovery — two
administrators approving the restoration of a third — which ADR 0009 already
lists as unbuilt, and which is a better fit for that need than a single sealed
envelope that can impersonate anyone.

**Unchanged.** ≥2 passkeys are still enforced before an account counts as fully
enrolled, recovery codes still exist, and the recovery/IdP circularity rule is
still applied everywhere an email address can be set. Losing every device is
still recoverable; it now costs an SSH session rather than an envelope.

**Still open.** First-run setup. `cardinal user create` plus `cardinal grant
directory-admins` plus `cardinal invite` is the sequence, and nothing yet does it
as one deliberate step.
