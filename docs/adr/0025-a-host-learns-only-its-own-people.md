# ADR 0025: A host learns only the people who may log into it

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

Replacing SSSD means something has to answer "who is uid 100003, what is their
home directory, which groups are they in". SSSD answers it by asking LDAP, and
that arrangement has a property nobody chose and everybody inherits: **a bound
host can enumerate the directory.** `getent passwd` on the least important
machine in the fleet returns every name, every uid and every group in the
company.

That is not a misconfiguration. It is what a directory bind is for. The host has
to be able to resolve any name it might see, so it is given the ability to
resolve all of them, and the blast radius of compromising a build agent includes
the whole staff list.

Cardinal does not have to inherit it, because the host does not read the
directory — it is told what to serve.

## Decision

**`GET /api/hosts/assignment` returns the POSIX records for the people Cedar
permits to log into that host under their own name, and nobody else.**

The same decision point as certificate issuance: same action (`SSHLogin`), same
resource (the host entity), same context key (`localAccount`). A host's view of
who exists and its view of who may log in therefore cannot drift apart — there
is no second rule to keep in sync.

Three things fall out of that and each is a decision in its own right.

**The subject is evaluated as if ideally authenticated.** Policy forbids
`SSHLogin` unless the principal is device-bound and recently authenticated —
properties of a *session*, and there is no session here. Nobody is logging in;
an agent is asking who might. Evaluated verbatim, every user fails that forbid,
every host receives an empty assignment, and the agent installs it without
complaint — a wrong answer indistinguishable from "nobody has access to this
machine". So `mayLogIn` substitutes an ideal auth context before evaluating.

That is safe **only** because this endpoint grants nothing. It decides which
names a host may resolve. Whether anyone may actually log in is decided again at
certificate issuance, against their real credential, and logged there. If a
future host endpoint ever grants something, it must not reuse this shortcut.

**Nothing is written to the decision log.** Every other Cedar evaluation in
Cardinal is logged; this one would write one row per user per host per poll —
tens of thousands a day for a modest fleet, drowning the log that exists so a
human can find the interesting entries. Knowing a name is not access, and the
access decision is logged where it happens.

**Someone permitted only as a shared account does not appear.** A rule granting
`context.localAccount == "deploy"` grants a local account the machine already
has; there is no directory identity to resolve. Only `localAccount ==
principal.login` puts a person in the assignment.

## Consequences

**Compromising a host yields that host's users.** Not nothing — but the people
who could log into that machine anyway, which is a blast radius proportional to
what was lost rather than to the size of the company.

**Enumeration is not supported, and that is now doubly true.** ADR 0020 already
decided the varlink provider returns `EnumerationNotSupported` rather than
listing the directory. Now there is no directory to list: the agent holds only
its own assignment.

**A permitted user with no uid is a silent failure**, so the response names them
explicitly in `unnumbered`. Policy says yes, a certificate is issued, and sshd
rejects the login because the host cannot resolve the name — nothing in that
chain says why. Reporting it means an operator sees it before anyone tries.

**The cost is one policy evaluation and one membership resolution per user, per
request.** For an internal directory of hundreds of people polled every few
minutes that is nothing. It will not stay nothing at ten thousand users, and the
fix when it stops being nothing is caching the assignment per host with
invalidation on membership change — deliberately not built yet, because the
shape of the invalidation depends on how agents end up polling.

**A host must be told again whenever anything changes.** Group membership,
policy, a new uid: none of it reaches a machine until its agent refreshes. That
is the same staleness the SSH certificate design already accepts, and the same
reason it is acceptable — a machine that cannot reach Cardinal keeps working
from what it last knew, which is the property SSSD's offline cache exists to
provide and this gets for free.

## Alternatives rejected

**Serve every numbered user to every host.** Simpler, and it reproduces exactly
the LDAP property this design exists to remove.

**A separate `KnownOnHost` action.** Cleaner in one way — no as-if-authenticated
shortcut — and it introduces a second rule that must agree with the first
forever. Two rules that must agree are one rule and a bug waiting to happen.
