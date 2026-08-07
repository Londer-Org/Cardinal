# ADR 0028: Shadow mode reports, and does not act

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

Migrating a host onto Cardinal has one failure that cannot be undone.

If the machine already says alice is uid 1234 and Cardinal says 100003, then the
moment Cardinal wins, every file alice owns belongs to a stranger and every file
the stranger owns belongs to alice. Nothing afterwards fixes it: the filesystem
recorded a number, the number changed, and the mapping from the old number to
the person is gone. On a machine with real data it is not a rollback, it is a
restore from backup.

Everything else a cutover changes is recoverable. A home directory that moved is
a rename. Sudo that appeared or disappeared is a policy edit. Groups gained or
lost are a grant. Only the numbers are permanent.

So the question worth answering before touching anything is narrow: **do the two
systems agree about the numbers?** And the way to answer it is to run the
comparison on the machine, against the machine, and change nothing.

## Decision

**`cardinal-agent shadow` fetches the assignment, asks the running system what it
currently believes, and prints the difference. It writes nothing.**

Findings are graded by what a cutover would cost, and only one grade stops it:

| Severity | Means | Example |
|---|---|---|
| `blocking` | Cutting over destroys something | uid or gid disagrees |
| `review` | Access changes; somebody should agree first | gains or loses sudo |
| `additive` | Cardinal grants something new | an account the machine has never had |
| `match` | The two agree | |

Nothing but a number mismatch is blocking, and that is a deliberate calibration.
A report that stopped a migration over a changed login shell would be turned off
by the second host, and then the uid check goes with it.

**Read-only by construction, not by discipline.** Shadow mode builds an `Agent`
with no cache path, no sudoers path, no host key and no socket directory — an
object that cannot write anything. It calls `Fetch` rather than `Refresh`.

That distinction exists because of this ADR: the first version called `Refresh`,
which writes the cache to `/var/lib`, renders sudoers and renews the certificate,
while the command's own help text said it changes nothing. `Fetch` was split out
and a test now fails if anything appears on disk.

The reason it has to be absolute is the one
[ADR 0020](0020-posix-identity-over-varlink.md) already noted: `nss-systemd` sits
somewhere in `nsswitch.conf`, and if Cardinal's provider is answering then
`getent passwd alice` returns Cardinal's answer. Comparing the agent against the
machine is meaningless when the agent is the thing being asked.

## Consequences

**The comparison asks the system, not a library, and does not care what is
behind it.** Through `getent`, `id` and `sudo`, which is the whole NSS chain —
`sssd` against LDAP or Active Directory, `nss_ldap`, plain `/etc/passwd`, or
something nobody here has heard of. A version that queried a particular directory
would work for one kind of deployment and be useless for every other.

Not Go's `os/user`, which reads `/etc/passwd` directly when cgo is disabled — and
would therefore report that nobody served by a directory exists at all, turning
every comparison into a false `additive` and concluding that a migration which
would destroy the machine is safe.

**The locale is forced to C.** `sudo` translates "may run the following
commands", and the check reads that string because `sudo -l -U` exits 0 whether
or not the person has any privilege — measured, not assumed. On a machine set to
French, an unforced locale would quietly report that nobody has sudo: a report
saying everything matches when nothing was compared.

**Accounts the machine can already resolve and Cardinal has never heard of are
invisible.** There is usually no asking "who else do you know about":
directory-backed NSS providers disable enumeration by default, exactly as
Cardinal does ([ADR 0025](0025-a-host-learns-only-its-own-people.md)) and for the
same reason. The remedy is `-users alice,bob` and the limitation is printed on
every report rather than left to be discovered.

**A non-zero exit means blocking.** So the command can be the gate in whatever
runs it across a fleet, without anything parsing its output.

**It does not compare who may log in.** Every other finding here is something
the machine itself can answer. That one is not: whatever currently decides host
access — a directory's own rule objects, a configuration-management template, a
hand-maintained `AllowUsers` — is not visible from the host in any general way.
Comparing it would mean teaching this package about a particular system, which is
exactly what the rest of it avoids.

## What this does not solve

Shadow mode tells you the numbers disagree. It does not tell you what to do
about it, and there are only two options: adopt the existing numbers in Cardinal,
or move the files. The first is almost always right, and the machine already
knows the numbers — `getent` is where they came from — so the input for it is a
shadow report rather than a connection to whatever system assigned them. The
second is a `find -uid ... -exec chown` on a quiet machine and a long evening.

The one thing that is not an option is doing it gradually. A uid is either
Cardinal's or the machine's existing one at any given moment, and the moment it
changes is the moment every file is reattributed.
