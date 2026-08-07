# ADR 0029: A number is permanent once it has been served, and not before

- **Status:** Accepted
- **Supersedes part of:** the "never changes" claim in migration 0019 and
  [ADR 0028](0028-shadow-mode-reports-and-does-not-act.md)'s "adopt the existing
  numbers" step, which had no mechanism behind it.
- **Date:** 2026-08-07

## Context

Shadow mode ends with one blocking finding: the machine says alice is 1234 and
Cardinal says 100003. There are two ways out, and only two — change every file on
the machine, or change the row in Cardinal.

Changing the row was documented as impossible. Migration 0019 says a uid is
permanent, and `SetPOSIXAttributes` deliberately takes no number parameter, with
the reasoning that every file on every disk records it so changing it
reattributes files rather than editing an attribute.

That reasoning is correct and it is not the whole story. **A number that has
never left Cardinal has reattributed nothing.** Before any host has been told
about it, it is a row in a table, and changing it costs exactly what changing a
row costs.

That window is the only thing that makes migration onto Cardinal practical. The
alternative — `find -uid 1234 -exec chown` across a fleet — is an evening per
machine and a restore from backup if anything is missed.

## Decision

**A number may be adopted until it is first served, and never afterwards. The
boundary is a column, not a warning.**

`posix_identities.first_served_at` is stamped the first time an assignment
includes that identity, by the endpoint that hands it out. `AdoptPOSIXNumber`
refuses once it is set.

Making it a column rather than a documented caution matters because the failure
is silent. An operator adopting after cutover sees success, and finds out weeks
later from the files.

The stamp is set by the server, not reported by the agent — the guarantee has to
hold from the moment the number leaves Cardinal, not from the moment somebody's
machine admits to having received it. A failure to stamp fails the request: the
agent keeps whatever it last cached, which is the safe direction.

**Adoption reads shadow reports.** The numbers live on the machines, and asking
an operator to retype them invites the typo that reattributes somebody's home
directory. `cardinal-agent shadow -json` on each host, then
`cardinal posix adopt -from web-01.json,web-02.json`.

**A fleet that disagrees with itself is refused, not resolved.** If two machines
give alice different numbers, no single value satisfies both, and picking one
silently reattributes her files on the other. That is work outside Cardinal —
reconcile the machines first.

## The design error this exposed

The first implementation refused uid 1234 with:

> `1234 is below 65536, which belongs to the system's own accounts`

uid 1234 is not a system account. It is a person on a machine numbering people
from 1000 upward, because that is what `UID_MIN` says on every mainstream
distribution — which is to say, the ordinary case adoption exists for. The
feature could not do the thing it was built to do.

The cause was one number serving two questions. **Where Cardinal starts
allocating** is a policy choice, deliberately above the distribution's range and
above systemd's `DynamicUser` reservation so a freshly handed-out number never
lands on either. **What a person may legitimately hold** is a fact about Unix,
and it is a much wider set. Migration 0019 wrote the first into a `CHECK`
constraint, where the second belonged.

They are now separate:

| | Enforced by | Value |
|---|---|---|
| Where Cardinal allocates | configuration, validated in Go | default 100000–999999, floor 65536 |
| What may be stored at all | a `CHECK` constraint | ≥ 1000, excluding 61184–65519 |

The constraint now says what is true on every machine, and the range says what
this deployment chose. That is the split that should have been there from the
start, and it took building the feature that crossed the two to see it.

## Consequences

**`cardinal posix assign` no longer says a number can never change.** It said so,
and it was true when written. It now says the number is permanent *once a host
has been told about it*, which is both true and the thing an operator planning a
migration needs to know.

**Adopting is idempotent.** Re-running a set of reports produces the same answer,
including once the numbers have been served — nothing is being changed, so the
guard is not tripped. An operator unsure whether the first run worked has to be
able to run it again.

**Adopted numbers do not disturb the allocator.** Allocation is `max + 1` within
the configured range; a number adopted below that range is outside the `WHERE`
and cannot drag the next assignment out with it.

**Refusals are counted separately by reason.** "Already served" means move the
files; "no such user" means create the account. An earlier version counted both
together and gave the first advice for the second problem, which is worse than
giving none.

## What this does not solve

A number already served, on a machine that disagrees. There is no window left,
and the only resolution is `chown`. Cardinal's contribution is to say so
precisely — which accounts, which machines, which numbers — rather than to
discover it during the cutover.
