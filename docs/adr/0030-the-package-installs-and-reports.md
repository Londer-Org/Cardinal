# ADR 0030: The package installs and reports, and does not prepare

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

`cardinal-agent` needs two edits before it does anything useful on a machine:

- `systemd` in the `passwd` and `group` lines of `/etc/nsswitch.conf`, or nothing
  ever consults its socket;
- `@includedir /etc/sudoers.d` in `/etc/sudoers`, or the drop-in it renders is
  silently inert.

Both are things a `.deb` postinst could do, and there is precedent: `libnss-systemd`
edits `nsswitch.conf` in its own postinst, and every distribution ships packages
that rewrite configuration on install.

The agent already refuses both edits
([ADR 0026](0026-sudo-is-as-strong-as-the-shell.md),
[ADR 0027](0027-a-machine-proves-its-own-name.md)) on the principle that it may
add a fact about the machine and may not change how the machine authenticates
people. The question is whether the package inherits that rule or is a different
actor — installing is, after all, a deliberate act by an administrator.

## Decision

**The package installs files and nothing else. It ships no maintainer scripts,
does not enable the unit, and makes no edit outside its own paths.**

The reasoning is what Cardinal is. A security product that rearranges how a
machine resolves every username — as a side effect of an install somebody did to
have a look at it — is the surprise that costs an identity system its
credibility. And the unit is not enabled because enabling it starts a daemon on
a machine that has not enrolled, for the same reason.

The other half of the decision is `cardinal-agent doctor`: check every
prerequisite, name what is missing, give the command that fixes it, and exit
non-zero while anything *fatal* is outstanding — so it can gate a rollout without
failing on a machine that merely has no sshd.

```
✗  enrolled         no key at /etc/cardinal/host_key
✓  nsswitch         passwd and group consult systemd
✗  userdb socket    nothing listening at /run/systemd/userdb/io.systemd.Cardinal
✓  sudoers include  /etc/sudoers.d is included
✓  visudo           available
✓  sshd drop-in     /etc/ssh/sshd_config.d is included and sshd accepts it
```

Configuration lives in `/etc/cardinal/agent.toml` rather than in flags in the
unit, so changing a setting is not editing a unit file that then conflicts on
every upgrade. The file is `config|noreplace`: an upgrade never overwrites what
an operator wrote.

## What the verification found, and what had to be corrected

The check was written to assert *"installing the package changes nothing about
how this machine resolves usernames"*. It failed on the first run, and it was
right to.

Cardinal's package ships no maintainer scripts — but it **depends** on
`libnss-systemd`, whose postinst adds `systemd` to `nsswitch.conf`. Installing
Cardinal therefore does change NSS, transitively. The claim was false.

The dependency is correct and stays: without `libnss-systemd` the agent's socket
exists and nothing ever asks it anything, so the package would install something
inert. What changed was the claim, to the one that is true and turned out to be
more interesting:

**`libnss-systemd` appends rather than inserts.** On a machine already using
another directory, the line becomes `passwd: files sss systemd` — the existing
source still wins for any name they both know. Installing the package is
therefore *additive and not a cutover*, which is exactly the property
[ADR 0020](0020-posix-identity-over-varlink.md) flagged as a migration decision
and exactly what shadow mode needs to stay meaningful: the agent is not yet the
thing being asked.

Cutting over is then a deliberate reordering by a human, which is where that
decision belongs.

The verification asserts the ordering directly, on a machine seeded with an
existing directory in the line, because "additive" is the whole safety property
and a future dependency change could quietly reverse it.

## Consequences

**Installing the package leaves a machine that does nothing.** By design, and
`doctor` says so precisely. The alternative — install and be live — means the
moment of cutover is an `apt install` rather than a decision.

**Two commands, not one, to get a host running.** Install, then enrol, then
enable. That is more steps than a package that prepares everything, and each one
is a thing somebody chose.

**Removing the package keeps `/etc/cardinal/agent.toml`.** Standard behaviour for
a `conffile`, and right: an operator removing the agent to try something is not
asking to lose the configuration.

**The unit is hardened where it costs nothing.** `ProtectSystem=strict` with
`ReadWritePaths` naming exactly the four places the agent writes, so a bug that
tried to write anywhere else fails rather than succeeds. It runs as root because
it writes `/etc/sudoers.d` and `/etc/ssh` and serves a socket every process must
reach — granting those individually is the same privilege spelled longer.

**Not `Before=sshd.service`.** An agent that must start before sshd is an agent
whose failure keeps people off the machine, which inverts the availability
property the whole design is arranged around. The cache answers from disk, and a
login arriving before the first refresh falls through to whatever else
`nsswitch.conf` names.

**`Restart=always`.** The failure this recovers from is Cardinal being
unreachable at boot — precisely when giving up would be worst — and the agent
serves from its cache meanwhile, so a restarting agent is not a broken machine.
