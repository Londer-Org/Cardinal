# ADR 0026: Sudo is exactly as strong as the shell that reaches it

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

Replacing FreeIPA's sudo rules means `cardinal-agent` writes
`/etc/sudoers.d/50-cardinal` from Cedar's `RunAsRoot` decision. Rendering the
file is mechanical. Deciding what the rule inside it says is not, and there is
one question with no comfortable answer.

**Cardinal has no passwords.** A sudoers rule without `NOPASSWD` prompts for a
credential that does not exist, so the person sits at a prompt they cannot
satisfy and the feature does not work at all. `NOPASSWD` is not a convenience
setting here; it is the only rule that functions.

That collides with the policy, which says:

```cedar
@id("root-requires-recent-auth")
forbid (principal, action == Cardinal::Action::"RunAsRoot", resource)
unless { principal.authAgeSeconds <= 900 };
```

`authAgeSeconds` is a property of a session. When the agent renders the file
there is no session — nobody is sudoing, a machine is asking who might — so the
condition cannot be evaluated and cannot be carried into the file. sudoers has
no way to express "if they authenticated in the last fifteen minutes" because
sudo has no idea what Cardinal is.

## Decision

**The rendered rule is `NOPASSWD: ALL`, and the control is the certificate, not
the sudoers file.**

The reasoning is that possession of the shell is already the proof. The only way
to have a shell as `alice` on a Cardinal-managed host is an SSH certificate
issued minutes earlier, and issuance required a device-bound passkey — a
stronger check than any password prompt sudo could have raised. Re-asking at the
sudo prompt would be asking a question that was answered, better, on the way in.

The renderer evaluates `RunAsRoot` with an as-if-ideally-authenticated subject,
exactly as the assignment endpoint does for `SSHLogin`
([ADR 0025](0025-a-host-learns-only-its-own-people.md)). The `authAgeSeconds`
condition therefore always passes at render time. It is not dead: it still
applies wherever a live session asks Cardinal directly.

## Consequences

**An SSH session outlives its certificate, and this is the real gap.** A shell
opened at 09:00 with a ten-minute certificate is still a shell at 17:00, and it
carries passwordless root the whole time. The freshness the policy asks for is
enforced once, at the door, and never again.

That is a genuine weakening and it is not mitigated by anything in this design.
What bounds it is operational: session lifetime, idle timeouts in sshd, and the
fact that the same is true of every Kerberos or certificate-based sudo
arrangement in use today. Naming the future fix rather than pretending it does
not exist: a PAM module that asks Cardinal for a step-up would close it, at the
cost of making sudo depend on Cardinal being reachable — which is the property
this whole design has been arranged to avoid, so it would have to be optional
and per-host.

**Anything running as that uid gets root.** A compromised service running under
an administrator's account escalates for free. The mitigation is not technical:
do not run services as a person's account. Worth stating because the
password-prompt version of sudo does provide a weak barrier here, and this
removes it.

**Command granularity is not supported.** The rule is `ALL`. FreeIPA sudo rules
can name commands, and Cedar cannot produce that list — Cedar *decides* about a
request, it does not *enumerate* what would be permitted. Rendering per-command
rules needs command sets to exist as directory objects that can be iterated over,
which is a data-model decision worth making on its own rather than as a
side-effect of this one. Until then a host grants root or does not.

**A broken render costs less than the folklore says, and is still prevented.**
Measured on sudo 1.9: an unparseable file in `sudoers.d` does **not** stop sudo
working. It is reported, skipped, and everything else carries on — root included.
What it actually costs is that everyone named only in that file silently loses
sudo, every invocation on the machine prints a syntax error to whoever runs it,
and `visudo -c` fails for the whole configuration afterwards. So `visudo -c` runs
against the candidate before it is moved into place, a rejection leaves the
previous file untouched, and a host without `visudo` gets nothing installed at
all.

**The agent cannot take away root.** It writes one file and reads none.
`/etc/sudoers` is never edited — not even to add the `@includedir` line that
makes the drop-in take effect, which is instead reported as a warning for a human
to act on. Whatever local root a machine had before Cardinal, it keeps.

## Alternatives rejected

**Render nothing and require a password.** Correct-looking and non-functional:
there is no password to type.

**Have sudo call back to Cardinal for a decision.** Closes the freshness gap and
makes every `sudo` on every host depend on the directory being reachable, which
is the failure this project is arranged around
([ADR 0020](0020-posix-identity-over-varlink.md)).

**Encode the freshness condition as a short-lived sudoers file** — write the
rule only while somebody has recently authenticated, and remove it after fifteen
minutes. Rejected: it makes sudo access depend on the refresh loop having run
recently, so a network blip removes root from an administrator mid-incident.
Failing that way during an outage is worse than the gap it closes.
