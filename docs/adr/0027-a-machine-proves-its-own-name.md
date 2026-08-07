# ADR 0027: A machine proves its own name

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

Every SSH connection to a new machine ends with a question nobody can answer:

```
The authenticity of host 'web-01.prod' can't be established.
ED25519 key fingerprint is SHA256:CxJdY/ua9taHXwPiWR0TB2z4pJ93JrdEK4eOoYACLRc.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

Nobody compares that string against anything. Everybody types `yes`. The
protection trust-on-first-use is supposed to provide has been trained out of
people by a decade of being asked it about machines that were fine, and the one
time it matters the answer is the same.

The fix is old and well understood — an SSH certificate authority signs each
machine's host key, clients trust the authority instead of a list of
fingerprints — and it is not deployed because someone has to run the authority
and get certificates onto every machine. Cardinal already runs one, and already
has an agent on every machine that can authenticate as that machine.

## Decision

**`cardinal-agent` obtains a host certificate for its machine and installs it,
and Cardinal decides the names it is good for.**

The single decision that shapes the rest: **principals come from the directory
and nothing in the request is consulted.** A certificate naming
`payments.internal` is the power to *be* `payments.internal`, so the machine
asking cannot be the machine that decides. A compromised host asking for one gets
its own name back, and is not refused — a refusal would tell the attacker the
field is read at all.

Names are written down, never derived. A host called `web-01.prod` does not get
the short name `web-01` thrown in, tempting as it is: `web-01.dev` would get it
too, and whichever answered first when somebody typed `ssh web-01` would be
trusted. That is an impersonation created by a convenience nobody asked for.
Extra names are aliases, granted deliberately, and unique across the fleet —
including against other hosts' directory names, which no database constraint can
express because the two live in different tables.

Host certificates last **seven days**, against the minutes a user certificate
gets. The asymmetry is the point: a user certificate expiring costs one person
one command, and a host certificate expiring costs every user of that machine a
fingerprint prompt at once, during whatever is already going wrong. The agent
renews with a third of the life remaining, so Cardinal can be unreachable for
two days before anybody notices and seven before the certificate is gone.

Not longer, because there is no revocation. A decommissioned machine keeps being
able to prove its name until its certificate expires. A week of that is a
bounded problem; a year of it is not.

## Consequences

**One line of `known_hosts` replaces every fingerprint anyone would have been
asked to accept.**

```
@cert-authority *.prod  ssh-ed25519 AAAAC3Nz...
```

Clients can then run `StrictHostKeyChecking=yes` and get a hard failure on an
unknown machine rather than a prompt — which is the setting everybody wants and
nobody can enable while TOFU is how trust is established.

**Withdrawing a name takes up to a renewal interval.** Removing an alias stops
it being *reissued*; the certificate already out there keeps working until it
expires. Same trade as everywhere else here, and the reason the lifetime is days
rather than months.

**The agent will not restart sshd.** It writes the certificate and a
`sshd_config.d` drop-in and stops. Reloading the daemon carrying the operator's
own session, as a side effect of a periodic refresh, is not a thing to do
automatically. sshd picks the certificate up on its next restart, and until then
the machine is exactly as it was.

**sshd_config is never edited**, only a drop-in — the same rule the sudoers
renderer follows, and for the same reason: the agent may add a fact about this
machine and may not change how the machine authenticates people. The drop-in is
validated with `sshd -T` before it is moved into place, because an invalid
sshd_config stops the daemon starting and that is discovered at the next reboot,
by which time nobody can log in to fix it.

**The certificate is checked before it is written.** Three ways it could be
wrong and make sshd refuse to start or quietly do nothing: it is a user
certificate, it is for a different key than the machine presents, or it names no
principals — which OpenSSH reads as valid for *every* hostname. All three are
refused by the agent, on top of being refused by the signer, because this is the
last place they can be caught before they are trusted.

**Cardinal's host key and the machine's SSH host key stay separate.** The first
is how the machine talks to Cardinal, the second is presented to every stranger
who connects to port 22. Signing the one Cardinal already holds would have been
simpler and would mean a compromise of either is a compromise of both.

## No Cedar decision here, on purpose

Every other issuance in Cardinal runs through a policy evaluation. This one does
not. The question a policy would answer — may this machine hold a certificate
for this name — has already been answered by somebody writing the name into the
directory, and an evaluation whose only possible input is that same fact is
ceremony rather than authorization. The issuance is recorded in the journal,
which is what an auditor actually needs.

## Verification

`make verify-host` runs a real OpenSSH client against a certificate this code
signed:

```
ssh -o StrictHostKeyChecking=yes -o BatchMode=yes ...
  → nobody@127.0.0.1: Permission denied (publickey,password).
```

Host verification happens before user authentication, so `Permission denied`
means the machine was verified and only the login failed —
`Host key verification failed` would mean the opposite. The same connection with
the authority removed from `known_hosts` produces exactly that, which is what
makes the first result mean something rather than being a client that verifies
nothing.
