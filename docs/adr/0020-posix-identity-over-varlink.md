# ADR 0020: POSIX identity is served over systemd's varlink interface

- **Status:** Accepted — the spike this was waiting on has been run.
- **Date:** 2026-08-06
- **Resolves:** the `systemd-userdbd spike` question in Phase 4.

## Context

Replacing SSSD means something on the host has to answer "who is user 64000,
what is their home directory, which groups are they in". Historically that meant
`nss_ldap`: a shared library loaded into **every process on the system** that
resolves a name — `sshd`, `sudo`, `ls -l`, anything. Writing one means writing C
that runs everywhere, cannot block for long, must be thread-safe, and takes the
whole process down with it if it faults.

The plan noted `systemd-userdbd` as the modern alternative and flagged it as
**unvalidated**, with "a small NSS module" as the fallback — while being honest
that the fallback is a materially different and much worse project.

## The spike

Run against systemd 255 on Ubuntu 24.04, in a container so the test needed no
privileged access to the host.

**The interface is three methods.** `varlinkctl introspect` on the running
`io.systemd.DynamicUser` service gives the whole contract:

```
method GetUserRecord(uid: ?int, userName: ?string, service: string)
    -> (record: object, incomplete: ?bool)
method GetGroupRecord(gid: ?int, groupName: ?string, service: string)
    -> (record: object, incomplete: ?bool)
method GetMemberships(userName: ?string, groupName: ?string, service: string)
    -> (userName: string, groupName: string)

error NoRecordFound()   error BadService()   error ServiceNotAvailable()
error ConflictingRecordNotFound()   error EnumerationNotSupported()
```

**The protocol is NUL-terminated JSON over a Unix socket.** That is the entire
framing. A prototype implementing all three methods came to roughly two hundred
lines of Go with **no imports beyond the standard library** — no varlink
library, no cgo, nothing added to the dependency surface.

**It works end to end.** With the socket at
`/run/systemd/userdb/io.systemd.Cardinal` and `nss-systemd` in `nsswitch.conf`:

```
$ getent passwd cardinaltest
cardinaltest:x:64000:64000:Cardinal Spike User:/home/cardinaltest:/bin/bash
$ getent passwd 64000
cardinaltest:x:64000:64000:Cardinal Spike User:/home/cardinaltest:/bin/bash
$ id cardinaltest
uid=64000(cardinaltest) gid=64000(cardinaltest) groups=64000(cardinaltest)
```

Lookup by name, lookup by uid, group lookup, and `id` — all resolving a user
that exists only inside a Go process. Unknown names correctly return nothing,
and a mismatched `service` field is refused with `BadService`.

## Decision

`cardinal-agent` serves POSIX identity over `io.systemd.UserDatabase`. The NSS
module fallback is **not needed and is removed from the plan**.

## Consequences

**No C, and no code inside other people's processes.** The agent is an ordinary
Go service that other processes reach over a socket. An agent that crashes stops
answering; it does not take `sshd` down with it. That difference is most of why
this was worth validating before committing.

**The service name is the socket name.** `nss-systemd` derives which service to
ask from the filename in `/run/systemd/userdb/`, and passes it back in the
`service` field — which the provider must check and refuse when it does not
match. The prototype refuses with `BadService`, and the real one must too, or
the agent will answer questions addressed to somebody else.

**Ordering in `nsswitch.conf` is a migration decision, not a detail.** The test
machine reads `passwd: files systemd sss`, so `nss-systemd` is consulted
*before* SSSD. During a migration both will be present, and whichever comes
first wins for any name they both know. Shadow mode has to account for that:
running the agent alongside SSSD to compare answers is only meaningful if the
agent is not already overriding them.

**Enumeration needs a decision.** Called with neither a name nor an id, a
provider is expected to return every record — which for a directory of any size
is a poor idea, and the interface offers `EnumerationNotSupported` for exactly
this. `getent passwd` with no argument will then not list Cardinal users, which
is the correct trade and worth documenting rather than discovering.

**Availability is unchanged by this.** The agent answers from its cache, so
identity resolution survives a Cardinal outage — the same property the SSH
certificate design has, for the same reason.
