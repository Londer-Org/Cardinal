# ADR 0024: A host proves possession of a key, not knowledge of a secret

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

Until now a host was a name in the directory that policy could refer to. Nothing
stopped a different machine claiming it, and that was fine while the only
consumer was [SSH certificate issuance](0022-cardinal-issues-short-lived-credentials.md):
that decision is about the *user*, and the host name is just the resource being
named in the request.

It stops being fine the moment the host itself asks for something. Everything
Phase 4 still needs is a question asked *by* a machine:

- Which sudoers rules apply here?
- Which POSIX identities should `nss-systemd` be served?
- May this host have an X.509 certificate for this name?

Each answer is worth stealing, and each is only sound if "which host is this?"
has a trustworthy answer.

The obvious shape is a bearer token: enrol once, get a secret, send it as an
`Authorization` header forever. It is what most agent-based systems do, and it
has a specific failure that matters here. The secret sits in a file on a box —
and hosts are the machines most likely to be compromised in the first place,
since they are what the whole access-control apparatus exists to protect. Once
copied, using it is indistinguishable from the real host using it. There is no
signal to detect, only a rotation schedule to hope you beat.

Cardinal already refused this pattern once, for people: there is no password
column, and [access tokens](0018-access-tokens-are-a-weaker-credential.md) are
deliberately weaker than a passkey rather than equivalent to one. Handing
machines the credential shape rejected for humans would be inconsistent, and
inconsistent in the wrong direction.

## Decision

**A host generates a keypair, keeps the private half, and proves possession on
every request. Cardinal stores only the public half.**

Enrollment mirrors [ADR 0013](0013-enrollment-invitations.md)'s shape for
people, because the problem is the same — a credential has to reach something
that has none yet:

- A single-use token, hashed at rest, one hour to live. Shorter than a person's
  twenty-four hours, because enrolling a host is something an operator does at a
  console *now*.
- Redeeming it registers the machine's public key. The private half never
  crosses the wire, so a database read yields the ability to *recognise* a host
  and never to *be* one.
- Redemption is one statement, so two machines racing the same token cannot both
  become the same host.
- Re-enrolling retires the previous key by closing its validity range. A rebuilt
  machine gets a new key and the disk from the old one stops working.

Afterwards, each request carries:

```
Authorization: Cardinal-Host <fingerprint>:<unix seconds>:<base64 ssh.Signature>
```

over the signed string:

```
cardinal-host-v1\n<method>\n<path>\n<unix seconds>\n<fingerprint>
```

Every field is there for a reason:

| Field | Without it |
|---|---|
| version | No way to change this format later without ambiguity |
| method, path | A signature captured from one request authorises a different one |
| timestamp | Unbounded replay |
| fingerprint | A signature can be presented alongside someone else's identity |

The timestamp is bounded at ±60 seconds. **Both directions**: a clock ahead of
ours is as much of a problem as one behind, and accepting the future would let a
captured header be held until it became valid. Sixty seconds is generous for a
machine NTP has not caught up with, and the threat model already assumes working
NTP because short-lived certificates depend on it too.

`requireHost` is a separate middleware from `requireAuth`, not a branch inside
it. A host is not a person, has no session, and must never reach an endpoint
written with a person in mind. Keeping them apart means that confusion cannot
happen by forgetting a check — it would take deliberately wiring the wrong
middleware onto a route.

## Consequences

**A stolen host key is still a stolen credential.** Proof-of-possession does not
change that; it changes what an attacker must exfiltrate — the key file itself,
not a string from a log, an environment variable, a config backup, or a
`ps` listing. Disabling the host cuts it off immediately, at both redemption and
authentication.

**No nonce store, and so no replay protection within the skew window.** A
captured header can be replayed for up to sixty seconds against the same method
and path. Accepted knowingly: the alternative is a table written on every agent
request forever, and what it buys is one minute of protection on requests that
are almost all reads. Revisit if a host endpoint is ever added where replaying a
*write* would be harmful.

**Signing is implemented twice** — in the server, and in `internal/hostclient`
for `cardinal host join`, `cardinal host whoami` and eventually the agent. That
duplication is deliberate: the server must never trust a string a client hands
it. The end-to-end tests are where the two meet, and are the only thing keeping
them honest.

**The enrollment endpoint is unauthenticated**, necessarily — a machine with no
credential is what it exists to fix. The token carries the whole authorization,
so it is rate limited like every other unauthenticated credential path, and
refusals do not distinguish expired from spent from revoked from never-existed.

**Host paths are exempt from CSRF**, for the same reason the OIDC protocol
endpoints are: neither client has a cookie jar, so there is no ambient authority
to abuse. The exemption is a closed list rather than a `/api/hosts/` prefix,
because the administrator-facing host management endpoints will live under that
prefix too and must keep their protection.

## What this does not decide

Whether the agent holds a *second* credential for high-value operations. Today
one key answers everything a host may ask. If asking for an X.509 certificate
for an arbitrary name turns out to warrant more than the same key that fetches
sudoers rules, that is a separate decision and this format has a version field
in front of it.
