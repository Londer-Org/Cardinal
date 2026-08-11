# ADR 0033: The CLI signs in rather than holding the database

- **Status:** Proposed
- **Date:** 2026-08-11
- **Relates to:** [ADR 0008](0008-single-binary-go-and-embedded-react.md), whose
  API-first claim this makes true rather than aspirational.
  [ADR 0018](0018-access-tokens-are-a-weaker-credential.md) is the constraint the
  sign-in flow exists to respect.

## Context

`cardinal` is a PostgreSQL client. It takes `-dsn`, connects to the database and
issues statements. Three consequences, none of them intended:

- **No policy.** Cedar answers questions about a principal, and there is no
  authenticated principal on that path — only a database credential. A policy
  set that refuses somebody administration refuses them nothing here.
- **No actor.** Entity creation records none; a grant records the member as its
  own granter, so `cardinal grant engineers alice` says alice granted alice.
- **Only from the database host.** Which is a machine nobody logs into except
  at setup, for debugging, or as root — a strange place for the primary
  administrative interface to live.

The last one is the tell. An interface used almost exclusively by whoever
already has root is not an interface, it is a recovery tool. It should be sized
like one.

### What already exists, and where it stops

`cardinal ssh` is already an authenticated API client, and its design is the one
to build on. A terminal cannot perform a WebAuthn ceremony, so it borrows one:
the person completes it in the console, and the terminal receives a session that
**inherits** what that ceremony proved. Not a weaker credential — an access
token is not device-bound, so policy correctly refuses it an SSH certificate,
and making tokens device-bound would put a credential reaching every machine in
the fleet into a file with a ninety-day life.

The verifier never leaves the terminal. What travels through the browser is a
hash on the way out and a single-use code on the way back, and neither is worth
anything without the other.

**Where it stops is the browser.** The terminal opens a loopback listener and
asks the console to redirect there when approval happens. Measured against the
example stack rather than read off the source:

```
approve this terminal at:

  https://id.cardinal.test:8443/cli-login
    ?callback=http%3A%2F%2F127.0.0.1%3A33155%2Fcallback&state=…&verifier_hash=…
```

`127.0.0.1:33155` is loopback **on the machine running the CLI**. Open that URL
in a browser anywhere else — your laptop, while the CLI runs on a server you are
SSH'd into — and the approval redirects to *that machine's* loopback, where
nothing is listening. The terminal waits two minutes and gives up.

So the current flow does not require a browser to exist on the machine. It
requires the browser and the CLI to **share a loopback interface**, which is a
stronger and less obvious condition, and it is false in the most ordinary case
there is: administering a server over SSH.

## Decision

### 1. Two kinds of command, and a command is exactly one of them

| | Client commands | Bootstrap commands |
|---|---|---|
| Reaches | the HTTP API | PostgreSQL, via `-dsn` |
| Authenticates as | a person, with a passkey | nobody; the connection string is the authority |
| Governed by policy | yes | no |
| Actor in the journal | the person | none, and it says so |
| Which | everything else | `migrate`, `init`, `invite`, `redact` |

**No command appears in both columns.** The alternative — one command with a
`-dsn` fallback — means two implementations of `grant` that must agree forever,
and the one nobody looks at is the one that bypasses policy. Running a client
command with `-dsn` is an error that says to sign in, not a quiet second path.

Bootstrap stays deliberately small, and every entry earns its place by being
needed when nobody can sign in:

- `migrate` and `init` run before any account exists.
- `invite` is the recovery path when every administrator is locked out. This is
  already the case and is already documented: it is why the offline break-glass
  key was removed ([ADR 0014](0014-break-glass-removed.md)).
- `redact` is irreversible and should require somebody to have gone to the
  machine.

Everything else — grants, groups, hosts, applications, policy, tokens, SSF,
mail, certificates — becomes a client command.

### 2. Sign-in does not assume the browser is here

Two flows, both ending in the same inherited session. The difference is only how
approval gets back to the terminal.

**Loopback** — approval is redirected to a listener on this machine. What exists
today. Requires a browser that can reach this machine's loopback.

**Device code** — the terminal asks the server for a pair: a `device_code` it
keeps, and a short `user_code` a human can read out loud. It prints the code and
a URL, then polls. The person opens that URL on **whatever device has a
browser** — a laptop, a phone — signs in, sees which terminal is asking, and
approves. RFC 8628 in shape; the existing exchange endpoint already takes a code
and a verifier, so most of it is present.

```
$ cardinal grant engineers alonfils -for 72h
  no browser here, so approve this terminal elsewhere:

    https://id.example.com/cli-login    code: BXFD-7KQN

  waiting…
```

**Which one runs is chosen, and said out loud.** The CLI prefers loopback when it
can open a browser here and is not in an SSH session, and device code otherwise.
`--auth loopback|device` forces either. The heuristic is allowed to be a
heuristic because it is not a security decision — both flows end in the same
session, and getting it wrong costs a fallback, not a credential.

They fail differently, which is the reason for keeping both rather than
standardising on the one that always works:

- **Loopback is phishing-resistant.** Approval is delivered to the machine that
  asked. Nobody can talk you into approving *their* terminal, because the
  redirect would not reach them.
- **Device code is phishable**, and this is the known weakness of the pattern:
  an attacker starts a flow, sends you the code, and you approve their session.
  Two things blunt it. The ninety-second window already chosen for CLI
  authorizations means a phishing attempt has to land inside a minute and a
  half. And the approval screen must show what is being approved — the
  requesting host and address, and a plain sentence that approving a code
  somebody sent you hands them your session.

So: loopback where it works, device code where it must, and never a silent
switch between them.

### 3. The credential is a session, and staleness is already handled

The terminal caches what it receives, in `$XDG_CONFIG_HOME/cardinal/`, mode
`0600`, keyed by server URL so two deployments do not collide.

A cached session is a credential at rest and there is no pretending otherwise.
What makes it acceptable is that it is the *same* credential a browser keeps in
its cookie jar, with the same lifetime, and that Cedar already refuses stale
sessions the privileged actions — freshness and device-binding are policy
inputs today. A stolen cache therefore cannot approve a recovery, issue an SSH
certificate, or administer the directory without a new ceremony. **The CLI needs
no new rule for this; it needs to handle the API saying "re-authenticate" by
running the flow again.**

Two consequences to build:

- `CLISessionTTL` is ten minutes, chosen for `cardinal ssh`, where the session
  exists to fetch a certificate and the certificate carries its own expiry.
  Ten minutes is wrong for an administrative session. It becomes the session
  configuration's idle and absolute limits, like any other session.
- **A CLI session appears in the console's session list**, labelled, and is
  revocable there. The `sessions` table already carries `user_agent` and
  `client_ip`; this is a matter of setting them honestly and showing them.

`cardinal logout` revokes server-side and removes the file.

### 4. Automation is a token, and cannot be more

A CI job has no human and no browser anywhere, and that is what
[access tokens](0018-access-tokens-are-a-weaker-credential.md) are for: bounded,
scoped, revocable, and never device-bound. Client commands accept one.

It follows that automation **cannot** perform device-bound actions — no SSH
certificates, no administration. That is not a gap to close later. A credential
in a CI variable that could administer the directory is the thing the whole
model exists to prevent, and the correct answer to "our pipeline needs to grant
memberships" is that it should not.

### 5. The layout keeps the two apart, and a test keeps it that way

```
cmd/cardinal/
    main.go              dispatch, global flags, exit codes — and nothing else
    usage.go             the help text

internal/cli/
    cli.go               Command, the registry, the run context
    api/                 typed client for the admin API, one file per group
    auth/
        flow.go          choosing between the two, and saying which
        loopback.go      the listener and the redirect
        device.go        the code, and the polling
        cache.go         the credential on disk
    command/             one file per group: directory, policy, app, host, ssf, mail…
    bootstrap/           migrate, init, invite, redact — the DSN four
    render/              tables, JSON, terminal detection
```

`cmd/cardinal` becomes a dispatcher. Today it is twenty-four files that each
open a store, parse flags and print — three unrelated jobs mixed per file, which
is why adding an output format or an authentication mode touches all of them.

**One boundary, enforced rather than intended:** nothing under
`internal/cli/command/` may import `internal/store`. An import-boundary test in
`internal/lint` asserts it, for the same reason the expand-only rule is a test —
the failure is silent, and a single `store.Open` in a client command quietly
restores everything this ADR exists to remove.

The agent is out of scope. `cardinal-agent` is a host daemon that serves POSIX
identity over varlink, renders sudoers and holds a host credential. It is not an
administrative client and must not become one.

## What must not bend

Four things. If the implementation makes any of them awkward, the implementation
is wrong.

1. **The CLI may never do something the console cannot.** The moment it can,
   "administered by policy" becomes "administered by policy unless you use the
   other one", and the audit story goes with it.
2. **Bootstrap commands stay on the list above.** Every addition is a command
   that escapes policy. Adding one is an ADR, not a patch.
3. **No operation gets two implementations.** One path per command, chosen by
   what the command is, never at runtime.
4. **A device-bound session must not become a long-lived file.** Whatever the
   cache holds expires like a session. If a future convenience wants a
   long-lived CLI credential, it is an access token and it is not device-bound.

## What this breaks

Every existing script calling `cardinal grant`, `cardinal app register` or
anything else over `-dsn` stops working, and must either sign in or carry a
token. Pre-1.0 with no supported upgrade path between versions, so this is
allowed — but it is the largest behavioural change the project has made, and it
should land in one release with the changelog saying so plainly rather than
arriving a command at a time.

The failure has to be a sentence, not a stack trace: running a client command
with `-dsn` should say that this command signs in, and how.

## What has to exist first

The admin API already covers users, groups, membership, hosts, applications,
group projection, policy rules and activation, invitations, tokens, mail, SSF,
decisions, recoveries and audit verification. Missing, and needed before the
matching commands can move:

- `policy publish` — versions can be activated over the API but not created.
- The SSH and X.509 authority commands: `ca init`, `list`, `trust`, `rotate`.
- `posix assign`, `set`, `adopt`, and the shadow-report form of `adopt`.
- `-at` on the point-in-time queries: `members`, `memberships`, `history`.
- `audit verify` exists; the journal listing it reads does too.

Each is a small addition to a surface that already exists, and each is
independently reviewable. The order that keeps the tree working is: add the
endpoint, move the command, remove its store access, and let the boundary test
prove the last step.

## Alternatives considered

**Leave the CLI on the database and fix attribution with a flag.** `-as <login>`
records who says they are running it. Cheaper, and it makes the journal *look*
right while remaining an assertion by whoever holds the database credential —
attribution nobody can check is worse than none, because it reads as evidence.
It stays as the fallback if this ADR is not taken.

**Device code only, dropping loopback.** One flow, works everywhere, less code.
Rejected because it would remove the phishing-resistant option in the case where
it is available, in exchange for deleting a listener that already works.

**Long-lived device-bound CLI credential.** Rejected on the same ground ADR 0018
rejects device-bound tokens: a credential that reaches every machine in the
fleet does not belong in a file.

**Make the console the only administrative surface.** Honest, and wrong. "Why
was this denied" is asked during an incident from a terminal, possibly because
the console is what is unreachable — which is why `cardinal decisions` exists
in the first place.

## Status of this record

Proposed, and nothing is built. The claim it rests on — that the loopback flow
fails when the browser is elsewhere — was measured against the example stack and
is quoted above. The rest is design.

The part most worth arguing with is §2: keeping two sign-in flows costs a
heuristic and a second code path, and a reviewer who would rather have one
should say so before this is built rather than after.
