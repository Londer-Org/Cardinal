# 32. An application sees the groups it owns, not the whole directory

**Status:** proposed
**Date:** 2026-08-10

## Context

Cardinal projects one subject into four consumers, and two of them carry group
membership: the `X-Auth-Request-Groups` header a forwardAuth application
receives, and the `groups` claim in an OIDC ID token. Both are built from
`claims.Subject.GroupNames()`, which returns the **transitive closure** — every
group the person belongs to, directly or by inheritance, with no reference to
who is asking.

So every application a person signs into learns their entire position in the
organisation. An internal wiki behind the proxy is told that somebody is in
`hr-investigations`. A relying party set up by a contractor is told about
`project-acquisition-x`. Neither needed to know, and neither was ever offered a
way to not be told.

This project already made the argument, in a different channel. The comment on
`EnabledStreamsFor` in `internal/store/ssf.go` says a stream that receives
everything "tells an application about people it has never seen, which is a
directory leak dressed as a feature." A claim that carries every group is that
same leak, and it is delivered on every request rather than only on revocation.

There is a second cost, and it arrives as an outage rather than a disclosure.
The payload grows with the size of the directory, not with the needs of the
application. A person in a few hundred groups produces a header that meets a
proxy's limit — 8KB is the common default — and an ID token that can exceed
what a client is willing to store in a cookie. Nothing warns first.

### The distinction already exists in the schema

[Migration 0013](../schema.md) is titled "system groups, and groups that belong
to an application", and it separates exactly the two kinds:

- `entities.system` marks a group whose membership confers authority *inside*
  Cardinal — `directory-admins`, `user-admins`, `security-admins`. Granting one
  is `AdministerDirectory` rather than `ManageUsers`, because otherwise a user
  admin could grant themselves the broader tier.
- `entities.owner_id` records the application a group exists for. Its own
  comment: "An application registered as `aura` wants `aura-users` and
  `aura-admins`, which Cardinal delivers in the groups claim and never
  interprets."

A constraint forbids a system group from being owned, because the two kinds are
the point.

What the column does not do is reach the claim. The migration says so plainly —
"it still appears in the groups claim like any other" — and describes itself as
"organisational only". The data model answers the question; the projection never
asks it.

### Most consumers do not want the groups anyway

Worth stating, because it bounds the blast radius of changing this. The `groups`
claim is only emitted when the relying party **requests the `groups` scope** —
it is a case in a switch over requested scopes in
`internal/server/oidcprovider/storage.go`. A client that does not ask never
receives it.

The claim-side behaviour above was read from Cardinal's own code. The rest of
this paragraph is not: common off-the-shelf applications — GitLab, Redmine and
their kind — authenticate a person over OIDC and then use their own membership
model, with group synchronisation from a claim as opt-in configuration rather
than the default path. That matches how those products are generally deployed
and it has **not** been tested against them here, so it is the assumption this
decision rests on rather than an observation. It is worth confirming against one
real relying party before this moves from proposed to accepted, because if a
common product does request `groups` and key on the full list, the opt-in
default below is doing more work than it appears to.

The same shape applies to forwardAuth: an application behind the proxy is
usually deciding "is this person signed in", and reads the groups header only if
it has its own reason to.

So the groups projection is, for most consumers, data they did not request,
cannot use, and would rather not be liable for.

## Decision

**An application receives the groups that concern it: the ones it owns, plus any
it has been explicitly granted sight of. Not the closure.**

Three parts, and the third is what keeps this from breaking deployments.

**Owned groups are the default set.** `owner_id` already names the application a
group exists for, so `aura` receives `aura-users` and `aura-admins` and nothing
else. This needs no new concept, no new administration surface, and no change to
how groups are created.

**System groups are never projected to an application.** Membership of
`directory-admins` is authority inside Cardinal and is nobody else's business;
an application deciding its own access on the strength of it is reading a
Cardinal internal as though it were an application role. The constraint that a
system group cannot be owned makes this fall out of the rule above rather than
needing a second one.

**Filtering is opt-in per application, and unfiltered is the default until an
application says otherwise.** Anything currently matching on a group name it can
see today would silently stop matching, and silent is the failure mode this
project keeps producing. An application declares that it wants the filtered
projection; until it does, it gets what it gets now.

### What is deliberately not decided here

**Roles are not being added.** An application-scoped role type was considered and
rejected for now: fine-grained roles reproduce the size problem one level down —
`invoices:read`, `invoices:write`, `reports:export` accumulate until the claim
meets the same limit — and adding a second authorization vocabulary that hits the
same wall is not progress. `directory.TypeRole` exists as a declared constant and
is used nowhere; it stays that way. If fine-grained authorization is wanted
later, the argument to have is whether an application should *ask* Cedar rather
than be handed an answer, which is what the forwardAuth, SSH and sudo decision
points already do and which does not grow a token at all.

**The set an application may see is explicit, never inferred.** Deriving it from
which groups appear in the Cedar rules governing that application would be
elegant and wrong: editing a policy rule would silently change what an
application is told about a person. A claim that changes as a side effect of a
policy edit is the shape of bug this repository has a table for.

## Consequences

An application learns what concerns it. The wiki is no longer told about
`hr-investigations`, and the payload is bounded by that application's own groups
rather than by the size of the directory — which removes the header-limit
failure as a side effect rather than as a feature.

Off-the-shelf applications are unaffected in what they can do. They receive
group *names* exactly as before, in the same claim, with the same meaning —
there are simply fewer of them. Nothing has to be taught a new contract, which
is what makes this safe for a deployment running both bought and built software.

An application that genuinely needs to see a group it does not own has to say so,
and that becomes a reviewable fact about the integration rather than an accident
of the projection.

The cost is a new thing to get wrong: an application that wants filtering and
forgets to be granted sight of a group it depends on will find people mysteriously
unauthorized. That failure is at least loud at the application, and the console
should show which groups an application is projected — a question that today has
no answer because it has no meaningful one.

## Status of this record

Proposed rather than accepted: the decision is argued and nothing is built. The
opt-in mechanism — where an application declares it wants filtering, and how
sight of a group it does not own is granted — is the part that needs designing
before this is implemented, and it should be designed against the console and the
CLI at the same time so administering it is not an afterthought.
