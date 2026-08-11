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

## The design

The mechanism this record deferred, now designed. Nothing below is built.

### The rule that must not bend

**Filtering changes what an application is told, never what Cardinal decides.**
Cedar evaluates against the full transitive closure exactly as it does today; the
projection is applied on the way out, to the header and the claim. A person
refused access must be refused for a reason in the directory, not because an
administrator narrowed a claim — and an application must never become *more*
permitted by seeing less.

That is the one invariant worth a test of its own, because getting it wrong
would turn a disclosure control into an authorization bug.

**And the type system holds it, not a comment.** The hazard is in the shape of
the existing code: `forwardauth.go` resolves one `subject` and uses it three
times — as the policy input, in the decision log, and to write the headers. The
obvious way to add filtering is to narrow that variable straight after resolving
it, which would work, read cleanly, and silently change what Cardinal decides.

Both directions of that mistake are real:

- **Wrongly denied.** `directory-admins-may-administer` is
  `permit (principal in Cardinal::Group::"…ad11", …)`. Had Cedar seen only the
  groups an application may be told about, narrowing a projection would revoke
  administration from actual directory administrators — an operator changing a
  disclosure setting would have changed access.
- **Wrongly granted, which is worse.** A deployment writing
  `forbid (…) when { principal in Cardinal::Group::"suspended" }` would find it
  stops matching once `suspended` is filtered out, and the person is permitted.
  No shipped rule does this — the three forbids key on `deviceBound` and
  `authAgeSeconds` — but policy authored by the deployment is the entire premise,
  and this is the failure nobody notices.

So `GroupsFor` does not return `[]Group`, which would assign straight back over
`Subject.Groups`. It returns a distinct type whose field is unexported, so a
filtered set cannot be constructed outside this package and cannot be put back
into a Subject:

```go
// Projected is the subset of a subject's groups that one application is told
// about. Deliberately not []Group: the assignment that would put a filtered set
// back into the Subject the policy engine reads does not compile.
type Projected struct{ groups []Group }

func (p Projected) Names() []string { … }
func (p Projected) IDs() []string   { … }

func (s *Subject) GroupsFor(p store.GroupProjection) Projected
```

The cost is a wrapper type in a package that has none, and a conversion at each
of the two output sites. That is accepted deliberately: prose and a test are how
the rest of Cardinal's invariants are held, and this repository keeps a table of
bugs where a comment was the only thing holding a rule in place. The test stays
as well — the type stops the slip, the test states the property.

### Storage

Two tables, because there are two questions: how much does this application see,
and what extra has it been shown.

```sql
-- How much of the closure this application is told about.
--
-- A row per application rather than a nullable column, so the console can show
-- the setting and the CLI can change it without touching the entity.
CREATE TABLE application_group_projection (
    entity_id  uuid PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,
    mode       text NOT NULL CHECK (mode IN ('all', 'owned')),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid REFERENCES entities(id)
);

-- Groups an application may see that it does not own.
--
-- The escape hatch, and deliberately a list of facts rather than a pattern: a
-- wildcard would be a rule nobody could answer "which groups does this
-- application see" about without evaluating it.
CREATE TABLE application_visible_groups (
    application_id uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    group_id       uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    added_at       timestamptz NOT NULL DEFAULT now(),
    added_by       uuid REFERENCES entities(id),
    PRIMARY KEY (application_id, group_id)
);
```

The migration inserts `mode = 'all'` for every application that already exists,
which is what makes this expand-only in behaviour as well as in schema. New
applications are registered with the same, so every application behaves
identically whenever it was created.

**This was decided the other way first, and the reversal is the useful part of
this record.** New applications started `owned`, on the reasoning that an
upgrade should change nothing while anything new is narrow by default. Three
things came out of building it:

- The end-to-end suite passed locally and failed in CI. The local database had
  been backfilled to `all`; CI built the stack from nothing and got the new
  default. Both were correct and only one was being tested.
- The lab's demonstration application renders the groups it receives. Rebuilt
  against a Cardinal carrying this migration, the page a reviewer looks at reads
  `Groups: (none)` for somebody who is in several.
- It contradicted the decision above. "Unfiltered is the default until an
  application says otherwise" — and a new application had said nothing.

The failure mode is what settled it: an application created after the upgrade is
registered, reachable, permitted, and told about no groups at all. That surfaces
in the application rather than in Cardinal, and reads as a directory problem to
whoever is debugging. Meanwhile the safety it bought was smaller than it looked
— an application seeing every group is the state every deployment is already in,
not an exposure created by the act of registering one.

The cost of the uniform default is that filtering is a thing nobody turns on,
which is how a capability ends up built and never used. That is answered where
somebody is actually looking rather than by a default they cannot see:
`cardinal app groups show` says how many groups exist, how many the application
owns, and therefore how many it is being told about for no reason, and creating
an application says it is told about everything and how to narrow it.

### Resolution

`Subject.Groups` stays the full closure. Self-service, the console and policy all
need it, and a projection that reached back into resolution would make "what am I
a member of" depend on who asked.

The filter is a separate step with its own input:

```go
// store
type GroupProjection struct {
    Mode    string              // "all" or "owned"
    Visible map[uuid.UUID]bool  // owned ∪ explicitly allowed, empty when Mode is "all"
}
func (s *Store) GroupProjectionFor(ctx context.Context, applicationID uuid.UUID) (GroupProjection, error)

// claims — returns Projected, not []Group. See the invariant above.
func (s *Subject) GroupsFor(p store.GroupProjection) Projected
```

`GroupsFor` returns the closure unchanged when the mode is `all`, and otherwise
the members of `Visible`, preserving order and depth so the nearest-first
contract still holds. `Subject.GroupNames` and `GroupIDs` stay exactly as they
are and keep returning everything, because the console, self-service and the
decision log all want the closure; the projected pair live on `Projected`.

### The two consumers

**forwardAuth** already resolves the hostname to an application and holds
`app.ID`. It projects after the decision, not before:

```go
projection, err := s.store.GroupProjectionFor(ctx, app.ID)
visible := subject.GroupsFor(projection)   // Projected, not []Group
h.Set(headerGroups,   strings.Join(visible.Names(), ","))
h.Set(headerGroupIDs, strings.Join(visible.IDs(), ","))
```

The decision log keeps recording the full closure. It is Cardinal's record of
why it decided, not a copy of what the application was told, and truncating it
would make the explorer answer a different question than the one it is asked.

**OIDC** has the client's `EntityID` from `OIDCClientByID`, so the `groups` and
`group_ids` claims are built from the same projection. Nothing changes for a
client that does not request the `groups` scope, which is most of them.

> **Corrected after implementing this.** "The claims" is two places, not one.
> zitadel/oidc assembles the id_token through `SetUserinfoFromScopes` and the
> access token through `GetPrivateClaimsFromScopes`, and Cardinal issues access
> tokens as JWTs, so both carry `groups` to the relying party. The first
> implementation projected the header, userinfo and the id_token while the
> access token still carried the whole closure — caught before release, by
> writing the documentation and finding the code did not match it. The end-to-end test now asserts
> both tokens, because a projection that holds for one and not the other is not
> a projection.

**Nothing else changes.** SCIM is inbound. SSH certificate principals come from
policy rather than from group names. The console and self-service views are
Cardinal's own surfaces, not third parties.

### Administration

```sh
cardinal app groups show <application>              # mode, owned, allowed, effective
cardinal app groups mode <application> owned|all
cardinal app groups allow <application> <group>     # sight of one it does not own
cardinal app groups disallow <application> <group>
```

`show` prints the effective list, because "which groups does this application
see" is the question an operator actually has and today it has no answer.

In the console, the application detail page gains a section with the mode, the
groups it owns, the ones it has been allowed, and what the projection currently
comes to. Behind `ManageApplications`, like the rest of that page.

### What tells you it is wrong

An application in `owned` mode whose projection is empty is almost certainly a
mistake — nobody configures filtering in order to send nothing. Cardinal logs it
at the point of projection and the console shows it on the application, in the
same spirit as the startup warning about policy actions no rule mentions.

### Rollback

The schema is expand-only and the previous build ignores both tables, so an
older Cardinal serves the full closure again — the behaviour it had. That makes
rolling back safe and, for anyone relying on filtering, visibly not a no-op:
the claim widens. Worth saying out loud in the release notes rather than
discovering it.

## Status of this record

Accepted, and built. The schema, the projection, the CLI, the console and the
end-to-end tests are in the tree; where the implementation contradicted the
design, the record above says so rather than being quietly edited to match.

One claim it rests on is still untested: that common off-the-shelf relying
parties do not request the `groups` scope by default. That is marked above as an
assumption, and it stays an assumption until somebody points a real relying
party at Cardinal and looks. It affects how much this feature matters, not
whether it is correct.
