# ADR 0019: In-app authorization, if it happens, is a local decision

- **Status:** **Proposed** — design only. Nothing here is built, and the open
  questions at the end are genuinely open.
- **Date:** 2026-08-06

## Context

Cardinal answers four questions today: may you reach this URL, may you log into
this host and as whom, what may you run as root there, and may you change this
directory object. What an application permits *inside itself* — may this person
delete this record, see this customer, approve this payment — is the
application's own business, and [ADR 0002](0002-identity-is-an-immutable-uuid.md)
onwards never claimed otherwise.

There is a real case for extending that. The policy an application enforces
today is written in the application, in its own idiom, deployed on its own
cadence, and reviewable only by reading its source — which is the situation
Cardinal was built to end for three other systems. Bringing it under Cedar would
mean one language, one review process, and a decision explorer that can answer
"why was I denied?" inside applications too.

The reason not to do it naively is arithmetic. An application asking Cardinal
about every action turns a function call into a network round trip, multiplies
request volume by however many checks a page performs, and makes Cardinal a
hard dependency of every action rather than of sign-in. Cardinal's own plan
treats "the identity provider is down, so nothing works" as a phase-0 constraint
and solves it for hosts by *not* asking at action time: SSH authorizes at
certificate issuance, and a host keeps working through a full outage.

Any design that fails that test should be rejected on those grounds alone.

## Decision (proposed)

**Decisions are evaluated where the action happens, never over the network.**

The component that does it already exists in the plan. `cardinal-agent` is
specified for Phase 4 to cache policy on a host, render sudoers from it, and
keep working while Cardinal is unreachable. An application needs precisely the
same thing with a different output: a decision instead of a sudoers file.

```
    Cardinal ──(policy set + the subject's memberships)──▶ cardinal-agent
                                                             │ localhost
    application ──"may alonfils Delete Ioc::\"123\"?"────────▶│ (unix socket)
                ◀──allow/deny + the rule that decided ────────┘
```

The application talks to something on its own machine or in its own pod. No
round trip leaves the host, Cardinal being unavailable does not stop decisions,
and the policy is still one reviewed, versioned artefact in git.

### Why a sidecar rather than a library

The obvious alternative is to embed Cedar in each application. Cedar's
implementations are Rust, a Go port (which Cardinal already uses), Java, and
WASM — so "a package for npm, a gem, a crate" would mean maintaining bindings,
each with its own build, its own release cadence and its own opportunity to
disagree with the others about what a policy means. Two implementations of an
authorization engine that disagree is a security bug that presents as a support
ticket.

A sidecar inverts that. The engine is one Go binary Cardinal already knows how
to build, sign and ship; the *package* in each language becomes a thin client
over a local socket, which is a few hundred lines and nearly impossible to get
subtly wrong:

```ts
const cardinal = new Cardinal()                 // finds the socket, no config
if (await cardinal.can("Delete", ioc)) { … }    // sub-millisecond, local
```

That is the shape worth having. It also means adding a language is a weekend
rather than a project.

### Why the application still supplies its own data

"May Arthur delete IOC 123" depends on facts about IOC 123 — who owns it, which
customer it belongs to — which live in the application's database and should
stay there. Cardinal must not mirror application data, and an application must
not ship its records to Cardinal to get an answer about them.

So the decision call carries the resource's attributes, and the policy is
evaluated against them locally. This is the second reason the answer cannot be a
remote call: a remote PDP would need either a copy of the application's data or
a payload containing it on every request.

### Optional, by construction

An application that ignores all of this works exactly as it does today: identity
headers with a group list, and it decides for itself. Nothing in Cardinal
requires the agent, no endpoint changes, and there is no degraded mode for not
adopting it. That is a requirement rather than an aspiration — an authorization
system that quietly becomes mandatory is one nobody can evaluate before
committing to it.

## Consequences

**Revocation becomes eventually consistent, and that has to be stated as a
number.** A cached policy and a cached membership mean a grant withdrawn in
Cardinal is still honoured locally for some window. The roadmap already carries
this as a known gap for the host agent; extending the agent to applications
extends the gap. Two mitigations, neither free: the window is short and
configurable, and policy can mark an action as requiring a fresh decision, which
falls back to a synchronous call and accepts the coupling *for that action
only*. "Delete customer" can afford 50ms and cannot afford stale.

**Policy updates stop needing a deploy.** `cardinal policy activate <version>`
reaches every agent, so changing who may do what is a Cardinal operation rather
than a release of every application. That is the operational win, and it is the
same mechanism as the host policy — one thing for an administrator to learn, not
two.

**Shadow mode applies here too.** Phase 4 already plans to run the agent
alongside SSSD logging what it *would* have decided, and diffing until they
agree. An application adopting Cardinal authorization should be able to do
exactly the same against its existing checks before enforcing anything. That is
what makes adoption reversible, and it is why this should reuse the agent rather
than invent a parallel path.

## Open questions

Written down because they are not answered, and building before answering them
would be the mistake:

1. **How do memberships reach the agent?** Policy is small and public-ish;
   membership is large and sensitive. Does an agent hold the whole directory
   (unacceptable for a third-party application), only the subjects that have
   presented themselves (leaks who uses what, via timing), or is membership
   carried in the request from the identity headers already present?
   *Instinct: the last one. The proxy already sends group identifiers, so the
   agent may need no directory data at all — which would remove this entire
   class of problem.*

2. **Who declares the application's schema?** Cedar validates against a schema
   of actions and resource types. If the application declares it, Cardinal is
   accepting a contract from something it does not control; if Cardinal declares
   it, every application change waits on a directory change.

3. **Is the sidecar acceptable outside Kubernetes?** In a pod it is a container
   and nobody blinks. On a bare VM running one Rails application it is another
   process to supervise, and that may be enough friction to lose the adoption
   this is supposed to make easy.

4. **What happens on a cold start?** An agent with no cached policy must fail
   closed, which means an application restarting during a Cardinal outage cannot
   authorize anything. For hosts the SSH design sidesteps this because
   certificates are already issued. There is no equivalent sidestep here.

5. **Does this earn its keep against the simplest alternative?** Roles resolved
   at sign-in and carried in the token cover a large fraction of real
   applications, need no agent, no socket and no package, and go stale only as
   fast as the token. The honest question is what proportion of real policy
   genuinely needs per-resource evaluation — and that is worth measuring on one
   real application before any of this is built.
