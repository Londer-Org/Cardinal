# First run

Everything below works today. It takes about ten minutes, and the last section
is the part nobody has done yet — a real passkey against a real browser.

## Upgrading

Cardinal evaluates a fixed set of Cedar actions, and new ones arrive with new
features. Cedar is default-deny, so an action your active policy set never
mentions is refused for everyone — which looks like a bug rather than a policy:
an administrator gets "you are not a member of directory-admins" while being a
member of directory-admins.

The server warns about exactly this at startup, naming the actions:

```
WARN the active policy set never mentions some actions, so they will be
     refused for everyone — republish policies/cardinal.cedar if this
     deployment was upgraded  actions=[ManageApplications ManageUsers]
```

The fix is to merge the new rules into your policy set and republish:

```sh
cardinal policy publish policies/cardinal.cedar -activate
```

## 0. Starting over

If the development database fills up with experiments:

```sh
make reset            # or: make reset ADMIN=you
```

It destroys everything in the dev database, reapplies migrations, publishes the
default policy, creates you as an administrator, and prints an enrollment link.
It asks before doing any of that.

Tests never need it. The store suite gets a fresh container per run through
testcontainers, and the end-to-end stack has its own database in
`examples/compose.yml` — so `go test ./...` touches neither this database nor
anything in it.

## 1. Database and build

```sh
make up                 # PostgreSQL 19 beta 2 on port 5433
make migrate
make release            # builds the React UI and embeds it in the binary
```

Then set yourself up in one step:

```sh
./bin/cardinal init alonfils -display "Arthur Lonfils"
```

It publishes the default policy, creates the account, grants it
`directory-admins`, and prints a single-use enrollment link. It refuses on a
directory that already has administrators — `init` is for a fresh deployment,
not a way to mint one on a live system.

## 2. Configuration

```sh
cp cardinal.example.toml cardinal.toml
```

Edit it: for local testing set

```toml
[server]
listen = "127.0.0.1:8099"

[webauthn]
rp_id = "localhost"
origins = ["http://localhost:8099"]
```

`rp_id = "localhost"` matters. Browsers treat `http://localhost` as a secure
context, so WebAuthn works there without TLS — which is true of no other
hostname.

That works here because everything is on one host, and it stops working the
moment anything is not. Note there is no `cookie_domain` above: the session
cookie is host-only, which is all a single host needs. Scoping it to a parent
domain — what forwardAuth single sign-on across `id.` and `app.` requires —
cannot be done from `localhost`, because browsers discard a cookie whose
`Domain` is a public suffix and `localhost` is one.

So the two arrangements really are different, and the example stack in
`examples/` is over HTTPS on `*.cardinal.test` for that reason rather than out
of caution. Passkeys need a secure context; SSO needs a parent-domain cookie;
no plain-http origin gives both.

There is no emergency key to generate. Cardinal used to ship an offline
break-glass keypair; [ADR 0014](adr/0014-break-glass-removed.md) removed it,
because the CLI already performed the same recovery and doing it twice meant two
credentials of last resort instead of one.

## 3. The directory, from the CLI

This is Phase 0, and all of it works:

```sh
./bin/cardinal user create alonfils -display "Arthur Lonfils"
./bin/cardinal user create contractor
./bin/cardinal group create engineers
./bin/cardinal group create prod-access

# Nested groups: engineers are, transitively, production
./bin/cardinal grant prod-access engineers -reason "engineering owns production"
./bin/cardinal grant engineers alonfils   -reason "employee"

# The interesting one: time-boxed access
./bin/cardinal grant prod-access contractor -for 72h -reason "incident #42"
```

Then look at what that bought you:

```sh
./bin/cardinal memberships alonfils     # prod-access, inherited, depth 2
./bin/cardinal members prod-access
./bin/cardinal revoke prod-access contractor
./bin/cardinal history prod-access contractor
```

That last command is the point of the whole temporal model. The contractor's
access is gone, but the record of who granted it, when, and *why* survived the
revocation. A boolean membership model destroys that.

Point-in-time queries:

```sh
./bin/cardinal members prod-access -at 2026-08-04T12:00:00Z
```

And the audit chain:

```sh
./bin/cardinal audit verify
make restore-drill      # back up, restore, verify the chain survived
```

## 4. Erasure

```sh
./bin/cardinal redact user contractor
./bin/cardinal list -all      # name is tombstoned
./bin/cardinal audit verify   # chain still intact
```

History survives; attribution does not. That is the resolution of append-only
audit versus GDPR Article 17 (ADR 0010).

## 5. The browser — the part that needs a human

```sh
./bin/cardinal serve -config cardinal.toml -dev
```

Open <http://localhost:8099>.

Enrolling a passkey needs a session, and getting a session needs a passkey.
Enrollment invitations break that circle ([ADR 0013](adr/0013-enrollment-invitations.md)):
an administrator issues a link, and the holder registers their own credential.
Cardinal used to solve it with an offline break-glass key instead, which is
gone ([ADR 0014](adr/0014-break-glass-removed.md)).

```sh
./bin/cardinal invite alonfils -config cardinal.toml
```

1. Open the link it prints. It names the account, so you can see whose it is.
2. Fill in your name and email — this is where the account stops being blank,
   and what every connected application will see.
3. Name the device and click **Register a passkey**. Tap your key.
4. Sign in with the passkey you just made. No username field: your authenticator
   offers the account, so there is nothing to enumerate.
5. Add a second passkey from **Your details → Passkeys**. The warning banner
   clears at two.
6. Generate recovery codes.

The link is single use — open it twice and the second attempt refuses, with the
same message an expired or made-up link gets.

### Becoming an administrator

Administering the directory is a Cedar decision like everything else (ADR 0012),
so it needs a grant rather than a flag. The group is created by migration and
starts empty — a migration that made the first account an administrator would
be a backdoor with a changelog entry:

```sh
./bin/cardinal grant directory-admins alonfils -reason "founding admin"
```

Sign in again with your passkey and an **Applications** tab appears, where
relying parties can be registered, inspected and retired.

Two things will refuse you, both deliberately:

- **A synced passkey is not enough.** Administration needs a device-bound
  credential — a hardware key, not one living in a cloud account.
- **A session older than five minutes is not enough.** The section stays where
  it is and a dialog asks for your key. Tap it and the page fills in — your
  session is kept, only the key is re-proved.

Sessions themselves slide: using Cardinal pushes the idle window forward, so
working through a morning does not sign you out halfway. An absolute cap of
seven days is never extended, so everybody re-authenticates eventually — that
cap is what stops a stolen session cookie from lasting indefinitely just because
somebody keeps using it.

### Deciding who may use which application

By default every signed-in user may sign in to every registered application —
Cedar is default-deny, so shipping no rule would have refused everyone
everything. Narrow it by editing `policies/cardinal.cedar`:

```cedar
@id("meridian-is-for-analysts")
permit (
    principal in Cardinal::Group::"<analysts-group-uuid>",
    action == Cardinal::Action::"AccessApplication",
    resource == Cardinal::Application::"meridian"
);
```

Then `cardinal policy publish policies/cardinal.cedar -activate` and restart.
Someone outside the group now gets a plain "no access to Meridian" screen naming
the rule, instead of a sign-in that appears to work and then stops.

Each refusal names the policy that produced it, in the response and in
**Access → decisions**. That is the demo worth showing someone: neither FreeIPA
nor Keycloak can tell you *which rule* denied you.

### If a link goes astray

Issue another. Re-issuing supersedes the outstanding one, so the first stops
working immediately — from the console, on the person's row under **Enrollment**,
or with `cardinal invite <login>`. `cardinal invite revoke <login>` withdraws one
without issuing a replacement.

That only applies to an account with no passkeys. Once someone is enrolled, a
new link would restore access rather than grant it, which is the next section.

### Recovering an account

Issuing an enrollment link for an account that *already* has passkeys is account
takeover by shape — open the link, register a credential, and you are that
person. So it takes two administrators (ADR 0015):

```
POST /api/recoveries              {"login": "jdoe", "reason": "lost both keys"}
POST /api/recoveries/jdoe/approve  ← a different administrator
```

The second approval issues the link. `cardinal invite jdoe` refuses an enrolled
account and says so. The escape hatch is unchanged: on the host, with database
access, `cardinal invite` still works — that is already the credential of last
resort, and no API rule changes it.

### Adding a second person

This is the part that had no safe answer until ADR 0013. Break-glass is the
emergency key — it can assume *any* account — so it is not an onboarding tool.
An invitation is:

```sh
./bin/cardinal user create jdoe
./bin/cardinal invite jdoe -config cardinal.toml
```

The link goes to stdout and everything explanatory to stderr, so it pipes
cleanly into a message. Send it however you like: it is single use, expires in
24 hours, grants no session, cannot administer anything, and lets the holder
register exactly one passkey on that one account. `cardinal invite revoke jdoe`
kills it; issuing another supersedes the first.

Opening it shows whose account it is, takes their name and email, and registers
their passkey. Then they sign in with the key they just made — which proves it
works while they are still at the screen.

**Watch for:** the link stops working the moment it is used. Open it twice and
the second attempt should refuse, with the same message an expired or made-up
link gets, because telling the holder which would answer "does this account
exist?" for anyone willing to guess.

## What to look for

- The server logs `BREAK-GLASS SESSION OPENED` at error level. That is
  deliberate — it should page someone.
- Revoking your only passkey is refused, because that would be a lockout.
- A synced passkey is badged *Synced*; a hardware key, *Device-bound*. Only the
  latter can satisfy the highest assurance level, which is why policy will be
  able to demand it.

## 6. Authorization, through a real proxy

The stack in `examples/` runs Traefik in front of an application that knows
nothing about authentication.

```sh
make e2e-up                    # PostgreSQL, Cardinal, Traefik, a protected app
```

Open <https://app.cardinal.test:8443>. You are sent to Cardinal, and after signing in
you land on a page showing the identity headers that arrived.

`make e2e-up` did three things behind that, and they are the three any protected
application needs:

```sh
cardinal application create protected-app       # an entity to write policy about
cardinal app hostname add protected-app app.cardinal.test
cardinal grant staff-apps protected-app         # what the shipped rule permits
```

Skip the last one and the page is refused — correctly, and this is the part
worth pausing on. The shipped `staff-web-access` rule permits an application
*in staff-apps*, and that group starts empty. Registering an application makes
it findable; putting it in a group the policy names is the deliberate act that
makes it reachable. Skip the middle one and the refusal comes earlier still,
naming the hostname nothing claims.

Then look at **Access** in the admin UI. Every request you just made is there,
with the policy that admitted it. To see a denial explained, add a rule:

```cedar
@id("no-admin-console-for-emergency-sessions")
forbid (principal, action == Cardinal::Action::"AccessURL", resource)
when { principal.emergency && context has path && context.path like "/admin*" };
```

```sh
cardinal policy publish policies/cardinal.cedar -activate
```

Visit `/admin/anything` and the explorer will say *"Explicitly forbidden by
policy no-admin-console-for-emergency-sessions"* — and clicking the rule name
shows its text. That distinction matters: an explicit forbid sends someone to
argue with the rule, whereas "no policy grants this" sends them to request
access.

```sh
make e2e        # the same stack, asserted
make e2e-down
```

## Cleanup

```sh
make down
```
