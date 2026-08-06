# First run

Everything below works today. It takes about ten minutes, and the last section
is the part nobody has done yet — a real passkey against a real browser.

## 1. Database and build

```sh
make up                 # PostgreSQL 19 beta 2 on port 5433
make migrate
make release            # builds the React UI and embeds it in the binary
```

## 2. The break-glass ceremony

This is a real ceremony, not a formality. The private key is printed once and
never stored by Cardinal.

```sh
./bin/cardinal break-glass generate > break-glass.key
```

The public key goes in `cardinal.toml`; the private key would normally go
offline. For a local test, leaving it in the working directory is fine — it is
gitignored, and you should delete it afterwards.

```sh
cp cardinal.example.toml cardinal.toml
```

Edit it: paste the public key, and for local testing set

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

There is a chicken-and-egg problem here, and break-glass is the designed answer
to it: enrolling a passkey needs a session, and getting a session needs a
passkey. Rather than a bootstrap mode someone could forget to disable, the
offline key breaks the circle.

1. Click **Emergency access**, then **Request a challenge**.
2. Run the command it shows you:
   ```sh
   ./bin/cardinal break-glass sign <challenge> -key break-glass.key
   ```
3. Paste the signature, enter `alonfils`, open the session.
4. You are in, with a red banner saying so. The session lasts 15 minutes.
5. Name a passkey and click **Add** — your laptop's biometric or a security key.
6. Add a second one. The warning banner clears at two.
7. Generate recovery codes.
8. Sign out, then **Sign in**. No username field: your authenticator offers the
   account, so there is nothing to enumerate.

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

Three things will refuse you, all deliberately:

- **A break-glass session cannot administer.** Emergency access exists to
  restore normal access, not to be worked in. Do the grant above with the CLI,
  which talks to the database directly.
- **A synced passkey is not enough.** Administration needs a device-bound
  credential — a hardware key, not one living in a cloud account.
- **A session older than five minutes is not enough.** Sign in again; the tab
  reappears.

Each refusal names the policy that produced it, in the response and in
**Access → decisions**. That is the demo worth showing someone: neither FreeIPA
nor Keycloak can tell you *which rule* denied you.

## What to look for

- The break-glass session shows `authMethod: break_glass` and a red banner.
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

Open <http://app.localhost:8100>. You are sent to Cardinal, and after signing in
you land on a page showing the identity headers that arrived.

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
rm break-glass.key
make down
```
