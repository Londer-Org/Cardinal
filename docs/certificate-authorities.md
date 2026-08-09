# Certificate authorities: how the keys are managed

What exists today is the **SSH** certificate authority. X.509 over ACME is
decided but not built ([ADR 0023](adr/0023-x509-certificates-via-acme.md)), and
is marked as such below.

Read [ADR 0021](adr/0021-ssh-ca-key-custody.md) for why these choices were made.
This document is how to operate them.

## The short version

Cardinal **generates** the SSH CA key. You do not supply one, and there is
currently no way to import an existing key.

The private half is sealed with AES-GCM and stored in PostgreSQL. The key that
seals it lives in the configuration file, so **an attacker needs both the
database and the configuration** — a database dump alone yields nothing usable.

It is not an HSM. What makes that acceptable rather than negligent is the rest
of the design: certificates last minutes, every issuance is logged with the rule
that permitted it, and rotation is one command rather than a project.

## Setting one up

```sh
# 1. Configure the sealing key. Its own value — see "Why two keys" below.
openssl rand -base64 32          # put this in ssh.ca_encryption_key

# 2. Generate the authority. Created INACTIVE on purpose.
cardinal ssh ca init

# 3. Wait for hosts to trust it. Anything running cardinal-agent does this on
#    its own: the trusted authorities ride the assignment it already polls, so
#    a host has them within one refresh interval.
cardinal ssh ca trust                     # what a host without the agent needs
#      /etc/ssh/sshd_config →  TrustedUserCAKeys /etc/ssh/cardinal_ca.pub

# 4. Only once every host trusts it, start signing.
cardinal ssh ca rotate <key-id>
```

**The order matters and the tool enforces it.** A key that signed the moment it
existed would issue certificates every host rejects, which presents as "Cardinal
is broken" rather than "the procedure was run backwards". `init` therefore
creates the key without activating it, and `-activate` exists only for a first
install where nothing trusts an older key yet.

## Rotating

`TrustedUserCAKeys` accepts several keys at once, which is the only reason
rotation is possible — OpenSSH certificates cannot be chained, so whatever signs
must itself be trusted by every host.

```sh
cardinal ssh ca init                        # publish the replacement
#   … hosts running the agent pick both up within one refresh interval …
cardinal ssh ca rotate <new-key-id>         # switch signing
```

The previous key stops signing immediately and stays **trusted** for a grace
period (48 hours by default), so certificates issued seconds before the switch
keep working.

**Agents converge on their own.** `cardinal-agent` writes
`/etc/ssh/cardinal_user_ca.pub` and the `TrustedUserCAKeys` drop-in that names
it, from the same assignment it already fetches — so a rotation reaches the
fleet on the ordinary interval and needs no fleet-wide copy. Until 0.3.0 this
was a manual step, which made rotation a fleet-wide operation nobody performs:
in practice the first key was the only key, and the machinery above had nothing
to converge on.

The window that remains is the interval itself. `rotate` starts signing at once,
so a host that has not yet fetched rejects the new certificates until it does.

One thing the agent will not do is *remove* trust. An empty list and an older
server that sends no list at all are indistinguishable on the wire, so an agent
that deleted the file on an empty answer would remove trust an operator
installed by hand. Withdrawing an authority is a rotation, and a rotation sends
a non-empty list.

`cardinal ssh ca list` shows which key is in which state.

## Why two encryption keys

`ssh.ca_encryption_key` is deliberately not `oidc.signing_key_encryption_key`,
and Cardinal **refuses to start** if they are equal.

They protect different things. The OIDC key forges tokens for registered
applications. The SSH CA key logs into every host as anybody. One leaked
configuration file should not yield both, and a warning about it is something
people read once.

### Rotating the token signing key

The OIDC signing key rotates too, and until 0.3.0 it could not: the rotation was
implemented, wrapped in a method nothing called, so the key with the widest
blast radius in the system was the one authority that had no rotate command.

```
cardinal oidc key list                  # keys, and which one is signing
cardinal oidc key rotate                # sign with a new one
```

Unlike the CAs this is one step, not two. A trust store has to be updated before
an SSH or X.509 authority can start signing; the JWKS is fetched live, so a
receiver picks up the new key on its next refresh with no distribution to
perform and no restart.

The retired key keeps verifying for a grace period, defaulting to the longest
token lifetime any registered client is configured with — measured rather than
assumed, because a key that stops verifying while tokens signed by it are still
valid is how a rotation becomes an outage. `-grace` overrides it and a shorter
one is refused unless you also pass `-force`.

The one failure mode worth knowing: a client that caches the JWKS aggressively
rather than honouring its refresh will reject new tokens until it refetches.
Both keys are published throughout the grace period precisely so that window is
survivable.

## What an attacker gets

Stated plainly, because a security control whose limits are unstated is one
people over-trust.

| They have | Result |
|---|---|
| A database dump | Nothing. The key is sealed. |
| The configuration file | Nothing on its own. |
| **Both** | **Complete compromise.** They can issue a certificate for any user on any host, and no log distinguishes it from a real one. |
| Root on the Cardinal host | The same, plus everything else. |

This is the same trust boundary as the OIDC signing key and the recovery path:
the host is the credential of last resort, and the
[threat model](threat-model.md) states it as an assumption rather than a defence.

What limits the damage:

- **Certificates last minutes.** A forged one is not durable access, and there
  is nothing to revoke because renewal simply stops.
- **Issuance is logged** with the deciding policy, so a compromise is
  reconstructable after the fact even though it is invisible in the moment.
- **Rotation is automated.** Responding to a suspicion is a command, not a
  project — which is what makes acting on a hunch affordable.

## Stronger custody

`crypto.Signer` is the interface the signing path takes, specifically so the key
material is configuration rather than a permanent decision. A PKCS#11
implementation slots in without anything above it changing.

**It is not implemented yet.** When it is, `ssh-keygen` itself supports signing
with a CA key in a PKCS#11 token, so this is well-trodden ground.

**TPM sealing was considered and rejected**, and the reason is worth knowing
before someone proposes it again: it would bind certificate issuance to one
physical machine, which breaks the stateless-nodes-plus-standby arrangement that
makes failover a ten-minute runbook. Trading fleet availability for key secrecy
is the wrong way round when the fleet is what the key exists to serve.

## X.509

Built in 0.2.0 — [ADR 0023](adr/0023-x509-certificates-via-acme.md). This
section said "not built yet" for a release after it shipped, which is the kind
of claim this project keeps finding: nobody writes it wrong, they write it true
and then it stops being true.

It works the same way the SSH authority does, and the commands mirror it:

```
cardinal x509 ca init -subject "Example Internal CA"   # create, not yet signing
cardinal x509 ca trust                                  # every trusted cert, PEM
cardinal x509 ca rotate <key-id>                        # make a key sign
cardinal x509 ca list                                   # keys, and which signs
```

Certificates are issued over ACME (RFC 8555) rather than a bespoke endpoint, so
any ACME client can order one. A host authenticates with an external account
binding issued by `cardinal host acme-credentials <host>`, and nothing is issued
for a name the directory has not granted whatever the CSR asks for.

Two things the earlier version of this section promised are still not built, and
are gaps rather than plans:

**Intermediates are not supported.** X.509 allows a chain, and the better shape
is an offline root signing a short-lived online intermediate so the long-lived
key never touches Cardinal. What exists is a self-signed root held the same way
the SSH CA key is held — sealed with `x509.ca_encryption_key`, in the database.
That is the same custody as SSH, not better, and the paragraph claiming
otherwise was describing an intention.

**Bringing your own root is not supported.** `x509 ca init` generates. Most
organisations already have a root they intend to keep, and "Cardinal generates
it or nothing" is a poor reason to run a second CA — this remains an open
question rather than a decision.

Trust distribution is the part that makes internal CAs fail in practice. An
internal CA is worthless until its root is in system trust stores, container
images, JVM keystores and browsers — `cardinal-agent` can place it on enrolled
Linux hosts, and everything else is documentation and honesty about the work.
