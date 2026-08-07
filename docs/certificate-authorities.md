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

# 3. Distribute the public key to every host, then:
#      /etc/ssh/sshd_config →  TrustedUserCAKeys /etc/ssh/cardinal_ca.pub
cardinal ssh ca trust > cardinal_ca.pub

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
cardinal ssh ca trust > cardinal_ca.pub     # now contains both
#   … distribute to every host …
cardinal ssh ca rotate <new-key-id>         # switch signing
```

The previous key stops signing immediately and stays **trusted** for a grace
period (48 hours by default), so certificates issued seconds before the switch
keep working. Redistribute `cardinal ssh ca trust` before the grace period ends,
or hosts will keep trusting a key Cardinal has withdrawn — harmless, but it
means the file no longer says what you think it says.

`cardinal ssh ca list` shows which key is in which state.

## Why two encryption keys

`ssh.ca_encryption_key` is deliberately not `oidc.signing_key_encryption_key`,
and Cardinal **refuses to start** if they are equal.

They protect different things. The OIDC key forges tokens for registered
applications. The SSH CA key logs into every host as anybody. One leaked
configuration file should not yield both, and a warning about it is something
people read once.

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

## X.509 — not built yet

Two things will differ, both for the better:

**Intermediates are possible.** Unlike SSH, X.509 supports a chain — so the
recommended shape is an offline root signing a short-lived online intermediate,
and the long-lived key never touches Cardinal at all. That is a materially
better answer than anything available for SSH.

**Bringing your own root should be supported**, and this is an open question
rather than a decision. Most organisations already have a root they intend to
keep, and "Cardinal generates it or nothing" would be a poor reason to run a
second CA. The SSH side generates only because there is rarely an existing SSH
CA to import.

Trust distribution is the part that makes internal CAs fail in practice. An
internal CA is worthless until its root is in system trust stores, container
images, JVM keystores and browsers — `cardinal-agent` can place it on enrolled
Linux hosts, and everything else is documentation and honesty about the work.
