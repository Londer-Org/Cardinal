# ADR 0021: Where the SSH CA private key lives

- **Status:** Accepted — decided; implementation belongs to Phase 4.
- **Date:** 2026-08-06
- **Resolves:** the `Key management` question in Phase 4, which the
  [threat model](../threat-model.md) calls the highest-stakes decision left.

## Context

Whoever holds the SSH CA private key can mint a certificate for any user on any
host, and `sshd` will accept it because that is what the key means. The
compromise is fleet-wide, silent — nothing in a log distinguishes a forged
certificate from a real one — and recovering means changing what every host
trusts.

Two properties of OpenSSH certificates shape every option:

**There are no chains.** A certificate is signed by one CA key and the host
trusts that key directly. The pattern X.509 uses to solve exactly this problem —
an offline root signing a short-lived online intermediate — is not available.
Whatever key signs user certificates must itself be trusted by every host.

**But a host can trust several CA keys at once.** `TrustedUserCAKeys` takes a
file of them. So rotation is: publish the new public key everywhere, switch
signing, remove the old one. Expensive by hand across a fleet — and
`cardinal-agent` is already specified to manage that file.

That second point reframes the whole decision. If rotation is automated, the
key is *replaceable* rather than sacred, and the design should optimise for
being able to replace it rather than for making it theoretically unstealable.

## Decision

**The signing path takes a `crypto.Signer`, and the key material behind it is
configuration.** This is the part that matters and it costs nothing to do now:
Cardinal asks an interface to sign, and never holds key bytes in its own logic.
Every option below is then an implementation of that interface, and the choice
stops being permanent.

**The default is envelope encryption in the database, with its own key.** The
same shape as OIDC signing keys, which already works: the private key is
encrypted at rest, and the encryption key comes from configuration or the
environment. Deliberately **not** the same encryption key as the OIDC one —
compromising the token-signing envelope must not also hand over the fleet.

**PKCS#11 is a supported implementation, not a requirement.** `ssh-keygen`
itself supports signing with a CA key in a PKCS#11 token, so this is the
well-trodden path for anyone with an HSM or a smartcard. Cardinal should accept
a PKCS#11 URI in place of a stored key and never see the private half.

**Rotation is designed in from the start, not added later.** The agent
distributes the new CA public key, Cardinal switches signing after a grace
period during which both are trusted, then the old key is withdrawn. Written
before the CA exists, because a rotation procedure retrofitted to a live fleet
is how a compromised key stays in place for months.

## Rejected

**Sealing the key to a TPM.** Tempting — the key never exists in usable form off
the machine, and a database dump is worthless. It conflicts directly with
Cardinal's own availability plan: stateless application nodes behind a
synchronous standby, which is what makes failover a ten-minute runbook rather
than a rebuild. A TPM-sealed key binds certificate issuance to one physical
host, so losing that host means no SSH access is issued until a new key is
provisioned and distributed to every machine. Trading fleet availability for key
secrecy is the wrong way round when the fleet is what the key exists to serve.

**Requiring an HSM.** Correct for a bank and wrong for this project: Cardinal
has to be deployable by one person on one server, and a mandatory second piece
of hardware makes the honest answer "you cannot run this". Supported, never
required.

**Reusing the OIDC signing-key encryption key.** One secret protecting both the
token signer and the fleet CA means one leaked configuration file yields both.
They are separate settings, and validation should refuse them being equal.

**A long-lived key with no rotation story.** The default outcome of not
deciding, and the one that turns a suspected compromise into a project.

## Consequences

The threat model's residual risk stands and should be restated rather than
quietly dropped: with the default configuration, an attacker holding both the
database and the configuration file holds the CA. That is the same trust
assumption already made for OIDC signing keys and for the recovery path — the
host is the credential of last resort — but it carries more here, because SSH
certificates are accepted by machines that cannot check with anybody.

What makes that acceptable rather than negligent is the rest of the design:
certificates are 5–15 minutes long, so a forged one is not durable access;
issuance is logged with the deciding policy; and rotation is automated, so
responding to a suspicion is a command rather than a project. Deployments that
want the stronger property have PKCS#11 and lose nothing by choosing it.
