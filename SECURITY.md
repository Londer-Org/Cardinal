# Security Policy

Cardinal is authentication and authorization infrastructure. A vulnerability
here is a vulnerability in every system that trusts it, so security reports are
taken seriously regardless of the project's pre-1.0 status.

## Supported versions

**None.** Cardinal is pre-1.0 and under active development. No version is
supported for production use, and there is no backported-fix policy yet. This
section will change at 1.0.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a security
problem.**

Report privately through
[GitHub Security Advisories](https://github.com/Londer-Org/Cardinal/security/advisories/new),
which creates a private channel visible only to maintainers.

Please include:

- What the issue is and roughly how severe you think it is
- Steps to reproduce, or a proof of concept
- Affected version or commit
- Any deployment configuration needed to trigger it

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | 3 working days |
| Initial assessment and severity | 10 working days |
| Fix or documented mitigation | Depends on severity; you'll get progress updates |

These are targets for a project maintained in spare time, not a contractual SLA.
If you haven't heard back within the acknowledgement window, please ping the
advisory thread — it means something went wrong, not that the report was ignored.

## Disclosure

Coordinated disclosure. The intent is to publish an advisory once a fix is
available, crediting you unless you'd rather stay anonymous. If a fix is taking
an unreasonable amount of time, you're entitled to disclose anyway — please tell
us your timeline so we can prepare.

## Scope

In scope, and most interesting:

- Authentication bypass, session fixation or forgery, credential handling
- Authorization bypass — Cedar policy evaluation producing an unsafe allow
- Privilege escalation through the admin API, CLI, or host agent
- Temporal-model correctness bugs, where a revoked or expired grant still
  resolves as active (this is an authorization bypass, not merely a data bug)
- Tampering with the event log that leaves the hash chain intact
- SSH certificate issuance granting principals the policy did not authorize
- Host agent flaws — sudoers rendering, POSIX identity, or anything that could
  remove or bypass local root access

Out of scope:

- Anything requiring a compromised Postgres superuser or root on the host
- Denial of service through simple resource exhaustion
- Findings from automated scanners without a demonstrated exploit path
- Vulnerabilities in dependencies with no exploitable path through Cardinal
  (report those upstream; do tell us if Cardinal's usage makes them exploitable)
- Missing hardening headers or best practices with no concrete attack

## Safe harbour

Good-faith research under this policy is welcome. Don't access, modify, or
exfiltrate data that isn't yours, don't degrade services others rely on, and
give us a reasonable chance to fix things before going public.
