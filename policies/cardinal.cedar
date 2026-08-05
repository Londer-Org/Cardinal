// Cardinal's default policy set.
//
// Authored here, validated in CI, loaded into the database as an immutable
// version. This one file governs every decision point: web access via Traefik
// forwardAuth, SSH certificate issuance, sudo rules, and Cardinal's own admin
// API (ADR 0005).
//
// Cedar is default-deny. Nothing here needs to say "deny by default", and a
// gap in this file fails closed.
//
// Group references use UUIDs because names are mutable (ADR 0002). The admin
// CLI prints them; `cardinal show group <name>` is the usual way to find one.

// ─────────────────────────────────────────────────────────────────────────────
// Web access
// ─────────────────────────────────────────────────────────────────────────────

// Anyone authenticated may reach applications marked public-to-staff.
//
// The forbid rules below still apply — in Cedar, a forbid always beats a
// permit, which is what makes the emergency and freshness rules below
// trustworthy rather than merely conventional.
@id("staff-web-access")
permit (
    principal,
    action == Cardinal::Action::"AccessURL",
    resource
)
when {
    context has audience && context.audience == "staff"
};

// ─────────────────────────────────────────────────────────────────────────────
// Step-up
// ─────────────────────────────────────────────────────────────────────────────

// Administering the directory requires a device-bound credential authenticated
// within the last five minutes.
//
// Two separate requirements, both load-bearing. Device-bound excludes a synced
// passkey, which is more recoverable but lives in a cloud account. Freshness
// excludes a twelve-hour session someone left open on an unlocked laptop.
@id("admin-requires-fresh-device-bound-auth")
forbid (
    principal,
    action == Cardinal::Action::"AdministerDirectory",
    resource
)
unless {
    principal.deviceBound && principal.authAgeSeconds <= 300
};

// ─────────────────────────────────────────────────────────────────────────────
// Emergency access
// ─────────────────────────────────────────────────────────────────────────────

// A break-glass session may not administer the directory.
//
// Break-glass exists to restore normal access, not to be worked in. Someone
// holding the offline key can already assume any account; letting that session
// also rewrite the directory would turn a recovery mechanism into an
// unaudited-in-practice superuser, because nobody reviews changes made during
// an incident.
//
// Enrolling a passkey remains possible — that is the bootstrap path — because
// it is not this action.
@id("break-glass-cannot-administer")
forbid (
    principal,
    action == Cardinal::Action::"AdministerDirectory",
    resource
)
when {
    principal.emergency
};

// A break-glass session may not obtain SSH access to production hosts.
//
// The emergency is in Cardinal. It is not, without separate evidence, in the
// fleet — and an emergency credential that also opens every server makes the
// blast radius of a stolen offline key considerably worse.
@id("break-glass-no-production-ssh")
forbid (
    principal,
    action == Cardinal::Action::"SSHLogin",
    resource
)
when {
    principal.emergency
};

// ─────────────────────────────────────────────────────────────────────────────
// Host access
// ─────────────────────────────────────────────────────────────────────────────

// SSH to a host requires membership of a group the host names, and a
// device-bound credential.
//
// Replaces FreeIPA HBAC. Evaluated at certificate *issuance*, so the host never
// consults the directory at login and a Cardinal outage does not lock anyone
// out (ADR 0006).
@id("ssh-requires-device-bound")
forbid (
    principal,
    action == Cardinal::Action::"SSHLogin",
    resource
)
unless {
    principal.deviceBound
};

// Running as root additionally requires a recent authentication.
//
// Replaces FreeIPA sudo rules. Fifteen minutes rather than five: sudo happens
// mid-task, and a five-minute window would have people re-authenticating
// constantly, which reliably ends with the rule being removed altogether.
@id("root-requires-recent-auth")
forbid (
    principal,
    action == Cardinal::Action::"RunAsRoot",
    resource
)
unless {
    principal.authAgeSeconds <= 900
};
