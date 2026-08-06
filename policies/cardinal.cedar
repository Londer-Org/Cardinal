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
// permit, which is what makes the freshness rules below trustworthy rather
// than merely conventional.
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
// Application access
// ─────────────────────────────────────────────────────────────────────────────

// Who may sign in to which application.
//
// Asked at /oidc/authorize, once the user is known and before any claim is
// released. Separate from AccessURL because an OIDC application is reached
// directly rather than through the proxy, so forwardAuth never sees it.
//
// This ships permissive on purpose. Cedar is default-deny, so a policy set with
// no permit here would refuse every sign-in to every application the moment
// this check existed — an upgrade that locks everyone out of everything is not
// a safe default, whatever it is a safe default for.
//
// Narrow it by replacing this rule. Applications are named by their directory
// name, so it reads the way an administrator thinks:
//
//     @id("grafana-is-for-engineering")
//     permit (
//         principal in Cardinal::Group::"<engineering-uuid>",
//         action == Cardinal::Action::"AccessApplication",
//         resource == Cardinal::Application::"grafana"
//     );
//
// Naming applications rather than referencing their UUID is the same trade the
// host rules make below: policy has to be readable by the person who maintains
// it, and renaming an application is a deliberate administrative act. Renaming
// one *does* change what this policy means — which is a reason to be careful
// about renames, not a reason to make every rule unreadable.
@id("any-user-may-access-any-application")
permit (
    principal,
    action == Cardinal::Action::"AccessApplication",
    resource
);

// ─────────────────────────────────────────────────────────────────────────────
// Directory administration
// ─────────────────────────────────────────────────────────────────────────────

// Members of directory-admins may administer the directory.
//
// The group is created by migration 0008 with this fixed UUID, because a rule
// shipped in this file cannot reference an identifier generated at install
// time. Nobody is a member until someone is granted it:
//
//     cardinal grant directory-admins alice
//
// This is a permit, and the forbid rule below still applies to it — in Cedar a
// forbid always beats a permit, so membership alone is not enough: the session
// must also be device-bound and recently authenticated.
@id("directory-admins-may-administer")
permit (
    principal in Cardinal::Group::"00000000-0000-7000-8000-00000000ad11",
    action in [
        Cardinal::Action::"AdministerDirectory",
        Cardinal::Action::"ManageUsers",
        Cardinal::Action::"ManageApplications"
    ],
    resource
);

// Narrower tiers, for organisations that want them.
//
// Both are empty until someone is granted them. An existing administrator keeps
// exactly what they had — migration 0011 moves nobody — so narrowing is a
// deliberate act rather than something discovered after an upgrade.

// Onboarding staff: create and disable accounts, issue enrollment invitations,
// grant and revoke group membership.
@id("user-admins-may-manage-people")
permit (
    principal in Cardinal::Group::"00000000-0000-7000-8000-00000000ad12",
    action == Cardinal::Action::"ManageUsers",
    resource
);

// Registering relying parties. Separate from managing people because choosing
// an application's redirect URIs is enough to build a phishing surface inside
// the organisation's own identity provider — a different blast radius from
// adding someone to a group.
@id("security-admins-may-manage-applications")
permit (
    principal in Cardinal::Group::"00000000-0000-7000-8000-00000000ad13",
    action == Cardinal::Action::"ManageApplications",
    resource
);

// ─────────────────────────────────────────────────────────────────────────────
// Step-up
// ─────────────────────────────────────────────────────────────────────────────

// Every administrative action requires a device-bound credential authenticated
// within the last five minutes.
//
// Listed explicitly rather than left to the broad action: a narrower tier that
// escaped the step-up rule would be a way to administer *something* from a
// twelve-hour session, which is the hole this rule exists to close.
//
// Two separate requirements, both load-bearing. Device-bound excludes a synced
// passkey, which is more recoverable but lives in a cloud account. Freshness
// excludes a twelve-hour session someone left open on an unlocked laptop.
@id("admin-requires-fresh-device-bound-auth")
forbid (
    principal,
    action in [
        Cardinal::Action::"AdministerDirectory",
        Cardinal::Action::"ManageUsers",
        Cardinal::Action::"ManageApplications"
    ],
    resource
)
unless {
    principal.deviceBound && principal.authAgeSeconds <= 300
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
