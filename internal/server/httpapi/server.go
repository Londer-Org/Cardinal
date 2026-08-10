package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"go.londer.be/cardinal/internal/ca/sshca"
	"go.londer.be/cardinal/internal/ca/x509ca"
	"go.londer.be/cardinal/internal/config"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/server/auth"
	"go.londer.be/cardinal/internal/server/claims"
	"go.londer.be/cardinal/internal/server/mail"
	"go.londer.be/cardinal/internal/server/oidcprovider"
	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/internal/server/ssf"
	"go.londer.be/cardinal/internal/store"
	"go.londer.be/cardinal/internal/version"
)

// Server holds the HTTP surface.
type Server struct {
	store *store.Store
	auth  *auth.Service
	cfg   *config.Config
	log   *slog.Logger

	// secureCookies is false only in development over plain HTTP. In any
	// deployment reachable over a network it must be true, or session cookies
	// travel in the clear.
	secureCookies bool
	devMode       bool

	// ui is the embedded admin interface. Nil serves API only, which is useful
	// while the frontend is being rebuilt.
	ui fs.FS

	clientIP *clientIPResolver
	claims   *claims.Resolver

	// sshCA is nil unless host access is configured. A certificate authority
	// nobody has enrolled hosts against is a signing key sitting in a database
	// for no reason, so it stays off until asked for.
	sshCA    *sshca.CA
	notifier *mail.Notifier

	// signals tells applications when access changes. Nil leaves the
	// transmitter off, which is what a deployment with no receivers configured
	// gets — and the server behaves identically without it.
	signals *ssf.Notifier

	// x509CA is nil unless X.509 issuance is configured. Optional in exactly
	// the same way and for the same reason: a deployment that already has a CA
	// keeps it, and nothing else in Cardinal depends on this (ADR 0023).
	x509CA *x509ca.CA

	// oidc is nil when the provider is disabled, which is the default: an
	// identity provider nobody has registered clients for is attack surface
	// without a purpose.
	oidc *oidcprovider.Provider

	// policy holds the live engine behind an atomic pointer.
	//
	// Reloading swaps the whole engine rather than mutating one, so an
	// in-flight request can never observe a half-applied policy change — it
	// evaluates entirely against the old set or entirely against the new.
	policy atomic.Pointer[policy.Engine]
}

// ReloadPolicy swaps in a new policy version.
//
// The context is only for the diagnostics below — the swap itself is a pointer
// store and cannot fail. A caller passing a request context that is cancelled
// therefore loses a warning and nothing else.
func (s *Server) ReloadPolicy(ctx context.Context, engine *policy.Engine) {
	s.policy.Store(engine)
	if engine != nil {
		s.log.Info("policy set loaded",
			"version", engine.Version(), "policies", len(engine.PolicyIDs()))

		// Cedar is default-deny, so an action this set never mentions is one
		// that will be refused every time — correct, and indistinguishable from
		// a bug to whoever hits it.
		//
		// The case worth catching is an upgrade: Cardinal gains an action, the
		// deployment keeps running its existing policy set, and an
		// administrator is told they are not a member of a group they are a
		// member of. Warning rather than refusing to start, because a
		// deliberately narrow policy set is a legitimate thing to run.
		if missing := engine.UngovernedActions(); len(missing) > 0 {
			s.log.Warn("the active policy set never mentions some actions, "+
				"so they will be refused for everyone — republish "+
				"policies/cardinal.cedar if this deployment was upgraded",
				"actions", missing, "version", engine.Version())
		}

		s.reportDanglingReferences(ctx, engine)
	}
}

// reportDanglingReferences names the rules that can never match.
//
// The sibling of the check above and the harder of the two to notice. An action
// no rule mentions produces a refusal somebody eventually reports; a rule naming
// a group that does not exist produces a refusal that looks *correct* — the
// person is not in the group, because the group is not there.
//
// Checked on every load rather than only at publication, because the reference
// can go missing long after the policy did not change: deleting a group is what
// silently removes whatever the rule naming it was granting, and nothing about
// that moment involves the policy set.
//
// A warning, never a refusal. A deployment running a trimmed policy set with
// rules for groups it has not made yet is doing something legitimate, and a
// server that would not start because of it turns a lint into an outage.
func (s *Server) reportDanglingReferences(ctx context.Context, engine *policy.Engine) {
	// Bounded: this is a diagnostic, and a slow database must not hold up a
	// policy swap that the rest of the fleet has already made.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	dangling, err := engine.Dangling(ctx, s.store.PolicyReferenceExists)
	if err != nil {
		s.log.WarnContext(ctx, "could not check what the policy set names", "error", err)
		return
	}
	for _, ref := range dangling {
		s.log.WarnContext(ctx,
			"a policy rule names something the directory does not have, so the "+
				"rule can never match — which looks like the rule working, "+
				"because Cedar is default-deny",
			"policy", ref.Policy, "names", ref.Kind, "identifier", ref.Identifier,
			"version", engine.Version())
	}
}

// Options carries the collaborators a Server needs that are not configuration:
// the policy engine, the OIDC provider, the certificate authorities.
type Options struct {
	DevMode bool
	UI      fs.FS
	Logger  *slog.Logger

	// OIDC enables the OpenID Connect provider. Nil leaves it off.
	OIDC *oidcprovider.Provider

	// SSHCA enables host access by certificate. Nil leaves it off, which is
	// the default: a certificate authority nobody has enrolled hosts against
	// is a signing key in a database for no reason.
	SSHCA *sshca.CA

	// X509CA enables ACME issuance. Nil leaves it off.
	X509CA *x509ca.CA

	// Notifier sends people word of what happened to their account. Nil leaves
	// notifications off, which is what a deployment with no relay configured
	// gets, and the server works identically without it.
	Notifier *mail.Notifier

	// Signals transmits security events to applications. Nil leaves it off.
	Signals *ssf.Notifier
}

// New builds a Server and wires its routes.
func New(s *store.Store, a *auth.Service, cfg *config.Config, opts Options) (*Server, error) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	// Validated at startup rather than per request: a malformed trusted_proxies
	// entry must stop the server, not silently degrade to trusting nothing.
	resolver, err := newClientIPResolver(cfg.Server.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("httpapi: server.trusted_proxies: %w", err)
	}
	if len(cfg.Server.TrustedProxies) > 0 {
		log.Info("trusting forwarded client addresses from configured proxies",
			"proxies", cfg.Server.TrustedProxies)
	}

	srv := &Server{
		store: s, auth: a, cfg: cfg, log: log,
		// Secure cookies are the default; dev mode is the only way to opt out,
		// so forgetting to configure something cannot silently downgrade them.
		secureCookies: !opts.DevMode,
		devMode:       opts.DevMode,
		ui:            opts.UI,
		clientIP:      resolver,
		claims:        claims.NewResolver(s),
		oidc:          opts.OIDC,
		sshCA:         opts.SSHCA,
		notifier:      opts.Notifier,
		signals:       opts.Signals,
		x509CA:        opts.X509CA,
	}
	return srv, nil
}

// Handler builds the routing tree.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// ── Authentication, anonymous but rate limited ──────────────────────────
	mux.Handle("POST /api/auth/login/begin",
		s.rateLimit(store.LimitLoginBegin)(http.HandlerFunc(s.handleLoginBegin)))
	mux.Handle("POST /api/auth/login/finish",
		s.rateLimit(store.LimitLoginFinish)(http.HandlerFunc(s.handleLoginFinish)))

	mux.Handle("GET /api/auth/me",
		s.requireAuth(s.requireScope(ScopeIdentity, http.HandlerFunc(s.handleMe))))

	// Tiered: people go to user-admins, applications to security-admins, and
	// directory-admins holds both. An endpoint added without a tier in mind
	// falls to requireAdmin, which is the strictest of the three.
	people := func(h http.HandlerFunc) http.Handler {
		return s.requireAuth(s.requirePermission(policy.ActionManageUsers, h))
	}
	apps := func(h http.HandlerFunc) http.Handler {
		return s.requireAuth(s.requirePermission(policy.ActionManageApplications, h))
	}
	mux.Handle("POST /api/auth/logout", s.requireAuth(http.HandlerFunc(s.handleLogout)))

	// Editing your own name and email. Not behind requireAdmin: correcting a
	// typo in your own display name is not administering the directory, and
	// demanding a fresh security key for it would make the step-up rule
	// something people resent rather than respect.
	mux.Handle("PATCH /api/auth/me",
		s.requireAuth(s.requireScope(ScopeProfile, http.HandlerFunc(s.handleUpdateProfile))))

	// Step-up. Rate-limited like login, because it is a login in everything but
	// the session it does not create.
	mux.Handle("POST /api/auth/reauth/begin",
		s.requireAuth(s.rateLimit(store.LimitLoginBegin)(http.HandlerFunc(s.handleReAuthBegin))))
	mux.Handle("POST /api/auth/reauth/finish",
		s.requireAuth(s.rateLimit(store.LimitLoginFinish)(http.HandlerFunc(s.handleReAuthFinish))))

	// Enrollment. Unauthenticated by necessity — the whole point is that the
	// account has no credential yet — so each of these carries its own rate
	// limit and the invitation token is the only thing that authorises them.
	mux.HandleFunc("GET /api/enroll", s.handleInvitationDetails)
	mux.HandleFunc("POST /api/enroll/begin", s.handleEnrollBegin)
	mux.HandleFunc("POST /api/enroll/finish", s.handleEnrollFinish)

	// Issuing them is administration.
	mux.Handle("POST /api/invitations", people(s.handleIssueInvitation))

	// Recovery restores an account that can already sign in, so it can mint a
	// credential on an administrator's account. That needs the broad tier, and
	// two of them.
	recovery := func(h http.HandlerFunc) http.Handler {
		return s.requireAuth(s.requirePermission(policy.ActionAdministerData, h))
	}
	mux.Handle("GET /api/recoveries", recovery(s.handleListRecoveries))
	mux.Handle("POST /api/recoveries", recovery(s.handleRequestRecovery))
	mux.Handle("POST /api/recoveries/{login}/approve", recovery(s.handleApproveRecovery))
	mux.Handle("DELETE /api/recoveries/{login}", recovery(s.handleCancelRecovery))
	mux.Handle("GET /api/invitations", people(s.handleListInvitations))
	mux.Handle("DELETE /api/invitations/{login}", people(s.handleRevokeInvitation))

	// ── Credential self-service ────────────────────────────────────────────
	//
	// All of it behind requireDeviceBound rather than requireAuth: these are the
	// routes that decide what can authenticate as you, and a bearer token must
	// not be able to change that. See the comment on requireDeviceBound for what
	// this was open to before, which was account takeover from a CI variable.
	//
	// Reads are refused too, not only mutations. There is no automation that
	// needs to enumerate its owner's passkeys, and letting a leaked token look
	// around tells its holder what else to go after.
	selfService := func(h http.Handler) http.Handler {
		return s.requireAuth(s.requireDeviceBound(h))
	}

	mux.Handle("POST /api/credentials/register/begin",
		selfService(http.HandlerFunc(s.handleRegisterBegin)))
	mux.Handle("POST /api/credentials/register/finish",
		selfService(http.HandlerFunc(s.handleRegisterFinish)))

	// Access tokens, for their owner only. There is deliberately no
	// administrative path to issue somebody else a token, because an
	// administrator who could would be able to act as them without any log
	// distinguishing it from the person themselves.
	//
	// A token cannot manage tokens, which is what stops a leaked one from
	// minting its own successor and outliving the revocation of the original.
	mux.Handle("GET /api/tokens", selfService(http.HandlerFunc(s.handleListTokens)))
	mux.Handle("POST /api/tokens", selfService(http.HandlerFunc(s.handleCreateToken)))
	mux.Handle("DELETE /api/tokens/{id}", selfService(http.HandlerFunc(s.handleRevokeToken)))

	// Sessions, for the person signed into them. Behind the same door as
	// passkeys for the same reason: seeing where somebody is signed in, and
	// signing them out of it, is credential management. A leaked token that
	// could do either would be able to enumerate its owner's devices and lock
	// them out of all of them.
	mux.Handle("GET /api/sessions", selfService(http.HandlerFunc(s.handleListSessions)))
	mux.Handle("DELETE /api/sessions", selfService(http.HandlerFunc(s.handleRevokeOtherSessions)))
	mux.Handle("DELETE /api/sessions/{id}", selfService(http.HandlerFunc(s.handleRevokeSession)))

	mux.Handle("GET /api/credentials",
		selfService(http.HandlerFunc(s.handleListCredentials)))
	mux.Handle("DELETE /api/credentials/{id}",
		selfService(http.HandlerFunc(s.handleRevokeCredential)))

	// ── Recovery codes ─────────────────────────────────────────────────────
	//
	// The most valuable thing on this list. A fresh set is account-recovery
	// authority in plain text, and generating one invalidates the owner's — so
	// a token that could do this both gained a way in and took away the way back.
	mux.Handle("POST /api/recovery/codes",
		selfService(http.HandlerFunc(s.handleGenerateRecoveryCodes)))
	mux.Handle("GET /api/recovery/codes/remaining",
		selfService(http.HandlerFunc(s.handleRemainingRecoveryCodes)))

	// And spending one. Unauthenticated by necessity: somebody who could
	// authenticate would not be here. Rate limited on the same budget as the
	// rest of recovery — five attempts per quarter hour — which is what makes
	// the difference between a code being found and a code being guessed.
	//
	// It returns an enrollment rather than a session. Everything above is
	// behind requireDeviceBound, and a session minted from a string on paper
	// would be unable to register the passkey this exists to let somebody
	// register.
	mux.Handle("POST /api/recovery/codes/redeem",
		s.rateLimit(store.LimitRecovery)(http.HandlerFunc(s.handleRedeemRecoveryCode)))

	// ── Host enrollment ────────────────────────────────────────────────────
	//
	// Enrolling is unauthenticated by necessity — a machine with no credential
	// is exactly what this exists to fix — so the token carries the whole
	// authorization, and it is rate limited like every other unauthenticated
	// credential path.
	mux.Handle("POST /api/hosts/enroll",
		s.rateLimit(store.LimitHostEnroll)(http.HandlerFunc(s.handleHostEnroll)))
	mux.Handle("GET /api/hosts/me", s.requireHost(http.HandlerFunc(s.handleHostSelf)))
	mux.Handle("GET /api/hosts/assignment",
		s.requireHost(http.HandlerFunc(s.handleHostAssignment)))
	mux.Handle("POST /api/hosts/certificate",
		s.requireHost(http.HandlerFunc(s.handleIssueHostCertificate)))

	// ── ACME (RFC 8555) ────────────────────────────────────────────────────
	//
	// Unauthenticated at this layer and authenticated at every one of them: a
	// JWS signed by an account key, whose account was bound to a host by a
	// credential Cardinal issued. Session cookies and host signatures are both
	// meaningless here, which is why none of these sit behind requireAuth or
	// requireHost.
	//
	// The directory endpoint is the only GET. Everything else is a POST because
	// ACME has no authenticated GET — a client reads by posting an empty
	// payload, which looks wrong and is §6.3.
	mux.HandleFunc("GET /acme/directory", s.handleACMEDirectory)
	mux.HandleFunc("GET /acme/new-nonce", s.handleACMENewNonce)
	mux.HandleFunc("HEAD /acme/new-nonce", s.handleACMENewNonce)
	mux.HandleFunc("POST /acme/new-account", s.handleACMENewAccount)
	mux.HandleFunc("POST /acme/new-order", s.handleACMENewOrder)
	mux.HandleFunc("POST /acme/order/{id}", s.handleACMEOrder)
	mux.HandleFunc("POST /acme/order/{id}/finalize", s.handleACMEFinalize)
	mux.HandleFunc("POST /acme/authz/{id}", s.handleACMEAuthorization)
	mux.HandleFunc("POST /acme/cert/{id}", s.handleACMECertificate)

	// ── Host access ────────────────────────────────────────────────────────
	//
	// The only place SSH access is decided. sshd does no thinking at login, so
	// whatever this returns is what a host will believe for the certificate's
	// lifetime.
	if s.sshCA != nil {
		// Approving a terminal is behind requireDeviceBound for the same reason
		// managing credentials is: it hands out something a passkey proved, so
		// an access token must not be able to bootstrap one.
		// Behind the same tier as the rest of the directory's administration.
		// It shows no secret, and it still says where this deployment is
		// reached, which database it holds and how long a session lives —
		// enough of a map that it is not for everybody.
		// Notification email. Behind the same tier as the rest of the
		// deployment's administration: the settings name a relay and a
		// credential, and whoever can change them can redirect or silence every
		// notice an account owner would otherwise receive.
		mux.Handle("GET /api/mail/settings",
			s.requireAuth(s.requirePermission(policy.ActionAdministerData,
				http.HandlerFunc(s.handleGetMailSettings))))
		mux.Handle("PUT /api/mail/settings",
			s.requireAuth(s.requirePermission(policy.ActionAdministerData,
				http.HandlerFunc(s.handleSaveMailSettings))))
		mux.Handle("POST /api/mail/test",
			s.requireAuth(s.requirePermission(policy.ActionAdministerData,
				http.HandlerFunc(s.handleSendTestMail))))
		mux.Handle("GET /api/mail/templates",
			s.requireAuth(s.requirePermission(policy.ActionAdministerData,
				http.HandlerFunc(s.handleListMailTemplates))))
		mux.Handle("PUT /api/mail/templates/{kind}",
			s.requireAuth(s.requirePermission(policy.ActionAdministerData,
				http.HandlerFunc(s.handleSaveMailTemplate))))
		mux.Handle("DELETE /api/mail/templates/{kind}",
			s.requireAuth(s.requirePermission(policy.ActionAdministerData,
				http.HandlerFunc(s.handleResetMailTemplate))))

		mux.Handle("GET /api/config",
			s.requireAuth(s.requirePermission(policy.ActionAdministerData,
				http.HandlerFunc(s.handleConfigReport))))

		mux.Handle("POST /api/cli/authorize",
			s.requireAuth(s.requireDeviceBound(http.HandlerFunc(s.handleCLIAuthorize))))

		// Unauthenticated, necessarily: the caller is a terminal holding nothing
		// yet. The code is single-use, expires in ninety seconds, and is
		// worthless without a verifier that never left the process.
		mux.HandleFunc("POST /api/cli/exchange", s.handleCLIExchange)

		mux.Handle("POST /api/ssh/certificate",
			s.requireAuth(http.HandlerFunc(s.handleIssueSSHCertificate)))
	}

	// ── Traefik forwardAuth ────────────────────────────────────────────────
	// Any method: Traefik mirrors the original request's method here, and a
	// POST to a protected route must be authorized the same as a GET.
	mux.HandleFunc("/api/auth/verify", s.handleForwardAuth)

	// ── Decision explorer ──────────────────────────────────────────────────
	mux.Handle("GET /api/decisions",
		s.requireAuth(s.requireScope(ScopeDecisions, http.HandlerFunc(s.handleDecisions))))

	// Application management. Behind requireAdmin, which evaluates
	// Cardinal::Action::"AdministerDirectory" — anyone who can register a client
	// chooses its redirect URIs and whether it asks for consent, which is enough
	// to build a phishing surface inside the organisation's own IdP.
	// People and groups. Membership is what every policy reads, so granting one
	// is administration in the fullest sense.
	mux.Handle("GET /api/directory/users", people(s.handleListUsers))
	mux.Handle("POST /api/directory/users", people(s.handleCreateUser))
	mux.Handle("GET /api/directory/users/{login}", people(s.handleGetUser))
	mux.Handle("DELETE /api/directory/users/{login}", people(s.handleDisableUser))
	mux.Handle("POST /api/directory/users/{login}/enable", people(s.handleEnableUser))
	mux.Handle("PATCH /api/directory/users/{login}", people(s.handleUpdateUserProfile))

	// Renaming, which the data model exists to make ordinary: the identity is
	// an immutable id and the name is an attribute, so this is one UPDATE and
	// nothing else moves (ADR 0002). One handler for every type, because a
	// per-type endpoint would imply a difference that does not exist.
	mux.Handle("POST /api/directory/users/{name}/rename",
		people(s.handleRename(directory.TypeUser)))
	mux.Handle("POST /api/directory/groups/{name}/rename",
		people(s.handleRename(directory.TypeGroup)))
	mux.Handle("POST /api/directory/hosts/{name}/rename",
		people(s.handleRename(directory.TypeHost)))

	// POSIX identity. The uid is never in the request — it is allocated once
	// and is permanent, because every file on every disk records it.
	mux.Handle("PUT /api/directory/users/{login}/posix", people(s.handleAssignPOSIX))

	mux.Handle("GET /api/directory/groups", people(s.handleListGroups))
	// The same tier as people and groups: a host is a directory entity, and
	// whoever manages who may reach a machine needs to see which machines exist.
	//
	// Creating one, handing it a way in, and granting it another name it may
	// prove all sit here too. That last one is the sharpest: an alias is the
	// power to *be* that name to anything trusting the CA, so it belongs behind
	// the same door as group membership rather than somewhere more convenient.
	mux.Handle("GET /api/directory/hosts", people(s.handleListHosts))
	mux.Handle("POST /api/directory/hosts", people(s.handleCreateHost))
	mux.Handle("GET /api/directory/hosts/{name}", people(s.handleGetHost))
	mux.Handle("POST /api/directory/hosts/{name}/enrollment",
		people(s.handleIssueHostEnrollment))
	mux.Handle("POST /api/directory/hosts/{name}/aliases",
		people(s.handleAddHostAlias))
	mux.Handle("DELETE /api/directory/hosts/{name}/aliases/{alias}",
		people(s.handleRemoveHostAlias))
	mux.Handle("GET /api/directory/applications", people(s.handleListApplicationNames))
	mux.Handle("POST /api/directory/groups", people(s.handleCreateGroup))
	mux.Handle("GET /api/directory/groups/{name}", people(s.handleGetGroup))
	mux.Handle("POST /api/directory/groups/{name}/members", people(s.handleGrantMembership))
	mux.Handle("DELETE /api/directory/groups/{name}/members/{member}", people(s.handleRevokeMembership))

	mux.Handle("GET /api/applications", apps(s.handleListApplications))
	mux.Handle("POST /api/applications", apps(s.handleRegisterApplication))
	mux.Handle("GET /api/applications/{clientID}", apps(s.handleGetApplication))
	mux.Handle("DELETE /api/applications/{clientID}", apps(s.handleDisableApplication))
	// Rotation, which had no implementation. A leaked secret could previously
	// only be dealt with by disabling the application and registering a new
	// one — which changes the client id, so it is a reconfiguration anyway.
	mux.Handle("POST /api/applications/{clientID}/secret",
		apps(s.handleRotateClientSecret))
	// Hostnames are keyed on the application's directory name, not its client
	// id. An application that only sits behind the proxy has no client id, and
	// it is the one that most needs a hostname.
	mux.Handle("POST /api/applications/{name}/hostnames",
		apps(s.handleAddApplicationHostname))
	mux.Handle("DELETE /api/applications/{name}/hostnames/{hostname}",
		apps(s.handleRemoveApplicationHostname))
	// Retiring, also by name and for the same reason. {state} is enable or
	// disable — one handler, because the two differ by a boolean and splitting
	// them would duplicate the lookup and the audit line.
	mux.Handle("POST /api/applications/{name}/{state}",
		apps(s.handleSetApplicationEnabled))
	// Shared Signals streams. Behind ManageApplications rather than an action
	// of their own: a stream belongs to an application, and whoever may
	// register a receiver is whoever may decide it hears about revocations.
	// A new action would need a migration and a policy rule to grant it, for a
	// distinction nobody would draw.
	mux.Handle("GET /api/ssf/streams", apps(s.handleListSSFStreams))
	// PUT because there is one stream per receiver, enforced by the schema —
	// sending it twice is the same request rather than a second stream.
	mux.Handle("PUT /api/ssf/streams/{application}", apps(s.handleSaveSSFStream))
	mux.Handle("DELETE /api/ssf/streams/{application}", apps(s.handleDeleteSSFStream))
	mux.Handle("POST /api/ssf/streams/{application}/{state}",
		apps(s.handleSetSSFStreamEnabled))

	mux.Handle("GET /api/policy",
		s.requireAuth(s.requireScope(ScopePolicy, http.HandlerFunc(s.handlePolicy))))

	// Policy versions and rollback.
	//
	// Behind requireAdmin — the broad tier — rather than the people or
	// applications one. Activating a set decides every question Cardinal
	// answers, including who may activate the next one, so it is not something
	// to hold by virtue of managing accounts.
	//
	// There is deliberately no publish endpoint. A policy set belongs in git,
	// reviewed and tested before it is live; one typed into a browser is one
	// nobody read. Rollback is the exception because it happens during an
	// incident, and requiring a shell on the server first is the wrong shape
	// for that moment.
	admin := func(h http.HandlerFunc) http.Handler {
		return s.requireAuth(s.requirePermission(policy.ActionAdministerData, h))
	}
	// The audit journal. Behind the broad tier: it is the record of everything
	// anybody did, including who read it, and is not something to hold by
	// virtue of managing accounts.
	// The certificate authorities and their trust bundles. Read-only: a bundle
	// is public by construction — it is what every machine has to hold — but
	// knowing which key is signing and when it expires is operational detail
	// worth the same tier as the rest.
	mux.Handle("GET /api/authorities", admin(s.handleAuthorities))

	mux.Handle("GET /api/audit/events", admin(s.handleListAuditEvents))
	mux.Handle("POST /api/audit/verify", admin(s.handleVerifyAuditChain))

	// Composing rules. The same tier as activating a version, and for the same
	// reason: a rule decides who may reach what, including who may compose the
	// next one.
	// The Shared Signals configuration document, unauthenticated like the OIDC
	// one beside it: a receiver reads it before it holds any credential.
	mux.HandleFunc("GET /.well-known/ssf-configuration", s.handleSSFConfiguration)

	// ── SCIM 2.0 ────────────────────────────────────────────────────────────
	//
	// Its own path prefix rather than /api, because identity providers are
	// configured with a base URL and every one of them appends /Users to it.
	//
	// requireProvision is both halves of ADR 0031: the token must carry the
	// scim scope, and policy must permit its owner to Provision. Neither
	// implies the other, and the discovery documents sit behind it too — what
	// this deployment supports is not something to tell an unauthenticated
	// caller.
	scimRoute := func(h http.HandlerFunc) http.Handler { return s.requireProvision(h) }

	mux.Handle("GET /scim/v2/ServiceProviderConfig",
		scimRoute(s.handleSCIMServiceProviderConfig))
	mux.Handle("GET /scim/v2/ResourceTypes", scimRoute(s.handleSCIMResourceTypes))
	mux.Handle("GET /scim/v2/Schemas", scimRoute(s.handleSCIMSchemas))

	mux.Handle("GET /scim/v2/Users", scimRoute(s.handleSCIMListUsers))
	mux.Handle("POST /scim/v2/Users", scimRoute(s.handleSCIMCreateUser))
	mux.Handle("GET /scim/v2/Users/{id}", scimRoute(s.handleSCIMGetUser))
	mux.Handle("PUT /scim/v2/Users/{id}", scimRoute(s.handleSCIMReplaceUser))
	mux.Handle("PATCH /scim/v2/Users/{id}", scimRoute(s.handleSCIMPatchUser))
	mux.Handle("DELETE /scim/v2/Users/{id}", scimRoute(s.handleSCIMDeleteUser))

	mux.Handle("GET /scim/v2/Groups", scimRoute(s.handleSCIMListGroups))
	mux.Handle("POST /scim/v2/Groups", scimRoute(s.handleSCIMCreateGroup))
	mux.Handle("GET /scim/v2/Groups/{id}", scimRoute(s.handleSCIMGetGroup))
	mux.Handle("PATCH /scim/v2/Groups/{id}", scimRoute(s.handleSCIMPatchGroup))
	mux.Handle("DELETE /scim/v2/Groups/{id}", scimRoute(s.handleSCIMDeleteGroup))

	mux.Handle("GET /api/policy/rules", admin(s.handleListRules))
	mux.Handle("POST /api/policy/rules", admin(s.handleAddRule))
	mux.Handle("DELETE /api/policy/rules/{id}", admin(s.handleRemoveRule))

	mux.Handle("GET /api/policy/versions", admin(s.handleListPolicyVersions))
	mux.Handle("GET /api/policy/versions/{version}", admin(s.handleGetPolicyVersion))
	mux.Handle("POST /api/policy/versions/{version}/activate",
		admin(s.handleActivatePolicyVersion))

	// ── OpenID Connect ─────────────────────────────────────────────────────
	if s.oidc != nil {
		// The library serves discovery, /authorize, /token, /userinfo and JWKS
		// on its own paths. Mounted directly rather than proxied, so its
		// well-known URLs are where every client expects them.
		// Everything the library owns lives under /oidc/, except discovery,
		// whose path is fixed by the specification. Cardinal's own bridge
		// handlers are registered after, and the more specific pattern wins in
		// Go's ServeMux.
		oidcHandler := s.oidc.Handler()

		// Cardinal's own discovery document, not the library's: the library
		// hardcodes response and grant types that no client here can use.
		mux.Handle("/.well-known/openid-configuration", s.oidc.DiscoveryHandler())
		mux.Handle("/oidc/", oidcHandler)

		// The hand-off between the library and Cardinal's own authentication.
		// More specific than "/oidc/", so it takes precedence.
		mux.HandleFunc("GET /oidc/login", s.handleOIDCLogin)
		mux.Handle("GET /api/oidc/pending",
			s.requireAuth(http.HandlerFunc(s.handlePendingAuthorization)))
		mux.Handle("POST /api/oidc/consent",
			s.requireAuth(http.HandlerFunc(s.handleConsentDecision)))
		mux.Handle("GET /api/oidc/resume",
			s.requireAuth(http.HandlerFunc(s.handleOIDCResume)))

		// Standing consents, and withdrawing them. Available whether or not any
		// client currently requires consent: a client's setting can change
		// after agreement was given, and the user must still be able to see and
		// undo what they agreed to.
		mux.Handle("GET /api/consents",
			s.requireAuth(http.HandlerFunc(s.handleListConsents)))
		mux.Handle("DELETE /api/consents/{clientID}",
			s.requireAuth(http.HandlerFunc(s.handleRevokeConsent)))
	}

	mux.HandleFunc("GET /api/health", s.handleHealth)

	if s.ui != nil {
		mux.Handle("/", s.spaHandler())
	}

	// Order matters: security headers outermost so they apply even to
	// responses produced by the layers below, then session resolution, then
	// CSRF, which needs to know whether a session exists.
	var h http.Handler = mux
	h = s.csrfProtect(h)
	h = s.authenticate(h)
	h = securityHeaders(s.devMode)(h)
	h = announceVersion(h)
	h = requestLogger(s.log)(h)
	return h
}

// announceVersion stamps every response with the release that produced it.
//
// Every response, including errors, which is the point: the case this exists
// for is an agent newer than the server asking for a route the server does not
// have. That answer is a 404, and a 404 with no version on it is
// indistinguishable from a typo in a path — so the agent logged a generic fetch
// failure and carried on serving its cache, which is a degradation that hides
// itself.
func announceVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set before the handler runs, so it survives a handler that writes a
		// status and returns without touching headers again.
		w.Header().Set(version.Header, version.Number)
		next.ServeHTTP(w, r)
	})
}

// spaHandler serves the embedded single-page app.
//
// Unknown paths fall back to index.html so client-side routing works on a hard
// refresh — but only for paths that are not API routes and do not look like a
// missing asset, so a genuine 404 for a stale bundle is not disguised as a
// working page.
func (s *Server) spaHandler() http.Handler {
	files := http.FileServer(http.FS(s.ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(s.ui, path); err == nil {
			files.ServeHTTP(w, r)
			return
		}

		// A missing asset must 404 rather than quietly render the app: a stale
		// bundle asking for a chunk that no longer exists would otherwise
		// receive index.html, fail to parse it as JavaScript, and produce a
		// blank page with a syntax error instead of a clear 404.
		//
		// The test for "asset" is the path's prefix, not whether it contains a
		// dot. It was the dot, and that 404'd every deep link to an entity whose
		// name has one — which is every host with a fully-qualified name, and
		// logins and group names too, since a dot is legal in all of them
		// (`namePattern` in internal/directory). /directory/hosts/web-01.prod
		// was a server 404 while /directory/hosts worked, so the bug only
		// appeared on a hard refresh or a pasted link.
		//
		// Vite emits everything hashed under assets/, and the only other files
		// are index.html and the favicon, both of which exist — so anything
		// missing under assets/ is genuinely gone and anything else is a route.
		if strings.HasPrefix(path, "assets/") {
			http.NotFound(w, r)
			return
		}

		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		files.ServeHTTP(w, r2)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unreachable")
		return
	}
	// The version goes here rather than only in a CLI, because health is the
	// one endpoint every deployment already polls: a load balancer, a probe, a
	// person with curl. "Which build is that node running" is otherwise a
	// question you can only answer by getting a shell on it, which is exactly
	// what you cannot do during a rolling deploy that went wrong.
	// The policy version for the same reason as the build. Policy is loaded
	// asynchronously — serve.go polls for an activated version every ten
	// seconds — so a node can be enforcing a set the database no longer calls
	// active, and until this was here nothing outside the process could tell.
	// That is the state somebody is asking about after a publish, a rollback, or
	// a rolling deploy where one node picked it up and another has not.
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"version":       version.String(),
		"policyVersion": s.PolicyVersion(),
	})
}

// ── helpers ────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body) //nolint:errcheck // the header is already written, so the status cannot be changed
	}
}

type errorBody struct {
	Error string `json:"error"`
}

// writeError sends a deliberately unhelpful message.
//
// Authentication failures must not distinguish "no such user" from "wrong
// credential" from "account disabled": each distinction is a username
// enumeration oracle. Detail goes to the log, not the response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorBody{Error: withoutPackagePrefix(message)})
}

// internalPrefixes are the package names Cardinal's own errors carry.
//
// Wrapped errors are written `fmt.Errorf("store: ...")` so a log line says
// which layer failed, which is the right thing for a log. Three dozen handlers
// then pass err.Error() straight to the client, and the prefix goes with it —
// so an administrator correcting a typo in a hostname was told "store: a
// hostname cannot be blank", and somebody adding a group to itself got
// "temporal: a group cannot be a member of itself". The sentences are good.
// The package names are implementation detail standing in front of them.
//
// An explicit list rather than a regexp for anything before a colon: messages
// legitimately contain colons — a URL, a duration, a quoted identifier — and a
// pattern would eat the front of those.
var internalPrefixes = []string{
	"store: ", "directory: ", "temporal: ", "policy: ", "auth: ",
	"ssf: ", "scim: ", "config: ", "event: ", "claims: ", "hostclient: ",
}

// withoutPackagePrefix strips one leading package name from a client-facing
// message. Only the response is changed; the log keeps the whole thing, which
// is where the layer is worth knowing.
func withoutPackagePrefix(message string) string {
	for _, prefix := range internalPrefixes {
		if after, found := strings.CutPrefix(message, prefix); found {
			return after
		}
	}
	return message
}

// decodeJSON reads a request body with a size cap, so a malicious client cannot
// exhaust memory by streaming an unbounded document.
func decodeJSON(r *http.Request, dst any) error {
	const maxBody = 1 << 20 // 1 MiB; WebAuthn responses are a few KiB at most
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("malformed request body")
	}
	return nil
}

// PolicyVersion reports which set is live, or 0 when none is.
func (s *Server) PolicyVersion() int64 {
	if engine := s.policy.Load(); engine != nil {
		return engine.Version()
	}
	return 0
}
