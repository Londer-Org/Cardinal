package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/claims"
	"github.com/arthur-lonfils/cardinal/internal/policy"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/cedar-policy/cedar-go/types"
)

// Administering the directory is a Cedar decision like any other.
//
// This is the row of ADR 0005's table that matters most: Cardinal's own access
// control runs through the same engine as web access, SSH and sudo, so there is
// no separate, arcane admin ACL language of the kind LDAP has. Membership of
// directory-admins is a permit; the forbid rule for fresh, device-bound
// credentials applies on top of it and always wins.

// adminResource is what admin actions are evaluated against.
//
// A single resource rather than one per object. Cardinal does not yet express
// per-object administration ("may edit this group but not that one"), and
// inventing a resource hierarchy the policy set cannot use would suggest a
// granularity that does not exist.
var adminResource = types.NewEntityUID(policy.TypeApplication, "cardinal")

// errNoPolicy is distinct from a denial. No policy loaded is an outage, and the
// caller should be told to come back rather than told they lack permission.
var errNoPolicy = errors.New("httpapi: no policy is active")

// requirePermission gates a handler behind one administrative action.
//
// Every refusal is logged as a decision, so "why can't I do this?" is
// answerable from the decision explorer with the deciding policy named —
// including the common case of an admin whose authentication has simply gone
// stale, which otherwise looks identical to not being an admin at all.
func (s *Server) requirePermission(action types.EntityUID, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		session, ok := SessionFrom(ctx)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		resource := r.Method + " " + r.URL.Path

		decision, subject, err := s.decideAction(ctx, session, action)
		if err != nil {
			s.log.ErrorContext(ctx, "admin authorization failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, "authorization unavailable")
			return
		}
		s.logAdminDecision(ctx, subject, decision, action.ID.String(), resource)

		if !decision.Allowed {
			// The deciding policy is named in the response, not only the log.
			// "Access denied" with no reason is the thing this project exists
			// to stop doing — and here the fix is usually the user's to make:
			// re-authenticate with a security key.
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":  adminDenialMessage(decision),
				"policy": decision.Reasons,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// adminDenialMessage turns a decision into something actionable.
//
// More than one forbid could fire at once, and which one is reported decides
// where the reader goes next — so this checks by name rather than taking
// whichever Cedar returned first.
func adminDenialMessage(decision policy.Decision) string {
	if slices.Contains(decision.Reasons, "admin-requires-fresh-device-bound-auth") {
		// No longer "sign in again": that was the only way to become fresh
		// before step-up existed, and repeating it now would send someone to
		// sign out of a session that is working.
		return "this needs a security key used in the last five minutes — " +
			"confirm with your key to continue"
	}
	// No reasons at all means nothing matched, i.e. default-deny. That is a
	// different sentence from "a rule forbids you", and sends the reader
	// somewhere different.
	if len(decision.Reasons) == 0 {
		return "you are not a member of directory-admins"
	}
	return "you are not permitted to administer the directory"
}

// decideAction evaluates one administrative action without recording anything.
//
// Separate from logging because /api/auth/me asks this question on every page
// load to decide what to render. Recording those would bury the decisions that
// matter — an actual attempt to administer something — under routine
// navigation, and the decision explorer would become unreadable.
func (s *Server) decideAction(ctx context.Context, session *store.Session, action types.EntityUID) (policy.Decision, *claims.Subject, error) {
	subject, err := s.claims.Resolve(ctx, session)
	if err != nil {
		// A disabled account holding a live session lands here. Refusing is
		// what makes disabling take effect immediately.
		return policy.Decision{}, nil, err
	}

	engine := s.policy.Load()
	if engine == nil {
		// No policy means no basis for allowing anything. An admin API that
		// fell open when policy failed to load would be the worst possible
		// failure mode.
		return policy.Decision{}, nil, errNoPolicy
	}

	decision := engine.Evaluate(policy.Request{
		Subject:  subject,
		Action:   action,
		Resource: adminResource,
	})
	return decision, subject, nil
}

// logAdminDecision records an attempt to administer something.
func (s *Server) logAdminDecision(ctx context.Context, subject *claims.Subject, decision policy.Decision, action, resource string) {
	principalID := subject.ID
	if err := s.store.LogDecision(ctx, store.DecisionRecord{
		DecisionPoint: "adminAPI",
		PrincipalID:   &principalID,
		Action:        action,
		Resource:      resource,
		Allowed:       decision.Allowed,
		Reasons:       decision.Reasons,
		Errors:        decision.Errors,
		PolicyVersion: decision.Version,
		Context: map[string]any{
			"auth_method":  subject.Auth.Method,
			"device_bound": subject.Auth.DeviceBound,
			"groups":       subject.GroupNames(),
		},
		Duration: decision.Duration,
	}); err != nil {
		// Best-effort, as everywhere else: an observability outage must not
		// become an availability one.
		s.log.ErrorContext(ctx, "admin decision log write failed", "error", err)
	}

	if len(decision.Errors) > 0 {
		s.log.ErrorContext(ctx, "admin policy evaluation errors",
			"errors", decision.Errors)
	}
}

// adminStatus is what the UI needs to render the admin section sensibly.
type adminStatus struct {
	// Allowed is true when the session can do something administrative right
	// now, without touching a key first.
	Allowed bool

	// ManageUsers and ManageApplications say what this person is entitled to,
	// not what they can do this second. A section that disappears when
	// authentication goes stale reads as a broken system; one that stays and
	// asks for a key reads as a policy.
	ManageUsers        bool
	ManageApplications bool

	// AdministerDirectory is the broad tier, which the narrower two do not
	// imply. Recovery lives behind it: restoring an account that can already
	// sign in can mint a credential on an administrator's own account, so a
	// user-admin is deliberately not allowed to start one. The UI needs to know
	// that separately, or it asks a question it will be refused for — and a
	// refusal recorded against someone who only loaded a page makes the
	// decision log describe an intent nobody had.
	AdministerDirectory bool

	// NeedsReauth distinguishes "you are not an administrator" from "you are,
	// but your authentication has gone stale". Without it the section simply
	// vanishes five minutes after signing in, which reads as a bug rather than
	// as a policy — and leaves the user with no idea that tapping their key
	// would bring it back.
	NeedsReauth bool
}

// adminStatusFor answers without the HTTP shape, for /api/auth/me.
//
// Not a security boundary — every admin endpoint evaluates the policy itself —
// but a section someone cannot use should say why rather than disappear.
func (s *Server) adminStatusFor(ctx context.Context, session *store.Session) adminStatus {
	// Asked twice: once as the session stands, and once as it would be with a
	// key touched just now.
	//
	// The tiers report the second answer, so a section does not vanish the
	// moment authentication goes stale — it stays, and touching a key fills it
	// in. The first answer is only used to decide whether to ask.
	//
	// The freshness rule is a forbid on every principal, so its firing says
	// nothing about membership on its own. Reporting NeedsReauth from that
	// alone would tell an ordinary user with an old session to confirm
	// themselves for a section they could never use.
	fresh := *session
	fresh.AuthAt = time.Now()
	fresh.DeviceBound = true

	var status adminStatus
	for _, tier := range []struct {
		action types.EntityUID
		into   *bool
	}{
		{policy.ActionManageUsers, &status.ManageUsers},
		{policy.ActionManageApplications, &status.ManageApplications},
		{policy.ActionAdministerData, &status.AdministerDirectory},
	} {
		entitled, _, err := s.decideAction(ctx, &fresh, tier.action)
		if err != nil {
			return adminStatus{}
		}
		*tier.into = entitled.Allowed

		if !entitled.Allowed {
			continue
		}

		now, _, err := s.decideAction(ctx, session, tier.action)
		if err != nil {
			return adminStatus{}
		}
		if now.Allowed {
			status.Allowed = true
		} else {
			// Entitled, but not right now. That is the one refusal a user can
			// fix, and the only one worth offering a key for.
			status.NeedsReauth = true
		}
	}
	return status
}
