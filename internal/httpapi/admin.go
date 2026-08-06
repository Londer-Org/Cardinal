package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"

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
// directory-admins is a permit; the forbid rules for freshness, device-bound
// credentials and break-glass apply on top of it and always win.

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

// requireAdmin gates a handler behind Cardinal::Action::"AdministerDirectory".
//
// Every refusal is logged as a decision, so "why can't I do this?" is
// answerable from the decision explorer with the deciding policy named —
// including the common case of an admin whose authentication has simply gone
// stale, which otherwise looks identical to not being an admin at all.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		session, ok := SessionFrom(ctx)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		resource := r.Method + " " + r.URL.Path

		decision, subject, err := s.decideAdmin(ctx, session)
		if err != nil {
			s.log.ErrorContext(ctx, "admin authorization failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, "authorization unavailable")
			return
		}
		s.logAdminDecision(ctx, subject, decision, resource)

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
// More than one forbid can fire at once, and which one is reported decides
// where the reader goes next. A break-glass session trips the freshness rule
// too — it is not device-bound — but "sign in again with your key" is a dead
// end there, because no amount of re-authenticating makes an emergency session
// able to administer. So the rules are checked in order of what they imply
// about the fix, not in whatever order Cedar returned them.
func adminDenialMessage(decision policy.Decision) string {
	if slices.Contains(decision.Reasons, "break-glass-cannot-administer") {
		return "emergency access cannot administer the directory; it exists to " +
			"restore normal access, not to be worked in. Sign in normally with " +
			"a security key"
	}
	if slices.Contains(decision.Reasons, "admin-requires-fresh-device-bound-auth") {
		return "administering the directory needs a security key used in " +
			"the last five minutes — sign in again with your key"
	}
	// No reasons at all means nothing matched, i.e. default-deny. That is a
	// different sentence from "a rule forbids you", and sends the reader
	// somewhere different.
	if len(decision.Reasons) == 0 {
		return "you are not a member of directory-admins"
	}
	return "you are not permitted to administer the directory"
}

// decideAdmin evaluates the policy without recording anything.
//
// Separate from logging because /api/auth/me asks this question on every page
// load to decide what to render. Recording those would bury the decisions that
// matter — an actual attempt to administer something — under routine
// navigation, and the decision explorer would become unreadable.
func (s *Server) decideAdmin(ctx context.Context, session *store.Session) (policy.Decision, *claims.Subject, error) {
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
		Action:   policy.ActionAdministerData,
		Resource: adminResource,
	})
	return decision, subject, nil
}

// logAdminDecision records an attempt to administer something.
func (s *Server) logAdminDecision(ctx context.Context, subject *claims.Subject, decision policy.Decision, resource string) {
	principalID := subject.ID
	if err := s.store.LogDecision(ctx, store.DecisionRecord{
		DecisionPoint: "adminAPI",
		PrincipalID:   &principalID,
		Action:        "AdministerDirectory",
		Resource:      resource,
		Allowed:       decision.Allowed,
		Reasons:       decision.Reasons,
		Errors:        decision.Errors,
		PolicyVersion: decision.Version,
		Context: map[string]any{
			"auth_method":  subject.Auth.Method,
			"device_bound": subject.Auth.DeviceBound,
			"emergency":    subject.Auth.Emergency,
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

// canAdminister answers the same question without the HTTP shape, for /api/auth/me.
//
// The UI uses it to decide what to show. It is not a security boundary — every
// admin endpoint evaluates the policy itself — but hiding a section someone
// cannot use beats letting them find out by being refused.
func (s *Server) canAdminister(ctx context.Context, session *store.Session) bool {
	decision, _, err := s.decideAdmin(ctx, session)
	return err == nil && decision.Allowed
}
