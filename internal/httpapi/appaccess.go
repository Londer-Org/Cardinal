package httpapi

import (
	"context"
	"net/http"

	"github.com/cedar-policy/cedar-go/types"
	"go.londer.be/cardinal/internal/policy"
	"go.londer.be/cardinal/internal/store"
)

// Who may sign in to which application.
//
// The question forwardAuth answers for proxied applications, asked again for
// applications that speak OIDC directly — because those are reached without the
// proxy, so no forwardAuth call ever happens for them. Without this, "Cardinal
// can authenticate you" and "Cardinal decides you may use this" were the same
// thing, which is not what anyone coming from Keycloak expects.
//
// Checked on every path that can complete an authorization, for the same reason
// consent is: a check the SPA performs is a check that anything skipping the SPA
// skips.

// applicationAccess is the outcome of asking.
type applicationAccess struct {
	Allowed bool

	// Reasons name the deciding policies, so a refusal can say which rule
	// produced it rather than only that one did.
	Reasons []string
}

// canAccessApplication evaluates AccessApplication for a subject and client.
//
// The resource is the application's directory name rather than its client id.
// An operator writes `resource == Cardinal::Application::"grafana"`, and a rule
// naming an opaque 43-character identifier is one nobody will read, let alone
// review. The client id travels in the context, so a decision log can still tie
// the record to exactly one registration.
func (s *Server) canAccessApplication(ctx context.Context, session *store.Session, client *store.OIDCClient) (applicationAccess, error) {
	subject, err := s.claims.Resolve(ctx, session)
	if err != nil {
		// A disabled account holding a live session lands here. Refusing is
		// what makes disabling take effect immediately.
		return applicationAccess{}, err
	}

	engine := s.policy.Load()
	if engine == nil {
		// No policy is no basis for allowing anything.
		return applicationAccess{}, errNoPolicy
	}

	decision := engine.Evaluate(policy.Request{
		Subject:  subject,
		Action:   policy.ActionAccessApplication,
		Resource: types.NewEntityUID(policy.TypeApplication, types.String(client.Name)),
		Context: map[string]types.Value{
			"clientId":    types.String(client.ClientID),
			"application": types.String(client.Name),
		},
	})

	principalID := subject.ID
	if err := s.store.LogDecision(ctx, store.DecisionRecord{
		DecisionPoint: "oidcAuthorize",
		PrincipalID:   &principalID,
		Action:        "AccessApplication",
		Resource:      client.Name,
		Allowed:       decision.Allowed,
		Reasons:       decision.Reasons,
		Errors:        decision.Errors,
		PolicyVersion: decision.Version,
		Context: map[string]any{
			"client_id":    client.ClientID,
			"auth_method":  subject.Auth.Method,
			"device_bound": subject.Auth.DeviceBound,
			"groups":       subject.GroupNames(),
		},
		Duration: decision.Duration,
	}); err != nil {
		// Best-effort, as everywhere else: an observability outage must not
		// become an availability one.
		s.log.ErrorContext(ctx, "application access decision log write failed", "error", err)
	}

	if len(decision.Errors) > 0 {
		s.log.ErrorContext(ctx, "application access policy evaluation errors",
			"errors", decision.Errors)
	}

	return applicationAccess{Allowed: decision.Allowed, Reasons: decision.Reasons}, nil
}

// denyApplicationAccess writes the refusal.
//
// 403 with the deciding policy named, matching the admin API. The message says
// the application by name, because "access denied" leaves someone unable to
// tell whether they are locked out of one thing or everything.
func (s *Server) denyApplicationAccess(w http.ResponseWriter, client *store.OIDCClient, access applicationAccess) {
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error": "you do not have access to " + client.Name +
			" — ask an administrator if you think you should",
		"policy": access.Reasons,
	})
}
