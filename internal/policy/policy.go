// Package policy is Cardinal's single authorization decision point.
//
// One Cedar policy set governs web access, SSH certificate issuance, sudo
// rules, and Cardinal's own admin API. The directory's access control is the
// same reviewable, testable policy set as everything else — there is no
// separate vendor-specific ACL language guarding the system itself.
//
// See ADR 0005.
package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/claims"
	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// Cedar entity types. These are the vocabulary a policy author writes against,
// so they are part of the contract and renaming one breaks every policy.
const (
	TypeUser        = types.EntityType("Cardinal::User")
	TypeGroup       = types.EntityType("Cardinal::Group")
	TypeApplication = types.EntityType("Cardinal::Application")
	TypeHost        = types.EntityType("Cardinal::Host")
	TypeAction      = types.EntityType("Cardinal::Action")
)

// Actions, one per decision point.
var (
	ActionAccessURL      = types.NewEntityUID(TypeAction, "AccessURL")
	ActionSSHLogin       = types.NewEntityUID(TypeAction, "SSHLogin")
	ActionRunAsRoot      = types.NewEntityUID(TypeAction, "RunAsRoot")
	ActionAdministerData = types.NewEntityUID(TypeAction, "AdministerDirectory")
)

// AdminGroupID is the built-in directory-admins group.
//
// Created by migration 0008 with a fixed identifier, because the permit rule
// in policies/cardinal.cedar cannot reference a UUID generated at install
// time. Recognisably synthetic on purpose: nobody reading a grant log should
// mistake it for something the system generated.
//
// Declared here rather than only in SQL and Cedar so a test can assert all
// three agree — changing one without the others is exactly the mistake that
// would silently lock everyone out of administration.
const AdminGroupID = "00000000-0000-7000-8000-00000000ad11"

// Decision is the outcome, with everything needed to explain it.
type Decision struct {
	Allowed bool

	// Reasons are the policy IDs that produced this outcome.
	//
	// Empty on a deny is meaningful and distinct from a populated one: it means
	// nothing matched, i.e. default-deny, rather than an explicit forbid. "No
	// policy grants you this" and "a policy specifically forbids you this" send
	// a user to different places.
	Reasons []string

	// Errors are policies that failed to evaluate — a missing attribute, a type
	// mismatch. They never grant access, but they are a bug in the policy set
	// and must be surfaced rather than swallowed.
	Errors []string

	Duration time.Duration
	Version  int64
}

// ExplicitlyDenied distinguishes a forbid from an absence of permit.
func (d Decision) ExplicitlyDenied() bool { return !d.Allowed && len(d.Reasons) > 0 }

// Explain renders the outcome for a human.
//
// This exists because "why was I denied?" is a product feature here, not a
// debugging aid. Neither FreeIPA nor Keycloak can answer it.
func (d Decision) Explain() string {
	switch {
	case d.Allowed && len(d.Reasons) > 0:
		return fmt.Sprintf("Allowed by policy %v.", d.Reasons)
	case d.Allowed:
		return "Allowed."
	case d.ExplicitlyDenied():
		return fmt.Sprintf("Explicitly forbidden by policy %v.", d.Reasons)
	default:
		return "Denied: no policy grants this access."
	}
}

// Request is a question for the policy engine.
type Request struct {
	Subject  *claims.Subject
	Action   types.EntityUID
	Resource types.EntityUID

	// Context carries decision-point specific facts — the HTTP method and path
	// for a web request, the target login for an SSH certificate.
	Context map[string]types.Value
}

// principalUID maps a subject to its Cedar identity.
//
// The immutable UUID, never the login: policy that matched on a name would
// silently change meaning when someone is renamed, which is exactly the class
// of bug ADR 0002 exists to remove.
func principalUID(s *claims.Subject) types.EntityUID {
	return types.NewEntityUID(TypeUser, types.String(s.ID.String()))
}

// buildEntities projects the subject and its groups into Cedar's entity store.
//
// Groups become parents of the principal, so `principal in Cardinal::Group::"…"`
// works for inherited membership without policy authors having to think about
// nesting. The transitive closure is already resolved by the claims layer, and
// crucially it was resolved with expiry applied — an expired grant is simply
// not in the list, so policy cannot accidentally honour it.
func buildEntities(s *claims.Subject) types.EntityMap {
	entities := types.EntityMap{}

	parents := make([]types.EntityUID, 0, len(s.Groups))
	for _, g := range s.Groups {
		uid := types.NewEntityUID(TypeGroup, types.String(g.ID.String()))
		parents = append(parents, uid)

		entities[uid] = types.Entity{
			UID: uid,
			Attributes: types.NewRecord(types.RecordMap{
				"name":  types.String(g.Name),
				"depth": types.Long(g.Depth),
			}),
		}
	}

	principal := principalUID(s)
	entities[principal] = types.Entity{
		UID:     principal,
		Parents: types.NewEntityUIDSet(parents...),
		Attributes: types.NewRecord(types.RecordMap{
			"login":       types.String(s.Login),
			"displayName": types.String(s.DisplayName),

			// The authentication story, so policy can demand step-up. A
			// twelve-hour session is fine for reading and not fine for issuing
			// recovery codes, and only policy should decide where that line is.
			"authMethod":  types.String(s.Auth.Method),
			"deviceBound": types.Boolean(s.Auth.DeviceBound),
			"authAgeSeconds": types.Long(
				max(0, int64(s.Auth.Age().Seconds()))),
		}),
	}

	return entities
}

// Engine evaluates requests against a loaded policy set.
//
// Immutable once built. Reloading policy replaces the whole engine rather than
// mutating one, so a request can never observe a half-applied policy change.
type Engine struct {
	policies *cedar.PolicySet
	version  int64

	// names maps Cedar's positional policy IDs to the @id annotation.
	//
	// cedar-go identifies policies by position — policy0, policy1 — which is
	// useless in a decision log: "denied by policy2" tells an operator nothing
	// six months later, and the numbering shifts the moment someone inserts a
	// policy above it. The annotation is the stable, meaningful name, and
	// NewEngine refuses a policy that lacks one.
	names map[cedar.PolicyID]string
}

// NewEngine compiles a Cedar document.
//
// Every policy must carry an @id annotation. That is enforced here rather than
// left to review because the cost of forgetting is paid later and by someone
// else: a decision log full of "policy2" cannot answer "why was I denied?",
// which is the feature the whole decision point exists to provide.
func NewEngine(document []byte, version int64) (*Engine, error) {
	policies, err := cedar.NewPolicySetFromBytes("cardinal.cedar", document)
	if err != nil {
		return nil, fmt.Errorf("policy: parsing Cedar document: %w", err)
	}

	names := map[cedar.PolicyID]string{}
	var unnamed []string
	for id, p := range policies.All() {
		annotation, ok := p.Annotations()["id"]
		if !ok || strings.TrimSpace(string(annotation)) == "" {
			pos := p.Position()
			unnamed = append(unnamed,
				fmt.Sprintf("%s (line %d)", id, pos.Line))
			continue
		}
		names[id] = string(annotation)
	}
	if len(unnamed) > 0 {
		sort.Strings(unnamed)
		return nil, fmt.Errorf(
			"policy: every policy needs an @id annotation so decisions can name it; "+
				"missing on: %s", strings.Join(unnamed, ", "))
	}

	return &Engine{policies: policies, version: version, names: names}, nil
}

// name resolves a Cedar policy ID to its readable @id.
func (e *Engine) name(id cedar.PolicyID) string {
	if n, ok := e.names[id]; ok {
		return n
	}
	// Unreachable while NewEngine rejects unnamed policies, but returning the
	// raw ID beats returning nothing if that ever changes.
	return string(id)
}

func (e *Engine) Version() int64 { return e.version }

// Evaluate answers a request.
//
// Fails closed by construction: Cedar's default with no matching permit is
// deny, and an evaluation error yields no permit either. There is no path
// through this function that grants access by accident.
func (e *Engine) Evaluate(req Request) Decision {
	start := time.Now()

	entities := buildEntities(req.Subject)

	context := types.RecordMap{}
	for k, v := range req.Context {
		context[types.String(k)] = v
	}

	decision, diagnostic := cedar.Authorize(e.policies, entities, types.Request{
		Principal: principalUID(req.Subject),
		Action:    req.Action,
		Resource:  req.Resource,
		Context:   types.NewRecord(context),
	})

	reasons := make([]string, 0, len(diagnostic.Reasons))
	for _, r := range diagnostic.Reasons {
		reasons = append(reasons, e.name(r.PolicyID))
	}

	// Policies that failed to evaluate — a missing attribute, a type mismatch.
	// They never grant access, but they are a defect in the policy set and
	// swallowing them would let a broken policy look like a working deny.
	errs := make([]string, 0, len(diagnostic.Errors))
	for _, diagErr := range diagnostic.Errors {
		errs = append(errs, fmt.Sprintf("%s: %s", e.name(diagErr.PolicyID), diagErr.Message))
	}

	return Decision{
		Allowed:  decision == cedar.Allow,
		Reasons:  reasons,
		Errors:   errs,
		Duration: time.Since(start),
		Version:  e.version,
	}
}

// PolicyIDs lists the loaded policies by their readable names, for the admin UI.
func (e *Engine) PolicyIDs() []string {
	ids := make([]string, 0, len(e.names))
	for id := range e.policies.All() {
		ids = append(ids, e.name(id))
	}
	sort.Strings(ids)
	return ids
}

// Source returns the Cedar text of a named policy, so the decision explorer can
// show the rule that fired rather than only its name.
func (e *Engine) Source(name string) (string, bool) {
	for id, p := range e.policies.All() {
		if e.name(id) == name {
			return string(p.MarshalCedar()), true
		}
	}
	return "", false
}
