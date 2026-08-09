package httpapi

import (
	"context"
	"fmt"
	"net/http"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/server/policy"
)

// Building policy rules from the console.
//
// The same operation the CLI performs, over HTTP: read the live document, add
// or remove one rule, publish the result as an ordinary version and activate
// it. Nothing here is a second representation of policy — what is stored is
// Cedar, what is enforced is Cedar, and a rule this cannot express travels
// through untouched with its comments.
//
// Behind the broad administration tier, like activating a version. Composing a
// rule decides who may reach what, including who may compose the next one, so
// it is not something to hold by virtue of managing accounts.

type ruleResponse struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`

	// Composable is false for the forbids and the administration tiers. The
	// console shows those as text and offers no remove button: they are the
	// guardrails the other rules sit inside, and changing one goes through the
	// policy file where it is reviewed as text.
	Composable bool `json:"composable"`

	// Summary is the rule as a sentence, with groups named rather than
	// identified. The identifiers are what is stored, because names are
	// mutable; the names are what a person can read.
	Summary string `json:"summary"`

	PrincipalGroup string   `json:"principalGroup"`
	Resource       string   `json:"resource"`
	ResourceKind   string   `json:"resourceKind"`
	LocalAccounts  []string `json:"localAccounts"`

	// Missing names what this rule refers to and the directory does not have.
	// A rule naming a group that is not there never matches, and Cedar being
	// default-deny makes that look exactly like the rule working.
	Missing []string `json:"missing"`

	Source string `json:"source"`
}

// groupNamesByID maps identifiers to names, for display.
func (s *Server) groupNamesByID(ctx context.Context) map[string]string {
	out := map[string]string{}
	groups, err := s.store.ListEntities(ctx, directory.TypeGroup, true)
	if err != nil {
		// A listing showing identifiers is worse than one showing names and far
		// better than no listing at all.
		s.log.WarnContext(ctx, "could not resolve group names for the rule list",
			"error", err)
		return out
	}
	for _, g := range groups {
		out[g.ID.String()] = g.Name
	}
	return out
}

func (s *Server) describeRule(
	ctx context.Context, r policy.Rule, names map[string]string,
) ruleResponse {
	display := r
	display.PrincipalGroup = displayName(names, r.PrincipalGroup)
	display.ResourceGroup = displayName(names, r.ResourceGroup)

	out := ruleResponse{
		ID:             r.ID,
		Kind:           string(r.Kind),
		Composable:     r.Composable(),
		Summary:        policy.Describe(display),
		PrincipalGroup: display.PrincipalGroup,
		LocalAccounts:  r.LocalAccounts,
		Source:         r.Source,
		Missing:        []string{},
	}
	switch {
	case r.ResourceApplication != "":
		out.Resource, out.ResourceKind = r.ResourceApplication, "application"
	case r.ResourceGroup == policy.Anything:
		out.Resource, out.ResourceKind = policy.Anything, "anything"
	default:
		out.Resource, out.ResourceKind = display.ResourceGroup, "group"
	}
	if out.LocalAccounts == nil {
		out.LocalAccounts = []string{}
	}

	// Only what this rule names, checked one rule at a time so the report sits
	// beside the rule rather than in a summary somebody has to correlate.
	for kind, identifier := range map[string]string{
		"group":       r.PrincipalGroup,
		"resource":    r.ResourceGroup,
		"application": r.ResourceApplication,
	} {
		if identifier == "" || identifier == policy.Everyone || identifier == policy.Anything {
			continue
		}
		lookupKind := "group"
		if kind == "application" {
			lookupKind = "application"
		}
		found, err := s.store.PolicyReferenceExists(ctx, lookupKind, identifier)
		if err == nil && !found {
			out.Missing = append(out.Missing, identifier)
		}
	}
	return out
}

func displayName(names map[string]string, id string) string {
	if id == "" || id == policy.Everyone || id == policy.Anything {
		return id
	}
	if name, ok := names[id]; ok {
		return name
	}
	return id
}

// handleListRules describes the live policy set, rule by rule.
func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	active, err := s.store.ActivePolicy(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "no policy set is active")
		return
	}
	rules, err := policy.Parse(active.Document)
	if err != nil {
		s.log.ErrorContext(ctx, "parsing the active policy failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the policy set")
		return
	}

	names := s.groupNamesByID(ctx)
	out := make([]ruleResponse, 0, len(rules))
	for _, rule := range rules {
		out = append(out, s.describeRule(ctx, rule, names))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": active.Version,
		"rules":   out,
	})
}

type addRuleRequest struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`

	// Names, not identifiers. The console shows names and this resolves them,
	// so a rename cannot change what a stored rule means and a person never has
	// to copy a UUID out of one page into another.
	PrincipalGroup      string   `json:"principalGroup"`
	ResourceGroup       string   `json:"resourceGroup"`
	ResourceApplication string   `json:"resourceApplication"`
	Anything            bool     `json:"anything"`
	LocalAccounts       []string `json:"localAccounts"`
}

// handleAddRule composes a rule and publishes the result.
func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req addRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rule := policy.Rule{
		ID:             req.ID,
		Kind:           policy.RuleKind(req.Kind),
		PrincipalGroup: policy.Everyone,
		LocalAccounts:  req.LocalAccounts,
	}

	if req.PrincipalGroup != "" && req.PrincipalGroup != policy.Everyone {
		group, err := s.store.LookupEntity(ctx, directory.TypeGroup, req.PrincipalGroup)
		if err != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("no group called %q", req.PrincipalGroup))
			return
		}
		rule.PrincipalGroup = group.ID.String()
	}

	switch {
	case req.ResourceApplication != "":
		// Checked rather than trusted, so a typo is a refused request instead
		// of a rule that silently never matches.
		if _, err := s.store.LookupEntity(
			ctx, directory.TypeApplication, req.ResourceApplication,
		); err != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("no application called %q", req.ResourceApplication))
			return
		}
		rule.ResourceApplication = req.ResourceApplication
	case req.ResourceGroup != "":
		group, err := s.store.LookupEntity(ctx, directory.TypeGroup, req.ResourceGroup)
		if err != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("no group called %q", req.ResourceGroup))
			return
		}
		rule.ResourceGroup = group.ID.String()
	case req.Anything:
		rule.ResourceGroup = policy.Anything
	default:
		writeError(w, http.StatusBadRequest,
			"a rule needs a resource: a group, an application, or every one of them")
		return
	}

	// Names in the comment, identifiers in the rule. Both, and for opposite
	// reasons: the rule must not change meaning when a group is renamed, and
	// the comment is the part a person reads.
	names := s.groupNamesByID(ctx)
	display := rule
	display.PrincipalGroup = displayName(names, rule.PrincipalGroup)
	display.ResourceGroup = displayName(names, rule.ResourceGroup)
	rule.Comment = policy.Describe(display)

	active, err := s.store.ActivePolicy(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "no policy set is active")
		return
	}
	updated, err := policy.Add(active.Document, rule)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.publishRuleChange(w, r, updated,
		"add rule "+rule.ID,
		"policy rule added from the console: "+policy.Describe(display))
}

// handleRemoveRule drops a rule and publishes the result.
func (s *Server) handleRemoveRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	active, err := s.store.ActivePolicy(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "no policy set is active")
		return
	}

	updated, err := policy.Remove(active.Document, id)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.publishRuleChange(w, r, updated,
		"remove rule "+id, "policy rule removed from the console: "+id)
}

// publishRuleChange stores an edited document and makes it live.
//
// Activated rather than staged. `cardinal policy publish` separates the two so
// a hand-edited file can be inspected before it governs anything; here the
// change is one rule that the console described before it was made, and a
// version left inactive would read as the button not having worked. It is still
// an ordinary version, so rolling back is the same one click as any other.
func (s *Server) publishRuleChange(
	w http.ResponseWriter, r *http.Request, document, description, logLine string,
) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	engine, err := policy.NewEngine([]byte(document), 0)
	if err != nil {
		// Unreachable while Add and Remove compile before returning, and worth
		// checking anyway: this is the last point before something no server
		// can load is written to the database.
		writeError(w, http.StatusBadRequest, "the result would not compile: "+err.Error())
		return
	}

	actorID := session.SubjectID
	version, err := s.store.PublishPolicy(ctx, document, description, &actorID)
	if err != nil {
		s.log.ErrorContext(ctx, "publishing a policy version failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not publish the change")
		return
	}
	if activateErr := s.store.ActivatePolicy(ctx, version.Version, &actorID); activateErr != nil {
		s.log.ErrorContext(ctx, "activating a policy version failed", "error", activateErr)
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("published version %d but could not activate it", version.Version))
		return
	}

	// This server reloads immediately rather than waiting for its own watcher:
	// whoever pressed the button is about to check whether it worked, and ten
	// seconds of the old rules reads as the button not working.
	reloaded, err := policy.NewEngine([]byte(document), version.Version)
	if err == nil {
		s.ReloadPolicy(ctx, reloaded)
	}

	s.log.WarnContext(ctx, logLine, "version", version.Version, "by", session.SubjectID)

	writeJSON(w, http.StatusOK, map[string]any{
		"version": version.Version,
		"rules":   len(engine.PolicyIDs()),
	})
}
