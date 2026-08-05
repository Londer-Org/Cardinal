package httpapi

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// The decision explorer.
//
// "Why was I denied?" is a product feature here, not a debugging aid. Neither
// FreeIPA nor Keycloak can answer it without a human reading three separate
// configurations, and being able to answer it — for users and for auditors — is
// one of the clearer reasons this project exists.

type decisionResponse struct {
	DecisionPoint string   `json:"decisionPoint"`
	PrincipalID   *string  `json:"principalId"`
	Action        string   `json:"action"`
	Resource      string   `json:"resource"`
	Allowed       bool     `json:"allowed"`
	Reasons       []string `json:"reasons"`
	Errors        []string `json:"errors"`
	PolicyVersion int64    `json:"policyVersion"`
	DurationMS    float64  `json:"durationMs"`

	// Explanation is the sentence a person actually needs. Computed here rather
	// than in the client so the CLI, the UI and a support engineer reading the
	// API all say the same thing.
	Explanation string `json:"explanation"`
}

func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	// Scoped to the caller by default.
	//
	// Reading everyone's decisions is itself privileged — the log reveals who
	// tried to reach what, and when — so it will become a policy check once
	// applications are directory entities. Until then the safe default is that
	// you see only your own.
	principalID := &session.SubjectID

	deniedOnly := r.URL.Query().Get("denied") == "true"

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	records, err := s.store.RecentDecisions(ctx, principalID, deniedOnly, limit)
	if err != nil {
		s.log.ErrorContext(ctx, "reading decisions failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read decisions")
		return
	}

	out := make([]decisionResponse, 0, len(records))
	for _, rec := range records {
		var principal *string
		if rec.PrincipalID != nil {
			id := rec.PrincipalID.String()
			principal = &id
		}
		out = append(out, decisionResponse{
			DecisionPoint: rec.DecisionPoint,
			PrincipalID:   principal,
			Action:        rec.Action,
			Resource:      rec.Resource,
			Allowed:       rec.Allowed,
			Reasons:       rec.Reasons,
			Errors:        rec.Errors,
			PolicyVersion: rec.PolicyVersion,
			DurationMS:    float64(rec.Duration.Microseconds()) / 1000,
			Explanation:   explain(rec.Allowed, rec.Reasons),
		})
	}

	writeJSON(w, http.StatusOK, out)
}

// explain mirrors policy.Decision.Explain for records read back from storage.
//
// The distinction it preserves matters: an empty reason list on a deny means
// nothing matched — default-deny — which sends someone to "request access",
// whereas a named forbid sends them to "this rule exists on purpose, go argue
// with it".
func explain(allowed bool, reasons []string) string {
	switch {
	case allowed && len(reasons) > 0:
		return "Allowed by " + joinPolicies(reasons) + "."
	case allowed:
		return "Allowed."
	case len(reasons) > 0:
		return "Explicitly forbidden by " + joinPolicies(reasons) + "."
	default:
		return "Denied: no policy grants this access."
	}
}

func joinPolicies(ids []string) string {
	switch len(ids) {
	case 0:
		return "no policy"
	case 1:
		return "policy " + ids[0]
	default:
		out := "policies "
		for i, id := range ids {
			if i > 0 {
				out += ", "
			}
			out += id
		}
		return out
	}
}

type policyResponse struct {
	Version     int64     `json:"version"`
	Description string    `json:"description"`
	ActivatedAt time.Time `json:"activatedAt"`
	Digest      string    `json:"digest"`
	Policies    []string  `json:"policies"`
	Document    string    `json:"document"`
}

// handlePolicy returns the live policy set, so the explorer can show the rule
// that fired rather than only its name.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	version, err := s.store.ActivePolicy(ctx)
	if err != nil {
		writeError(w, http.StatusNotFound, "no policy is active")
		return
	}

	engine := s.policy.Load()
	var names []string
	if engine != nil {
		names = engine.PolicyIDs()
	}

	activated := time.Time{}
	if version.ActivatedAt != nil {
		activated = *version.ActivatedAt
	}

	writeJSON(w, http.StatusOK, policyResponse{
		Version:     version.Version,
		Description: version.Description,
		ActivatedAt: activated,
		// Hex digest, so an operator can confirm what is loaded matches what is
		// in git without diffing by eye.
		Digest:   hex.EncodeToString(version.Digest),
		Policies: names,
		Document: version.Document,
	})
}
