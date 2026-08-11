package httpapi

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/internal/store"
)

// Policy versions, and rolling back to one.
//
// Publishing and activating were CLI-only, which is defensible: a policy set
// belongs in git and reaches Cardinal from a pipeline, and this deliberately
// does not add an editor. Rolling *back* is the exception.
// It happens during an incident, by whoever is looking at the decision log
// wondering why half the company cannot log in, and requiring them to find a
// shell on the Cardinal server first is the wrong shape for that moment.
//
// Publishing stays out of the console on purpose. A policy set typed into a
// browser is one nobody reviewed, and the whole argument for policy-as-code is
// that it is diffable and testable before it is live.

// maxPolicyVersions bounds the listing.
//
// Fifty. Enough to reach back through a normal release history, and this is a
// picker rather than an archive — the answer to "what changed six months ago"
// is git, where the document came from.
const maxPolicyVersions = 50

type policyVersionResponse struct {
	Version     int64     `json:"version"`
	Description string    `json:"description"`
	Digest      string    `json:"digest"`
	PublishedAt time.Time `json:"publishedAt"`

	Active      bool       `json:"active"`
	ActivatedAt *time.Time `json:"activatedAt"`

	// Live is whether *this* server is currently evaluating it. Distinct from
	// Active, which is what the database says — they differ for the seconds
	// between an activation and each node picking it up, and they differ
	// indefinitely if a version was activated that does not compile.
	Live bool `json:"live"`

	// PolicyCount is how many rules the document contains, so a version that
	// accidentally dropped half the set is visible in the list rather than
	// only after activating it.
	PolicyCount int `json:"policyCount"`

	// Invalid means the stored document no longer compiles. Worth surfacing in
	// the list, because it is the one version somebody must not roll back to
	// and it looks exactly like the others.
	Invalid bool `json:"invalid"`
}

func (s *Server) describeVersion(v *store.PolicyVersion, live int64) policyVersionResponse {
	out := policyVersionResponse{
		Version:     v.Version,
		Description: v.Description,
		Digest:      hex.EncodeToString(v.Digest),
		PublishedAt: v.CreatedAt,
		Active:      v.Active(),
		ActivatedAt: v.ActivatedAt,
		Live:        v.Version == live,
	}

	// Compiled rather than counted with a regular expression: the number that
	// matters is how many rules the engine would load, which is not the same as
	// how many `permit` keywords appear in the text.
	engine, err := policy.NewEngine([]byte(v.Document), v.Version)
	if err != nil {
		out.Invalid = true
		return out
	}
	out.PolicyCount = len(engine.PolicyIDs())
	return out
}

func (s *Server) handleListPolicyVersions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	versions, err := s.store.ListPolicyVersions(ctx, maxPolicyVersions)
	if err != nil {
		s.log.ErrorContext(ctx, "listing policy versions failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list policy versions")
		return
	}

	live := s.PolicyVersion()
	out := make([]policyVersionResponse, 0, len(versions))
	for _, v := range versions {
		out = append(out, s.describeVersion(v, live))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"versions": out,
		// What this server is enforcing right now, so the console can say so
		// rather than inferring it from a row.
		"live": live,
	})
}

// handleGetPolicyVersion returns one version's document, so it can be read and
// compared against the live one before anybody activates it.
func (s *Server) handleGetPolicyVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	version, err := strconv.ParseInt(r.PathValue("version"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such policy version")
		return
	}

	stored, err := s.store.PolicyVersionByNumber(ctx, version)
	if err != nil {
		if errors.Is(err, store.ErrNoSuchPolicyVersion) {
			writeError(w, http.StatusNotFound, "no such policy version")
			return
		}
		s.log.ErrorContext(ctx, "reading a policy version failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the version")
		return
	}

	described := s.describeVersion(stored, s.PolicyVersion())
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  described,
		"document": stored.Document,
	})
}

// handleActivatePolicyVersion rolls the live set to a published version.
//
// Two things happen here that the CLI does not do, and both matter more than
// the row update:
//
//   - The document is compiled before anything is written. Activating a set
//     that does not compile leaves every node unable to load it, and each one
//     keeps serving whatever it had — so the fleet ends up split across
//     versions with nothing on screen to say so. Refusing early makes it a
//     failed button press instead.
//
//   - This server reloads immediately rather than waiting for its own watcher.
//     Whoever pressed the button is about to check whether it worked, and ten
//     seconds of the old rules still being enforced reads as the button not
//     working. Other nodes converge on the watcher's interval.
func (s *Server) handleActivatePolicyVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	version, err := strconv.ParseInt(r.PathValue("version"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such policy version")
		return
	}

	stored, err := s.store.PolicyVersionByNumber(ctx, version)
	if err != nil {
		if errors.Is(err, store.ErrNoSuchPolicyVersion) {
			writeError(w, http.StatusNotFound, "no such policy version")
			return
		}
		s.log.ErrorContext(ctx, "reading a policy version failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the version")
		return
	}

	engine, err := policy.NewEngine([]byte(stored.Document), stored.Version)
	if err != nil {
		writeError(w, http.StatusBadRequest,
			"this version no longer compiles, so no server could enforce it: "+err.Error())
		return
	}

	actorID := session.SubjectID
	if err := s.store.ActivatePolicy(ctx, version, &actorID); err != nil {
		s.log.ErrorContext(ctx, "activating a policy version failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not activate that version")
		return
	}

	s.ReloadPolicy(ctx, engine)
	s.log.WarnContext(ctx, "policy set activated from the console",
		"version", version, "by", session.SubjectID)

	writeJSON(w, http.StatusOK, map[string]any{
		"live":        version,
		"policyCount": len(engine.PolicyIDs()),
	})
}
