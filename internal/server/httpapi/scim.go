package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/directory/temporal"
	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/internal/server/scim"
	"go.londer.be/cardinal/internal/store"
)

// Provisioning over SCIM.
//
// An identity provider is the source of truth for who exists, and Cardinal is
// the source of truth for what they may do. This is the seam between the two,
// and everything unusual about it follows from ADR 0031:
//
//   - Its own Cedar action, Provision, because the step-up forbid demands a
//     device-bound credential used in the last five minutes and a machine
//     synchronising at 3am has neither.
//   - Its own token scope, so a token issued for anything else can never
//     become a provisioning credential.
//   - No system group, ever. Membership of one confers authority inside
//     Cardinal, and a client that could modify one would be a path from "the
//     IdP integration" to "directory administrator".
//   - No credentials and no POSIX numbers. A passkey is registered by its
//     owner; a uid is permanent once served and an IdP has no idea which are
//     taken.

// scimBase is the path everything here hangs from.
const scimBase = "/scim/v2"

// requireProvision gates every SCIM route.
//
// Both conditions, and neither implies the other: the token must have been
// issued for provisioning, and policy must permit its owner to provision. A
// person who is a member of provisioners still cannot provision with a token
// they created for a build pipeline.
func (s *Server) requireProvision(next http.Handler) http.Handler {
	return s.requireAuth(s.requireScope(ScopeSCIM, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			session, _ := SessionFrom(ctx)

			engine := s.policy.Load()
			if engine == nil {
				scim.WriteError(w, http.StatusServiceUnavailable, "",
					"no policy set is active, so nothing can be authorized")
				return
			}

			subject, err := s.claims.Resolve(ctx, session)
			if err != nil {
				scim.WriteError(w, http.StatusForbidden, "", "access denied")
				return
			}

			decision := engine.Evaluate(policy.Request{
				Subject:  subject,
				Action:   policy.ActionProvision,
				Resource: adminResource,
			})

			principalID := subject.ID
			if logErr := s.store.LogDecision(ctx, store.DecisionRecord{
				DecisionPoint: "scim",
				PrincipalID:   &principalID,
				Action:        "Provision",
				Resource:      r.URL.Path,
				Allowed:       decision.Allowed,
				Reasons:       decision.Reasons,
				Errors:        decision.Errors,
				PolicyVersion: decision.Version,
				Context: map[string]any{
					"method":      r.Method,
					"auth_method": subject.Auth.Method,
				},
				Duration: decision.Duration,
			}); logErr != nil {
				s.log.ErrorContext(ctx, "scim: decision log write failed", "error", logErr)
			}

			if !decision.Allowed {
				scim.WriteError(w, http.StatusForbidden, "", decision.Explain())
				return
			}
			next.ServeHTTP(w, r)
		})))
}

// ── Discovery ───────────────────────────────────────────────────────────────

// handleSCIMServiceProviderConfig says what this implementation does.
//
// The mechanism the specification provides for being honest about gaps. A
// client reads this first and adapts; without it, a missing feature is
// discovered from a failure in the middle of a synchronisation, which is the
// worst possible moment and the hardest to attribute.
func (s *Server) handleSCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	scim.Write(w, http.StatusOK, map[string]any{
		"schemas":          []string{scim.SchemaServiceConfig},
		"documentationUri": strings.TrimRight(s.cfg.Server.PublicURL, "/") + "/docs",
		"patch":            map[string]any{"supported": true},
		// Not supported, and said so rather than discovered. Bulk is a large
		// piece of protocol whose absence a client handles by sending
		// individual requests, which is what they all do anyway.
		"bulk": map[string]any{
			"supported": false, "maxOperations": 0, "maxPayloadSize": 0,
		},
		"filter": map[string]any{"supported": true, "maxResults": scimMaxPageSize},
		// Passwords do not exist here. There is no password column, so there is
		// nothing for a client to change (ADR 0001).
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "Cardinal access token",
			"description": "An access token issued with the scim scope, whose owner policy permits to Provision",
			"primary":     true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig"},
	})
	_ = r
}

func (s *Server) handleSCIMResourceTypes(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(s.cfg.Server.PublicURL, "/") + scimBase
	types := []any{
		map[string]any{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":       "User",
			"name":     "User",
			"endpoint": "/Users",
			"schema":   scim.SchemaUser,
			"meta":     map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/User"},
		},
		map[string]any{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":       "Group",
			"name":     "Group",
			"endpoint": "/Groups",
			"schema":   scim.SchemaGroup,
			"meta":     map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/Group"},
		},
	}
	scim.Write(w, http.StatusOK, scim.NewListResponse(len(types), 1, types))
	_ = r
}

func (s *Server) handleSCIMSchemas(w http.ResponseWriter, r *http.Request) {
	schemas := []any{
		map[string]any{
			"id": scim.SchemaUser, "name": "User",
			"description": "Cardinal user",
			"meta":        map[string]any{"resourceType": "Schema"},
		},
		map[string]any{
			"id": scim.SchemaGroup, "name": "Group",
			"description": "Cardinal group",
			"meta":        map[string]any{"resourceType": "Schema"},
		},
	}
	scim.Write(w, http.StatusOK, scim.NewListResponse(len(schemas), 1, schemas))
	_ = r
}

// ── Projection ──────────────────────────────────────────────────────────────

// scimMaxPageSize bounds what one request returns.
//
// A client asking for everything gets pages rather than a directory-sized
// response, and a client asking for a million gets this instead of an attempt.
const scimMaxPageSize = 200

// scimUser projects a directory entity into the SCIM shape.
//
// Deliberately not through the claims package. That projects a *subject* — who
// somebody is for the purpose of a decision, with an authentication story
// attached — and this projects a record an identity provider owns. Reusing it
// would put an auth context into a provisioning response and couple the two
// together for no gain.
func (s *Server) scimUser(
	ctx context.Context, e *directory.Entity, externalID string, groups []Ref2,
) scim.User {
	u := scim.User{
		Schemas:    []string{scim.SchemaUser},
		ID:         e.ID.String(),
		ExternalID: externalID,
		UserName:   e.Name,
		Active:     e.DisabledAt == nil,
		Meta: scim.Meta{
			ResourceType: "User",
			Created:      e.CreatedAt.UTC().Format(time.RFC3339),
			LastModified: e.UpdatedAt.UTC().Format(time.RFC3339),
			Location:     s.scimLocation("Users", e.ID.String()),
		},
	}
	if e.DisplayName != "" {
		u.DisplayName = e.DisplayName
		u.Name = &scim.Name{Formatted: e.DisplayName}
	}
	if email := entityEmail(e); email != "" {
		u.Emails = []scim.Email{{Value: email, Primary: true, Type: "work"}}
	}
	for _, g := range groups {
		u.Groups = append(u.Groups, scim.Ref{
			Value: g.ID, Display: g.Name, Type: "direct",
			Ref: s.scimLocation("Groups", g.ID),
		})
	}
	_ = ctx
	return u
}

// Ref2 is a group an entity belongs to, for projection.
type Ref2 struct {
	ID   string
	Name string
}

func (s *Server) scimLocation(kind, id string) string {
	return strings.TrimRight(s.cfg.Server.PublicURL, "/") + scimBase + "/" + kind + "/" + id
}

// scimPage reads startIndex and count.
//
// SCIM counts from one, not zero. Getting that wrong drops the first record of
// every page and the symptom is one person missing from a synchronisation,
// which is attributed to almost anything else first.
func scimPage(r *http.Request) (offset, limit, startIndex int) {
	startIndex = 1
	if v, err := strconv.Atoi(r.URL.Query().Get("startIndex")); err == nil && v > 0 {
		startIndex = v
	}
	limit = scimMaxPageSize
	if v, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && v >= 0 {
		limit = min(v, scimMaxPageSize)
	}
	return startIndex - 1, limit, startIndex
}

// ── Users ───────────────────────────────────────────────────────────────────

func (s *Server) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filter, err := scim.ParseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		// 400 with the SCIM type, so a client can tell "I asked for something
		// you do not do" from "your server is broken" and fall back to listing.
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
		return
	}

	offset, limit, startIndex := scimPage(r)

	// A filter on the natural key resolves to at most one record, which is what
	// reconciliation asks for and is far cheaper than a page scan.
	if filter != nil {
		entity, lookupErr := s.scimResolveUser(ctx, *filter)
		if lookupErr != nil {
			if errors.Is(lookupErr, directory.ErrNotFound) {
				scim.Write(w, http.StatusOK, scim.NewListResponse(0, startIndex, nil))
				return
			}
			scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidPath, lookupErr.Error())
			return
		}
		projected, projectErr := s.scimProjectUser(ctx, entity)
		if projectErr != nil {
			s.log.ErrorContext(ctx, "scim: projecting a user failed", "error", projectErr)
			scim.WriteError(w, http.StatusInternalServerError, "", "could not read that user")
			return
		}
		scim.Write(w, http.StatusOK, scim.NewListResponse(1, startIndex, []any{projected}))
		return
	}

	// Disabled accounts included, deliberately. SCIM says deprovisioned rather
	// than deleted — a client sends active:false far more often than DELETE —
	// so a listing that hid them would make every reconciliation try to create
	// the people it had just switched off.
	users, total, listErr := s.store.ListUsers(ctx,
		store.Page{Offset: offset, Limit: limit}, store.UsersAll)
	if listErr != nil {
		s.log.ErrorContext(ctx, "scim: listing users failed", "error", listErr)
		scim.WriteError(w, http.StatusInternalServerError, "", "could not list users")
		return
	}

	out := make([]any, 0, len(users))
	for _, u := range users {
		entity, getErr := s.store.LookupEntity(ctx, directory.TypeUser, u.Login)
		if getErr != nil {
			continue
		}
		projected, projectErr := s.scimProjectUser(ctx, entity)
		if projectErr != nil {
			continue
		}
		out = append(out, projected)
	}
	scim.Write(w, http.StatusOK, scim.NewListResponse(total, startIndex, out))
}

// scimResolveUser turns a supported filter into one entity.
func (s *Server) scimResolveUser(ctx context.Context, f scim.Filter) (*directory.Entity, error) {
	switch f.Attribute {
	case "username":
		return s.store.LookupEntity(ctx, directory.TypeUser, f.Value)
	case "externalid":
		return s.store.EntityByExternalID(ctx, directory.TypeUser, f.Value)
	case "id":
		id, err := uuid.Parse(f.Value)
		if err != nil {
			return nil, directory.ErrNotFound
		}
		return s.store.GetEntity(ctx, id)
	default:
		return nil, scim.ErrUnsupportedFilter{Raw: f.Attribute + " eq …"}
	}
}

func (s *Server) scimProjectUser(ctx context.Context, e *directory.Entity) (scim.User, error) {
	externalID, err := s.store.ExternalIDOf(ctx, e.ID)
	if err != nil {
		return scim.User{}, err
	}

	memberships, err := s.store.GroupsOfMember(ctx, e.ID)
	if err != nil {
		return scim.User{}, err
	}
	groups := make([]Ref2, 0, len(memberships))
	for _, m := range memberships {
		groups = append(groups, Ref2{ID: m.GroupID.String(), Name: m.GroupName})
	}
	return s.scimUser(ctx, e, externalID, groups), nil
}

func (s *Server) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	entity, ok := s.scimUserByPath(w, r)
	if !ok {
		return
	}
	projected, err := s.scimProjectUser(ctx, entity)
	if err != nil {
		s.log.ErrorContext(ctx, "scim: projecting a user failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "could not read that user")
		return
	}
	scim.Write(w, http.StatusOK, projected)
}

func (s *Server) scimUserByPath(w http.ResponseWriter, r *http.Request) (*directory.Entity, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		scim.WriteError(w, http.StatusNotFound, "", "no such user")
		return nil, false
	}
	entity, err := s.store.GetEntity(r.Context(), id)
	if err != nil || entity.Type != directory.TypeUser {
		scim.WriteError(w, http.StatusNotFound, "", "no such user")
		return nil, false
	}
	return entity, true
}

// handleSCIMCreateUser provisions an account.
//
// The account has no credential and cannot be signed into. That is not an
// omission: a passkey is registered by its owner and by nobody else, so
// provisioning creates somebody who exists and must still enrol (ADR 0031).
func (s *Server) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)
	actorID := session.SubjectID

	var in scim.User
	if err := decodeJSON(r, &in); err != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidSyntax, err.Error())
		return
	}
	if strings.TrimSpace(in.UserName) == "" {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue,
			"userName is required and is the login this account will have")
		return
	}

	// An existing account with this login is adopted rather than duplicated.
	// The first synchronisation after pointing an identity provider at an
	// established directory is exactly this case, and creating a second Ada
	// beside the first is the failure it produces.
	if existing, err := s.store.LookupEntity(ctx, directory.TypeUser, in.UserName); err == nil {
		scim.WriteError(w, http.StatusConflict, scim.TypeUniqueness,
			"an account with userName "+in.UserName+" already exists as "+existing.ID.String()+
				" — PATCH or PUT it rather than creating a second")
		return
	}

	entity, err := directory.NewEntity(directory.TypeUser, in.UserName, scimDisplayName(in))
	if err != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
		return
	}
	if email := scimPrimaryEmail(in); email != "" {
		entity.Attrs = map[string]any{"email": email}
	}

	if createErr := s.store.CreateEntity(ctx, entity, &actorID); createErr != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, createErr.Error())
		return
	}
	if in.ExternalID != "" {
		if setErr := s.store.SetExternalID(ctx, entity.ID, in.ExternalID); setErr != nil {
			s.log.ErrorContext(ctx, "scim: recording the external id failed", "error", setErr)
			scim.WriteError(w, http.StatusConflict, scim.TypeUniqueness, setErr.Error())
			return
		}
	}
	// A client that sends active:false on creation means it. Applied after the
	// row exists, because disabling is a separate audited act.
	if !in.Active {
		if disableErr := s.store.DisableEntity(ctx, entity.ID, &actorID); disableErr != nil {
			s.log.ErrorContext(ctx, "scim: disabling a new account failed", "error", disableErr)
		}
	}

	s.log.InfoContext(ctx, "scim: account provisioned",
		"login", entity.Name, "externalId", in.ExternalID, "by", actorID)

	s.scimRespondUser(w, r, entity.ID, http.StatusCreated)
}

// handleSCIMReplaceUser applies a whole record.
func (s *Server) handleSCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)
	actorID := session.SubjectID

	entity, ok := s.scimUserByPath(w, r)
	if !ok {
		return
	}

	var in scim.User
	if err := decodeJSON(r, &in); err != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidSyntax, err.Error())
		return
	}

	if in.UserName != "" && in.UserName != entity.Name {
		if _, err := s.store.RenameEntity(ctx, entity.ID, in.UserName, &actorID); err != nil {
			scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
			return
		}
	}

	display, email := scimDisplayName(in), scimPrimaryEmail(in)
	if _, err := s.store.UpdateProfile(ctx, entity.ID,
		store.ProfileUpdate{DisplayName: &display, Email: &email}, &actorID); err != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
		return
	}

	if err := s.scimSetActive(ctx, entity, in.Active, actorID); err != nil {
		s.log.ErrorContext(ctx, "scim: changing account state failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "could not change that account")
		return
	}

	s.scimRespondUser(w, r, entity.ID, http.StatusOK)
}

// handleSCIMPatchUser applies operations.
//
// In practice identity providers use PATCH for exactly one thing on a user —
// switching active — and everything else through PUT. Both are supported, and
// the narrow path is the one that has to be right.
func (s *Server) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)
	actorID := session.SubjectID

	entity, ok := s.scimUserByPath(w, r)
	if !ok {
		return
	}

	var patch scim.PatchRequest
	if err := decodeJSON(r, &patch); err != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidSyntax, err.Error())
		return
	}

	for _, op := range patch.Operations {
		switch op.Normalised() {
		case "replace", "add":
			if err := s.scimApplyUserSet(ctx, entity, op, actorID); err != nil {
				scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidPath, err.Error())
				return
			}
		case "remove":
			// Removing an attribute means clearing it. Only the two Cardinal
			// stores are clearable; a path it does not know is refused rather
			// than ignored, because an ignored operation reports success and
			// changes nothing.
			if err := s.scimClearUserAttribute(ctx, entity, op, actorID); err != nil {
				scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidPath, err.Error())
				return
			}
		default:
			scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidSyntax,
				"unknown patch operation "+op.Op)
			return
		}
	}

	s.scimRespondUser(w, r, entity.ID, http.StatusOK)
}

// handleSCIMDeleteUser deprovisions.
//
// Disables rather than deletes. Entities are never hard-deleted here — audit
// history has to keep resolving, and a past grant to somebody who no longer
// exists still needs explaining — so DELETE and active:false do the same thing,
// which is also what most identity providers expect.
func (s *Server) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)
	actorID := session.SubjectID

	entity, ok := s.scimUserByPath(w, r)
	if !ok {
		return
	}
	if err := s.store.DisableEntity(ctx, entity.ID, &actorID); err != nil {
		s.log.ErrorContext(ctx, "scim: deprovisioning failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "could not deprovision that account")
		return
	}
	s.log.InfoContext(ctx, "scim: account deprovisioned", "login", entity.Name, "by", actorID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) scimRespondUser(
	w http.ResponseWriter, r *http.Request, id uuid.UUID, status int,
) {
	ctx := r.Context()
	fresh, err := s.store.GetEntity(ctx, id)
	if err != nil {
		scim.WriteError(w, http.StatusInternalServerError, "", "could not read that user back")
		return
	}
	projected, err := s.scimProjectUser(ctx, fresh)
	if err != nil {
		scim.WriteError(w, http.StatusInternalServerError, "", "could not read that user back")
		return
	}
	scim.Write(w, status, projected)
}

func (s *Server) scimSetActive(
	ctx context.Context, e *directory.Entity, active bool, actorID uuid.UUID,
) error {
	switch {
	case active && e.DisabledAt != nil:
		return s.store.EnableEntity(ctx, e.ID, &actorID)
	case !active && e.DisabledAt == nil:
		return s.store.DisableEntity(ctx, e.ID, &actorID)
	default:
		return nil
	}
}

func scimDisplayName(u scim.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if u.Name != nil {
		return u.Name.Formatted
	}
	return ""
}

// scimPrimaryEmail picks one address out of however many arrived.
//
// The primary, or the first when none is marked. Cardinal keeps one address and
// silently keeping the last would make the answer depend on JSON ordering.
func scimPrimaryEmail(u scim.User) string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

// scimApplyUserSet handles one add or replace operation.
//
// The paths are the ones identity providers actually send. A path this does not
// know is refused rather than ignored: an ignored operation makes PATCH report
// success and change nothing, and a client believes it has synchronised.
func (s *Server) scimApplyUserSet(
	ctx context.Context, e *directory.Entity, op scim.Operation, actorID uuid.UUID,
) error {
	// A pathless replace carries a whole object of attributes, which is how
	// Entra sends most of them.
	if strings.TrimSpace(op.Path) == "" {
		var body map[string]json.RawMessage
		if err := json.Unmarshal(op.Value, &body); err != nil {
			return fmt.Errorf("a patch with no path needs an object of attributes: %w", err)
		}
		for key, raw := range body {
			if err := s.scimApplyUserField(ctx, e, key, raw, actorID); err != nil {
				return err
			}
		}
		return nil
	}
	return s.scimApplyUserField(ctx, e, op.Path, op.Value, actorID)
}

func (s *Server) scimApplyUserField(
	ctx context.Context, e *directory.Entity, path string, raw json.RawMessage,
	actorID uuid.UUID,
) error {
	switch strings.ToLower(strings.TrimSpace(path)) {
	case "active":
		var active bool
		if err := json.Unmarshal(raw, &active); err != nil {
			return fmt.Errorf("active must be a boolean: %w", err)
		}
		return s.scimSetActive(ctx, e, active, actorID)

	case "displayname", "name.formatted":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("%s must be a string: %w", path, err)
		}
		_, err := s.store.UpdateProfile(ctx, e.ID,
			store.ProfileUpdate{DisplayName: &value}, &actorID)
		return err

	case "username":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("userName must be a string: %w", err)
		}
		_, err := s.store.RenameEntity(ctx, e.ID, value, &actorID)
		return err

	case "externalid":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("externalId must be a string: %w", err)
		}
		return s.store.SetExternalID(ctx, e.ID, value)

	case "emails":
		// However many arrive, one is kept — the primary, or the first.
		var emails []scim.Email
		if err := json.Unmarshal(raw, &emails); err != nil {
			// Some clients send a bare string for emails[0].value.
			var single string
			if json.Unmarshal(raw, &single) != nil {
				return fmt.Errorf("emails must be a list or a string: %w", err)
			}
			emails = []scim.Email{{Value: single, Primary: true}}
		}
		email := scimPrimaryEmail(scim.User{Emails: emails})
		_, err := s.store.UpdateProfile(ctx, e.ID,
			store.ProfileUpdate{Email: &email}, &actorID)
		return err

	default:
		// Named, and refused. Cardinal keeps a login, a display name and an
		// email; SCIM defines dozens more, and quietly discarding the rest
		// would let a client believe this directory holds a job title.
		return fmt.Errorf(
			"this provider does not store %q. It keeps userName, displayName, "+
				"emails, externalId and active, and refuses the rest rather than "+
				"accepting them and discarding them", path)
	}
}

// scimClearUserAttribute handles remove.
func (s *Server) scimClearUserAttribute(
	ctx context.Context, e *directory.Entity, op scim.Operation, actorID uuid.UUID,
) error {
	empty := ""
	switch strings.ToLower(strings.TrimSpace(op.Path)) {
	case "displayname", "name.formatted":
		_, err := s.store.UpdateProfile(ctx, e.ID,
			store.ProfileUpdate{DisplayName: &empty}, &actorID)
		return err
	case "emails":
		_, err := s.store.UpdateProfile(ctx, e.ID,
			store.ProfileUpdate{Email: &empty}, &actorID)
		return err
	case "externalid":
		return s.store.SetExternalID(ctx, e.ID, "")
	default:
		return fmt.Errorf(
			"nothing at %q can be removed. userName cannot be cleared — an "+
				"account with no login cannot be referred to at all", op.Path)
	}
}

// ── Groups ──────────────────────────────────────────────────────────────────

// scimGroupByPath resolves a group, and refuses a system one.
//
// The check ADR 0031 turns on. Membership of a system group is a grant of
// authority inside Cardinal, so a provisioning client that could modify one
// would be a path from "the IdP integration" to "directory administrator". The
// refusal is 403 rather than 404: pretending the group does not exist would
// send an operator hunting for a synchronisation bug.
func (s *Server) scimGroupByPath(
	w http.ResponseWriter, r *http.Request, forWriting bool,
) (*directory.Entity, bool) {
	ctx := r.Context()

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		scim.WriteError(w, http.StatusNotFound, "", "no such group")
		return nil, false
	}
	entity, err := s.store.GetEntity(ctx, id)
	if err != nil || entity.Type != directory.TypeGroup {
		scim.WriteError(w, http.StatusNotFound, "", "no such group")
		return nil, false
	}

	if forWriting {
		system, sysErr := s.store.IsSystemGroup(ctx, entity.ID)
		if sysErr != nil {
			scim.WriteError(w, http.StatusInternalServerError, "", "could not read that group")
			return nil, false
		}
		if system {
			s.log.WarnContext(ctx, "scim: refused a write to a system group",
				"group", entity.Name)
			scim.WriteError(w, http.StatusForbidden, scim.TypeMutability,
				entity.Name+" confers authority inside Cardinal, so it is not "+
					"provisionable. Membership of it is granted from Cardinal, "+
					"not from an identity provider")
			return nil, false
		}
	}
	return entity, true
}

func (s *Server) scimProjectGroup(ctx context.Context, e *directory.Entity) (scim.Group, error) {
	externalID, err := s.store.ExternalIDOf(ctx, e.ID)
	if err != nil {
		return scim.Group{}, err
	}
	members, err := s.store.MembersOfGroup(ctx, e.ID)
	if err != nil {
		return scim.Group{}, err
	}

	g := scim.Group{
		Schemas:     []string{scim.SchemaGroup},
		ID:          e.ID.String(),
		ExternalID:  externalID,
		DisplayName: e.Name,
		Meta: scim.Meta{
			ResourceType: "Group",
			Created:      e.CreatedAt.UTC().Format(time.RFC3339),
			LastModified: e.UpdatedAt.UTC().Format(time.RFC3339),
			Location:     s.scimLocation("Groups", e.ID.String()),
		},
	}
	for _, m := range members {
		g.Members = append(g.Members, scim.Ref{
			Value: m.MemberID.String(), Display: m.MemberName,
			Ref: s.scimLocation("Users", m.MemberID.String()),
		})
	}
	return g, nil
}

func (s *Server) handleSCIMListGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filter, err := scim.ParseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
		return
	}
	offset, limit, startIndex := scimPage(r)

	if filter != nil {
		var entity *directory.Entity
		var lookupErr error
		switch filter.Attribute {
		case "displayname":
			entity, lookupErr = s.store.LookupEntity(ctx, directory.TypeGroup, filter.Value)
		case "externalid":
			entity, lookupErr = s.store.EntityByExternalID(ctx, directory.TypeGroup, filter.Value)
		default:
			scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidPath,
				"groups can be filtered by displayName or externalId")
			return
		}
		if lookupErr != nil {
			scim.Write(w, http.StatusOK, scim.NewListResponse(0, startIndex, nil))
			return
		}
		projected, projectErr := s.scimProjectGroup(ctx, entity)
		if projectErr != nil {
			scim.WriteError(w, http.StatusInternalServerError, "", "could not read that group")
			return
		}
		scim.Write(w, http.StatusOK, scim.NewListResponse(1, startIndex, []any{projected}))
		return
	}

	groups, total, listErr := s.store.ListGroups(ctx,
		store.Page{Offset: offset, Limit: limit}, "")
	if listErr != nil {
		s.log.ErrorContext(ctx, "scim: listing groups failed", "error", listErr)
		scim.WriteError(w, http.StatusInternalServerError, "", "could not list groups")
		return
	}

	out := make([]any, 0, len(groups))
	for _, g := range groups {
		entity, getErr := s.store.LookupEntity(ctx, directory.TypeGroup, g.Name)
		if getErr != nil {
			continue
		}
		projected, projectErr := s.scimProjectGroup(ctx, entity)
		if projectErr != nil {
			continue
		}
		out = append(out, projected)
	}
	scim.Write(w, http.StatusOK, scim.NewListResponse(total, startIndex, out))
}

func (s *Server) handleSCIMGetGroup(w http.ResponseWriter, r *http.Request) {
	entity, ok := s.scimGroupByPath(w, r, false)
	if !ok {
		return
	}
	projected, err := s.scimProjectGroup(r.Context(), entity)
	if err != nil {
		scim.WriteError(w, http.StatusInternalServerError, "", "could not read that group")
		return
	}
	scim.Write(w, http.StatusOK, projected)
}

func (s *Server) handleSCIMCreateGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)
	actorID := session.SubjectID

	var in scim.Group
	if err := decodeJSON(r, &in); err != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidSyntax, err.Error())
		return
	}
	if strings.TrimSpace(in.DisplayName) == "" {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue,
			"displayName is required and becomes the group's name")
		return
	}
	if _, err := s.store.LookupEntity(ctx, directory.TypeGroup, in.DisplayName); err == nil {
		scim.WriteError(w, http.StatusConflict, scim.TypeUniqueness,
			"a group called "+in.DisplayName+" already exists")
		return
	}

	entity, err := directory.NewEntity(directory.TypeGroup, in.DisplayName, "")
	if err != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
		return
	}
	if createErr := s.store.CreateEntity(ctx, entity, &actorID); createErr != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, createErr.Error())
		return
	}
	if in.ExternalID != "" {
		if setErr := s.store.SetExternalID(ctx, entity.ID, in.ExternalID); setErr != nil {
			scim.WriteError(w, http.StatusConflict, scim.TypeUniqueness, setErr.Error())
			return
		}
	}
	for _, m := range in.Members {
		if err := s.scimAddMember(ctx, entity.ID, m.Value, actorID); err != nil {
			scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
			return
		}
	}

	s.log.InfoContext(ctx, "scim: group provisioned", "group", entity.Name, "by", actorID)
	s.scimRespondGroup(w, r, entity.ID, http.StatusCreated)
}

// handleSCIMPatchGroup is where membership actually changes.
//
// Every identity provider uses PATCH for this rather than PUT, because a group
// of ten thousand people is not something to send whole on every change.
func (s *Server) handleSCIMPatchGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)
	actorID := session.SubjectID

	entity, ok := s.scimGroupByPath(w, r, true)
	if !ok {
		return
	}

	var patch scim.PatchRequest
	if err := decodeJSON(r, &patch); err != nil {
		scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidSyntax, err.Error())
		return
	}

	for _, op := range patch.Operations {
		path := strings.ToLower(strings.TrimSpace(op.Path))
		verb := op.Normalised()

		// A `remove` with a value filter — members[value eq "…"] — is how Okta
		// removes one person. Recognised by prefix, because parsing the whole
		// path grammar is the thing the filter parser deliberately refuses.
		if verb == "remove" && strings.HasPrefix(path, "members[") {
			id := scimIDFromMemberPath(op.Path)
			if id == "" {
				scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidPath,
					"this provider understands members[value eq \"<id>\"] and no other filter")
				return
			}
			if err := s.scimRemoveMember(ctx, entity.ID, id, actorID); err != nil {
				scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
				return
			}
			continue
		}

		if path != "members" && path != "" {
			scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidPath,
				"a group's only provisionable attribute is members; "+op.Path+" is not one")
			return
		}

		var refs []scim.Ref
		if len(op.Value) > 0 {
			if err := json.Unmarshal(op.Value, &refs); err != nil {
				scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidSyntax,
					"members must be a list of {value}: "+err.Error())
				return
			}
		}

		switch verb {
		case "add":
			for _, m := range refs {
				if err := s.scimAddMember(ctx, entity.ID, m.Value, actorID); err != nil {
					scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
					return
				}
			}
		case "remove":
			// A remove with no value clears the group.
			if len(refs) == 0 {
				if err := s.scimClearMembers(ctx, entity.ID, actorID); err != nil {
					scim.WriteError(w, http.StatusInternalServerError, "", err.Error())
					return
				}
				continue
			}
			for _, m := range refs {
				if err := s.scimRemoveMember(ctx, entity.ID, m.Value, actorID); err != nil {
					scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
					return
				}
			}
		case "replace":
			if err := s.scimClearMembers(ctx, entity.ID, actorID); err != nil {
				scim.WriteError(w, http.StatusInternalServerError, "", err.Error())
				return
			}
			for _, m := range refs {
				if err := s.scimAddMember(ctx, entity.ID, m.Value, actorID); err != nil {
					scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidValue, err.Error())
					return
				}
			}
		default:
			scim.WriteError(w, http.StatusBadRequest, scim.TypeInvalidSyntax,
				"unknown patch operation "+op.Op)
			return
		}
	}

	s.scimRespondGroup(w, r, entity.ID, http.StatusOK)
}

func (s *Server) handleSCIMDeleteGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)
	actorID := session.SubjectID

	entity, ok := s.scimGroupByPath(w, r, true)
	if !ok {
		return
	}
	if err := s.store.DisableEntity(ctx, entity.ID, &actorID); err != nil {
		scim.WriteError(w, http.StatusInternalServerError, "", "could not remove that group")
		return
	}
	s.log.InfoContext(ctx, "scim: group removed", "group", entity.Name, "by", actorID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) scimRespondGroup(
	w http.ResponseWriter, r *http.Request, id uuid.UUID, status int,
) {
	fresh, err := s.store.GetEntity(r.Context(), id)
	if err != nil {
		scim.WriteError(w, http.StatusInternalServerError, "", "could not read that group back")
		return
	}
	projected, err := s.scimProjectGroup(r.Context(), fresh)
	if err != nil {
		scim.WriteError(w, http.StatusInternalServerError, "", "could not read that group back")
		return
	}
	scim.Write(w, status, projected)
}

// scimAddMember grants membership, unbounded.
//
// Unbounded is right here and wrong almost everywhere else in Cardinal, where a
// grant carries a validity period because an unbounded one is the one nobody
// revokes. A provisioned membership has a different lifecycle: the identity
// provider revokes it, by sending a remove, and an expiry Cardinal invented
// would make the two disagree on a schedule nobody chose.
func (s *Server) scimAddMember(
	ctx context.Context, groupID uuid.UUID, memberID string, actorID uuid.UUID,
) error {
	id, err := uuid.Parse(memberID)
	if err != nil {
		return fmt.Errorf("member %q is not an id — SCIM members carry the value from a User resource", memberID)
	}
	if _, err := s.store.GetEntity(ctx, id); err != nil {
		return fmt.Errorf("no such member %s", memberID)
	}

	grantErr := s.store.Grant(ctx, temporal.Grant{
		GroupID:   groupID,
		MemberID:  id,
		Period:    temporal.FromTime(time.Now()),
		GrantedBy: actorID,
		Reason:    "provisioned over SCIM",
	}, &actorID)

	// Already a member is success, not a conflict. A reconciliation re-sends
	// the full membership regularly, and a provider that erred on the second
	// pass would report a permanent failure for a directory that is correct.
	if grantErr != nil && errors.Is(grantErr, temporal.ErrOverlappingGrant) {
		return nil
	}
	return grantErr
}

func (s *Server) scimRemoveMember(
	ctx context.Context, groupID uuid.UUID, memberID string, actorID uuid.UUID,
) error {
	id, err := uuid.Parse(memberID)
	if err != nil {
		return fmt.Errorf("member %q is not an id", memberID)
	}
	// Not a member is success, for the same reason as above.
	if err := s.store.Revoke(ctx, groupID, id, time.Now(), &actorID); err != nil &&
		!errors.Is(err, directory.ErrNotFound) {
		return err
	}
	return nil
}

func (s *Server) scimClearMembers(
	ctx context.Context, groupID uuid.UUID, actorID uuid.UUID,
) error {
	members, err := s.store.MembersOfGroup(ctx, groupID)
	if err != nil {
		return err
	}
	for _, m := range members {
		if err := s.scimRemoveMember(ctx, groupID, m.MemberID.String(), actorID); err != nil {
			return err
		}
	}
	return nil
}

// scimIDFromMemberPath reads the id out of `members[value eq "<id>"]`.
//
// The one path filter that matters, matched narrowly rather than parsed. Okta
// sends exactly this to remove one person, and supporting it is the difference
// between deprovisioning working and not.
func scimIDFromMemberPath(path string) string {
	open := strings.Index(path, "\"")
	if open < 0 {
		return ""
	}
	rest := path[open+1:]
	closeIdx := strings.Index(rest, "\"")
	if closeIdx < 0 {
		return ""
	}
	return rest[:closeIdx]
}
