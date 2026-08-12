package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/directory/temporal"
	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/internal/store"
)

// People and groups, over the admin API.
//
// Everything here sits behind requireAdmin, so it is a Cedar decision like any
// other. Membership is the most consequential thing in the directory — it is
// what every policy reads — so granting one is administration in the fullest
// sense, and the decision log records each attempt.
//
// Grants carry a period, not a boolean. That is the flagship of the data model
// (ADR 0001) and it was previously reachable only from the CLI, which meant the
// feature existed and nobody could use it.

type userResponse struct {
	Login       string `json:"login"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`

	Credentials   int  `json:"credentials"`
	FullyEnrolled bool `json:"fullyEnrolled"`
	Groups        int  `json:"groups"`

	// InvitationPending distinguishes an account waiting to be set up from one
	// nobody ever finished setting up. Both have no passkeys; only one has
	// someone on the way.
	InvitationPending bool      `json:"invitationPending"`
	CreatedAt         time.Time `json:"createdAt"`

	// Disabled, so a listing that includes them can say which is which.
	Disabled bool `json:"disabled"`
}

// pageFrom reads paging and search from the query string.
//
// Bad numbers are ignored rather than refused: a stray `?limit=abc` should show
// the first page, not an error, because nobody typed it deliberately and the
// safe interpretation is obvious.
func pageFrom(r *http.Request) store.Page {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))   //nolint:errcheck // a bad number means the default, as documented above
	offset, _ := strconv.Atoi(q.Get("offset")) //nolint:errcheck // a bad number means the default, as documented above
	return store.Page{Search: q.Get("q"), Limit: limit, Offset: offset}
}

// pagedResponse carries the page and how much there is.
//
// The total is what lets the console say "25 of 412" rather than only showing
// what it was handed — which is the difference between a list an administrator
// can navigate and one they have to guess at.
type pagedResponse[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page := pageFrom(r)

	// Active by default. An account that vanished the moment it was disabled
	// could never be found again, which is how disabling became a door with no
	// way back — so `status=disabled` and `status=all` exist.
	users, total, err := s.store.ListUsers(ctx, page,
		store.UserFilter(r.URL.Query().Get("status")))
	if err != nil {
		s.log.ErrorContext(ctx, "listing users failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list users")
		return
	}

	out := make([]userResponse, 0, len(users))
	for _, u := range users {
		out = append(out, userResponse{
			Login:             u.Login,
			DisplayName:       u.DisplayName,
			Email:             u.Email,
			Credentials:       u.Credentials,
			FullyEnrolled:     u.FullyEnrolled(),
			Groups:            u.Groups,
			InvitationPending: u.InvitationPending,
			CreatedAt:         u.CreatedAt,
			Disabled:          u.DisabledAt != nil,
		})
	}

	writeJSON(w, http.StatusOK, pagedResponse[userResponse]{
		Items: out, Total: total,
		Limit: len(out), Offset: page.Offset,
	})
}

type grantResponse struct {
	Group  string     `json:"group"`
	Member string     `json:"member"`
	From   time.Time  `json:"from"`
	Until  *time.Time `json:"until"`

	GrantedBy string `json:"grantedBy"`
	Reason    string `json:"reason"`
}

func describeGrants(grants []*store.NamedGrant) []grantResponse {
	out := make([]grantResponse, 0, len(grants))
	for _, g := range grants {
		out = append(out, grantResponse{
			Group:     g.GroupName,
			Member:    g.MemberName,
			From:      g.From,
			Until:     g.Until,
			GrantedBy: g.GrantedByAs,
			Reason:    g.Reason,
		})
	}
	return out
}

type userDetailResponse struct {
	// POSIX is nil when this account has no uid.
	POSIX map[string]any `json:"posix"`

	userResponse

	Memberships []grantResponse `json:"memberships"`

	// InvitationExpiresAt is set while a link is outstanding, so the console can
	// say how long is left rather than only that one exists — "issued" and
	// "issued yesterday and expiring in an hour" call for different actions.
	InvitationExpiresAt *time.Time `json:"invitationExpiresAt"`
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	entity, err := s.store.LookupEntity(ctx, directory.TypeUser, r.PathValue("login"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	enrolled, err := s.store.FullyEnrolled(ctx, entity.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading enrollment failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the account")
		return
	}
	at, err := atFrom(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	memberships, err := s.store.GroupsOfMemberAt(ctx, entity.ID, at)
	if err != nil {
		s.log.ErrorContext(ctx, "reading memberships failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the account")
		return
	}

	// Credentials and invitation state were previously left at their zero
	// values here, so the detail view reported "no passkeys, not invited" for an
	// account the list showed as invited. Nothing rendered them, so nothing
	// noticed — until something did.
	credentials, err := s.store.CredentialsFor(ctx, entity.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing credentials failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the account")
		return
	}

	var invitationExpiry *time.Time
	if inv, err := s.store.PendingInvitationFor(ctx, entity.ID); err == nil {
		invitationExpiry = &inv.ExpiresAt
	}

	// Nil when they have none, which is the common case: most accounts never
	// touch a Linux host, and a uid handed out to everybody would be a number
	// on a filesystem for no reason.
	var posix map[string]any
	if identity, err := s.store.POSIXIdentityFor(ctx, entity.ID); err == nil {
		posix = posixResponse(identity)
	}

	email, _ := entity.Attrs["email"].(string) //nolint:errcheck // a missing or non-string attribute is the empty string
	writeJSON(w, http.StatusOK, userDetailResponse{
		userResponse: userResponse{
			Login:             entity.Name,
			DisplayName:       entity.DisplayName,
			Email:             email,
			Credentials:       len(credentials),
			FullyEnrolled:     enrolled,
			Groups:            len(memberships),
			InvitationPending: invitationExpiry != nil,
			CreatedAt:         entity.CreatedAt,
			Disabled:          entity.DisabledAt != nil,
		},
		Memberships:         describeGrants(memberships),
		InvitationExpiresAt: invitationExpiry,
		POSIX:               posix,
	})
}

type createUserRequest struct {
	Login       string `json:"login"`
	DisplayName string `json:"displayName"`

	// Invite issues an enrollment link in the same step. Creating an account
	// nobody can sign in to and forgetting the second command is the mistake
	// this exists to prevent.
	Invite bool `json:"invite"`
}

type createUserResponse struct {
	Login string `json:"login"`

	// InvitationURL is present only when one was issued, and only once.
	InvitationURL string     `json:"invitationUrl,omitempty"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	entity, err := directory.NewEntity(directory.TypeUser,
		strings.TrimSpace(req.Login), strings.TrimSpace(req.DisplayName))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	actorID := session.SubjectID
	if err := s.store.CreateEntity(ctx, entity, &actorID); err != nil {
		// Passed through rather than flattened: "already exists" and "name is
		// not valid" send the operator to different places.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.log.InfoContext(ctx, "user created",
		"login", entity.Name, "actor", session.SubjectID)

	out := createUserResponse{Login: entity.Name}
	if req.Invite {
		issued, err := s.store.IssueInvitation(ctx, entity.ID, &actorID, store.InvitationTTL)
		if err != nil {
			// The account exists and is usable; only the link failed. Saying so
			// beats rolling back a creation the operator asked for.
			s.log.ErrorContext(ctx, "issuing invitation failed", "error", err)
			writeError(w, http.StatusInternalServerError,
				"the account was created, but the invitation could not be issued — "+
					"issue one from the account itself")
			return
		}
		out.InvitationURL = s.cfg.Server.PublicURL + "/enroll?token=" + issued.Token
		out.ExpiresAt = &issued.Invitation.ExpiresAt
	}

	writeJSON(w, http.StatusCreated, out)
}

// handleEnableUser undoes a disable.
//
// The other half of a control that had none. Sessions and access tokens are
// deliberately not restored — disabling revoked them, and a token that was live
// while an account was cut off is exactly what should not resume working.
func (s *Server) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	// LookupEntity does not filter on disabled — names resolve either way,
	// which is what makes finding a disabled account possible at all.
	entity, err := s.store.LookupEntity(ctx, directory.TypeUser, r.PathValue("login"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	actorID := session.SubjectID
	if err := s.store.EnableEntity(ctx, entity.ID, &actorID); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusConflict, "that account is not disabled")
			return
		}
		s.log.ErrorContext(ctx, "enabling user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not enable the account")
		return
	}

	s.log.InfoContext(ctx, "user enabled", "login", entity.Name, "by", session.SubjectID)

	writeJSON(w, http.StatusOK, map[string]any{
		"login": entity.Name,
		// Said explicitly, because somebody re-enabling an account expects it to
		// be as it was and it is not quite.
		"note": "sessions and access tokens were revoked when this account was " +
			"disabled and have not been restored; they will need to sign in again",
	})
}

func (s *Server) handleDisableUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	entity, err := s.store.LookupEntity(ctx, directory.TypeUser, r.PathValue("login"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	// Disabling yourself is a mistake nobody means to make, and the recovery
	// costs a shell on the host. Cardinal has no reason to help.
	if entity.ID == session.SubjectID {
		writeError(w, http.StatusBadRequest,
			"you cannot disable your own account — ask another administrator")
		return
	}

	actorID := session.SubjectID
	if err := s.store.DisableEntity(ctx, entity.ID, &actorID); err != nil {
		s.log.ErrorContext(ctx, "disabling user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not disable the account")
		return
	}

	// Sessions do not survive it. Disabling an account whose holder stays signed
	// in until their cookie expires is not disabling it.
	if _, err := s.store.RevokeAllSessions(ctx, entity.ID, &actorID); err != nil {
		s.log.ErrorContext(ctx, "revoking sessions for disabled user failed", "error", err)
	}

	// Nor do access tokens, for the same reason and more urgently: a session
	// ends on its own within hours, whereas a token in someone's pipeline is
	// valid until its expiry, and nobody watching the account list would see it
	// still working.
	if _, err := s.store.RevokeAllAccessTokens(ctx, entity.ID); err != nil {
		s.log.ErrorContext(ctx, "revoking access tokens for disabled user failed", "error", err)
	}

	s.log.InfoContext(ctx, "user disabled",
		"login", entity.Name, "actor", session.SubjectID)
	w.WriteHeader(http.StatusNoContent)
}

// ── Groups ──────────────────────────────────────────────────────────────────

type groupResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Members     int    `json:"members"`

	// System marks a group whose membership confers authority within Cardinal.
	// The console shows it, because an administrator cannot otherwise tell
	// aura-admins from directory-admins by looking.
	System bool `json:"system"`

	// Owner is the application a group exists for, empty when it belongs to
	// nobody in particular.
	Owner string `json:"owner"`
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	page := pageFrom(r)

	kind := store.GroupKind(r.URL.Query().Get("kind"))
	groups, total, err := s.store.ListGroups(ctx, page, kind)
	if err != nil {
		s.log.ErrorContext(ctx, "listing groups failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list groups")
		return
	}

	out := make([]groupResponse, 0, len(groups))
	for _, g := range groups {
		out = append(out, groupResponse{
			Name: g.Name, DisplayName: g.DisplayName, Members: g.Members,
			System: g.System, Owner: g.Owner,
		})
	}

	writeJSON(w, http.StatusOK, pagedResponse[groupResponse]{
		Items: out, Total: total,
		Limit: len(out), Offset: page.Offset,
	})
}

// handleListApplicationNames lists applications for an owner picker.
//
// Under ManageUsers, not ManageApplications: the tier that creates groups needs
// to name an application to associate one with, and would otherwise be refused
// the list it has to choose from. It returns names only — associating a group
// means naming an application, not inspecting its redirect URIs, so this does
// not widen access to a registration for a dropdown's sake.
func (s *Server) handleListApplicationNames(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page := pageFrom(r)

	apps, total, err := s.store.ListApplicationNames(ctx, page)
	if err != nil {
		s.log.ErrorContext(ctx, "listing application names failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list applications")
		return
	}

	type ref struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	}
	out := make([]ref, 0, len(apps))
	for _, a := range apps {
		out = append(out, ref{Name: a.Name, DisplayName: a.DisplayName})
	}

	writeJSON(w, http.StatusOK, pagedResponse[ref]{
		Items: out, Total: total, Limit: len(out), Offset: page.Offset,
	})
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	entity, err := s.store.LookupEntity(ctx, directory.TypeGroup, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such group")
		return
	}

	at, err := atFrom(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	members, err := s.store.MembersOfGroupAt(ctx, entity.ID, at)
	if err != nil {
		s.log.ErrorContext(ctx, "listing members failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the group")
		return
	}

	owner := ""
	if entity.OwnerID != nil {
		if app, err := s.store.GetEntity(ctx, *entity.OwnerID); err == nil {
			owner = app.Name
		}
	}

	body := map[string]any{
		"name":        entity.Name,
		"displayName": entity.DisplayName,
		"system":      entity.System,
		"owner":       owner,
		"members":     describeGrants(members),
	}
	// Echoed so a caller can tell an answer about March from an answer about
	// now, which otherwise look identical.
	if !at.IsZero() {
		body["at"] = at.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`

		// Owner names the application this group exists for. Organisational
		// only: Cardinal treats an owned group exactly like any other, and it
		// still reaches the application through the groups claim.
		Owner string `json:"owner"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	entity, err := directory.NewEntity(directory.TypeGroup,
		strings.TrimSpace(req.Name), strings.TrimSpace(req.DisplayName))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// A group created through the API is never a system group. Conferring
	// authority within Cardinal is a decision the policy set makes, and it
	// should not be reachable by choosing a name in a form.
	ownerName := strings.TrimSpace(req.Owner)
	if ownerName != "" {
		app, err := s.store.LookupEntity(ctx, directory.TypeApplication, ownerName)
		if err != nil {
			writeError(w, http.StatusNotFound, "no such application")
			return
		}
		entity.OwnerID = &app.ID
	}

	actorID := session.SubjectID
	if err := s.store.CreateEntity(ctx, entity, &actorID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.log.InfoContext(ctx, "group created",
		"name", entity.Name, "owner", ownerName, "actor", session.SubjectID)

	// Reports the owner it was given. Echoing an empty one back would tell the
	// caller their request was ignored when it was not.
	writeJSON(w, http.StatusCreated, groupResponse{
		Name: entity.Name, DisplayName: entity.DisplayName, Owner: ownerName,
	})
}

type grantRequest struct {
	Member string `json:"member"`

	// Until bounds the grant. Absent means unbounded, which is the one every
	// directory ends up full of — so the UI asks, and the CLI warns.
	Until  *time.Time `json:"until"`
	Reason string     `json:"reason"`
}

// requireAuthorityOver refuses to let a narrow tier grant a broad one.
//
// Membership of a system group *is* administrative authority, so handing one
// out is an act of the same weight as the power it confers. ManageUsers is
// enough to run onboarding and to manage the groups an application cares about;
// it is not enough to make somebody an administrator, because then a user-admin
// could simply grant themselves directory-admins — which is exactly what they
// could do before this existed.
//
// Returns true when the caller may proceed; it has already written the refusal
// otherwise.
func (s *Server) requireAuthorityOver(w http.ResponseWriter, r *http.Request, group *directory.Entity) bool {
	if !group.System {
		return true
	}

	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	decision, subject, err := s.decideAction(ctx, session, policy.ActionAdministerData)
	if err != nil {
		s.log.ErrorContext(ctx, "authority check failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "authorization unavailable")
		return false
	}
	s.logAdminDecision(ctx, subject, decision, "AdministerDirectory",
		r.Method+" "+r.URL.Path)

	if !decision.Allowed {
		s.log.WarnContext(ctx, "refused a system-group change from a narrow tier",
			"group", group.Name, "actor", session.SubjectID)
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": group.Name + " confers authority within Cardinal, so changing " +
				"its membership needs full directory administration — managing " +
				"people is not enough to make somebody an administrator",
			"policy": decision.Reasons,
		})
		return false
	}
	return true
}

func (s *Server) handleGrantMembership(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req grantRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	group, err := s.store.LookupEntity(ctx, directory.TypeGroup, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such group")
		return
	}
	if !s.requireAuthorityOver(w, r, group) {
		return
	}

	// Members may be users or groups: nesting is how role inheritance is
	// expressed, and refusing it here would make the console strictly weaker
	// than the CLI.
	member, err := s.lookupMember(ctx, strings.TrimSpace(req.Member))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user or group")
		return
	}

	// Unbounded unless an end is given. Between validates the ordering, so a
	// paste-error that puts the expiry in the past is refused rather than
	// stored as an empty range nobody notices.
	period := temporal.FromTime(time.Now())
	if req.Until != nil {
		period = temporal.Between(time.Now(), *req.Until)
		if err := period.Validate(); err != nil {
			writeError(w, http.StatusBadRequest,
				"that expiry is not after the start of the grant")
			return
		}
	}

	if err := s.store.Grant(ctx, temporal.Grant{
		GroupID:   group.ID,
		MemberID:  member.ID,
		Period:    period,
		GrantedBy: session.SubjectID,
		Reason:    strings.TrimSpace(req.Reason),
	}, &session.SubjectID); err != nil {
		// An overlapping grant is refused by the exclusion constraint, which is
		// the temporal model doing its job — say so rather than reporting a
		// server error.
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	s.log.InfoContext(ctx, "membership granted",
		"group", group.Name, "member", member.Name,
		"until", req.Until, "actor", session.SubjectID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevokeMembership(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	group, err := s.store.LookupEntity(ctx, directory.TypeGroup, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such group")
		return
	}
	// Revocation too. Removing the last administrator is not an escalation, but
	// it is a denial of service on the directory, and a tier that cannot grant
	// the power should not be able to take it away either.
	if !s.requireAuthorityOver(w, r, group) {
		return
	}
	member, err := s.lookupMember(ctx, r.PathValue("member"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user or group")
		return
	}

	// Revocation truncates the period rather than deleting the row, so who
	// granted it and why outlive the access itself (ADR 0001).
	if err := s.store.Revoke(ctx, group.ID, member.ID, time.Now(), &session.SubjectID); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no current membership to revoke")
			return
		}
		s.log.ErrorContext(ctx, "revoking membership failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not revoke it")
		return
	}

	s.log.InfoContext(ctx, "membership revoked",
		"group", group.Name, "member", member.Name, "actor", session.SubjectID)
	w.WriteHeader(http.StatusNoContent)
}

// lookupMember resolves a name that may be a user or a group.
func (s *Server) lookupMember(ctx context.Context, name string) (*directory.Entity, error) {
	if e, err := s.store.LookupEntity(ctx, directory.TypeUser, name); err == nil {
		return e, nil
	}
	return s.store.LookupEntity(ctx, directory.TypeGroup, name)
}

// hostResponse is one machine in the inventory.
type hostResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`

	Enrolled bool `json:"enrolled"`

	// LastSeen is RFC3339 or empty. Empty means never, which is a different
	// thing from long ago and has to be distinguishable in the table.
	LastSeen string `json:"lastSeen"`

	Aliases  int  `json:"aliases"`
	Groups   int  `json:"groups"`
	Disabled bool `json:"disabled"`
}

// handleListHosts answers what the fleet looks like.
//
// The question nothing else in Cardinal can answer: which machines are still
// checking in. A host that enrolled six months ago and has not been seen since
// is either decommissioned or broken, and both are worth knowing about before
// somebody tries to log into it.
func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hosts, total, err := s.store.ListHosts(ctx, pageFrom(r))
	if err != nil {
		s.log.ErrorContext(ctx, "listing hosts failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list hosts")
		return
	}

	out := make([]hostResponse, 0, len(hosts))
	for _, h := range hosts {
		row := hostResponse{
			Name: h.Name, DisplayName: h.DisplayName,
			Enrolled: h.Enrolled, Aliases: h.Aliases,
			Groups: h.Groups, Disabled: h.Disabled,
		}
		if h.LastSeenAt != nil {
			row.LastSeen = h.LastSeenAt.UTC().Format(time.RFC3339)
		}
		out = append(out, row)
	}

	page := pageFrom(r)
	writeJSON(w, http.StatusOK, pagedResponse[hostResponse]{
		Items: out, Total: total,
		Limit: len(out), Offset: page.Offset,
	})
}
