package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/arthur-lonfils/cardinal/internal/temporal"
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
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := s.store.ListUsers(ctx)
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
		})
	}
	writeJSON(w, http.StatusOK, out)
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
	userResponse

	Memberships []grantResponse `json:"memberships"`
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
	memberships, err := s.store.GroupsOfMember(ctx, entity.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading memberships failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the account")
		return
	}

	email, _ := entity.Attrs["email"].(string)
	writeJSON(w, http.StatusOK, userDetailResponse{
		userResponse: userResponse{
			Login:         entity.Name,
			DisplayName:   entity.DisplayName,
			Email:         email,
			FullyEnrolled: enrolled,
			Groups:        len(memberships),
			CreatedAt:     entity.CreatedAt,
		},
		Memberships: describeGrants(memberships),
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

	s.log.InfoContext(ctx, "user disabled",
		"login", entity.Name, "actor", session.SubjectID)
	w.WriteHeader(http.StatusNoContent)
}

// ── Groups ──────────────────────────────────────────────────────────────────

type groupResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Members     int    `json:"members"`
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing groups failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list groups")
		return
	}

	out := make([]groupResponse, 0, len(groups))
	for _, g := range groups {
		out = append(out, groupResponse{
			Name: g.Name, DisplayName: g.DisplayName, Members: g.Members,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	entity, err := s.store.LookupEntity(ctx, directory.TypeGroup, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such group")
		return
	}

	members, err := s.store.MembersOfGroup(ctx, entity.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing members failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the group")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":        entity.Name,
		"displayName": entity.DisplayName,
		"members":     describeGrants(members),
	})
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
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

	actorID := session.SubjectID
	if err := s.store.CreateEntity(ctx, entity, &actorID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.log.InfoContext(ctx, "group created",
		"name", entity.Name, "actor", session.SubjectID)
	writeJSON(w, http.StatusCreated, groupResponse{
		Name: entity.Name, DisplayName: entity.DisplayName,
	})
}

type grantRequest struct {
	Member string `json:"member"`

	// Until bounds the grant. Absent means unbounded, which is the one every
	// directory ends up full of — so the UI asks, and the CLI warns.
	Until  *time.Time `json:"until"`
	Reason string     `json:"reason"`
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
