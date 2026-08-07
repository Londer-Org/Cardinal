package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/google/uuid"
)

// Hosts, from the console.
//
// Everything here existed as a CLI command and nowhere else, which made the
// inventory page a list of machines you could look at and not touch. Adding a
// host, handing it a way in, granting it another name it may prove — all of it
// needed a shell on the Cardinal server and a database connection string.
//
// The interesting addition is not any of those. It is `access`: who may log
// into this machine, as which local account, and with sudo. That question has
// an answer inside Cardinal — the agent asks it every five minutes — and until
// now nobody could ask it about a host except the host itself.

type hostDetailResponse struct {
	hostResponse

	// Aliases are the other names this machine may prove. Each is the power to
	// *be* that name to anything trusting the CA, which is why they are listed
	// rather than counted here.
	Aliases []string `json:"aliasNames"`

	Groups      []grantResponse      `json:"memberships"`
	Credentials []hostCredentialInfo `json:"credentials"`

	// Access is who may log in. Empty is a real answer and a common one: a host
	// in no group is a host no rule reaches.
	Access []hostAccessEntry `json:"access"`

	// AccessUnavailable when policy could not be consulted. Distinguished from
	// an empty list on purpose — "nobody may log in" and "I could not work it
	// out" look identical on screen and mean opposite things.
	AccessUnavailable bool `json:"accessUnavailable"`
}

type hostCredentialInfo struct {
	Fingerprint string     `json:"fingerprint"`
	EnrolledAt  time.Time  `json:"enrolledAt"`
	LastSeenAt  *time.Time `json:"lastSeenAt"`

	// Live distinguishes the key the host authenticates with now from the ones
	// it used before. Retired keys are listed rather than hidden, because
	// "which key made that request last month" is a question only they answer.
	Live bool `json:"live"`
}

type hostAccessEntry struct {
	Login       string `json:"login"`
	DisplayName string `json:"displayName"`

	// LocalAccount is the POSIX name they land on, which is not always their
	// login and is the thing somebody auditing a machine actually reads.
	LocalAccount string `json:"localAccount"`
	UID          int    `json:"uid"`
	Sudo         bool   `json:"sudo"`
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	entity, err := s.store.LookupEntity(ctx, directory.TypeHost, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such host")
		return
	}

	aliases, err := s.store.ListHostAliases(ctx, entity.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing host aliases failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the host")
		return
	}

	credentials, err := s.store.ListHostCredentials(ctx, entity.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing host credentials failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the host")
		return
	}

	memberships, err := s.store.GroupsOfMember(ctx, entity.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading host memberships failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the host")
		return
	}

	out := hostDetailResponse{
		hostResponse: hostResponse{
			Name: entity.Name, DisplayName: entity.DisplayName,
			Enrolled: len(credentials) > 0, Aliases: len(aliases),
			Groups: len(memberships), Disabled: entity.DisabledAt != nil,
		},
		Aliases:     aliases,
		Groups:      describeGrants(memberships),
		Credentials: make([]hostCredentialInfo, 0, len(credentials)),
	}

	var lastSeen *time.Time
	for _, c := range credentials {
		out.Credentials = append(out.Credentials, hostCredentialInfo{
			Fingerprint: c.Fingerprint, EnrolledAt: c.EnrolledAt,
			LastSeenAt: c.LastSeenAt, Live: c.Live,
		})
		if c.LastSeenAt != nil && (lastSeen == nil || c.LastSeenAt.After(*lastSeen)) {
			lastSeen = c.LastSeenAt
		}
	}
	if lastSeen != nil {
		out.LastSeen = lastSeen.UTC().Format(time.RFC3339)
	}

	access, ok := s.hostAccess(ctx, entity.ID, entity.Name)
	out.Access, out.AccessUnavailable = access, !ok

	writeJSON(w, http.StatusOK, out)
}

// hostAccess answers "who may log into this machine, as whom".
//
// The same evaluation the agent gets from /api/hosts/assignment, asked about a
// host rather than by one. It reuses mayLogIn and mayRunAsRoot rather than
// reimplementing the rules, so this page cannot drift from what the machine is
// actually told — a console that disagreed with the sudoers file would be worse
// than no console, because somebody would trust it.
//
// The second return is false when policy could not be consulted at all. An
// empty list is a legitimate answer and must not be confused with a failure to
// produce one.
func (s *Server) hostAccess(ctx context.Context, hostID uuid.UUID, hostName string) ([]hostAccessEntry, bool) {
	engine := s.policy.Load()
	if engine == nil {
		return nil, false
	}

	hostSubject, err := s.claims.ResolveByID(ctx, hostID)
	if err != nil {
		s.log.ErrorContext(ctx, "host access: resolving host failed", "error", err)
		return nil, false
	}

	identities, err := s.store.ListPOSIXIdentities(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "host access: listing POSIX identities failed",
			"error", err)
		return nil, false
	}

	// A synthetic credential, because mayLogIn reads exactly two fields from
	// one and neither depends on a machine having authenticated. Building it
	// here is what lets an administrator ask the question before the host has
	// ever enrolled — which is precisely when they want to check the answer.
	cred := &store.HostCredential{HostID: hostID, HostName: hostName}

	entries := []hostAccessEntry{}
	for _, p := range identities {
		if p.Type != directory.TypeUser {
			continue
		}

		subject, err := s.claims.ResolveByID(ctx, p.EntityID)
		if err != nil {
			// Same as the agent's path: one unresolvable user must not cost the
			// whole answer, and omitting them matches what the host would be
			// told anyway.
			s.log.WarnContext(ctx, "host access: skipping unresolvable user",
				"user", p.EntityID, "error", err)
			continue
		}
		if !s.mayLogIn(engine, subject, cred, hostSubject) {
			continue
		}

		entries = append(entries, hostAccessEntry{
			Login:        subject.Login,
			DisplayName:  subject.DisplayName,
			LocalAccount: p.Name,
			UID:          p.Number,
			Sudo:         s.mayRunAsRoot(engine, subject, cred, hostSubject),
		})
	}

	// Sudo first, then by name: the rows somebody is checking for are the ones
	// that can become root, and burying them in an alphabetical list is how
	// they go unread.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Sudo != entries[j].Sudo {
			return entries[i].Sudo
		}
		return entries[i].LocalAccount < entries[j].LocalAccount
	})
	return entries, true
}

type createHostRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req createHostRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}

	entity, err := directory.NewEntity(directory.TypeHost,
		strings.TrimSpace(req.Name), strings.TrimSpace(req.DisplayName))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	actorID := session.SubjectID
	if err := s.store.CreateEntity(ctx, entity, &actorID); err != nil {
		if errors.Is(err, directory.ErrAlreadyExists) {
			writeError(w, http.StatusConflict, "a host with that name already exists")
			return
		}
		s.log.ErrorContext(ctx, "creating a host failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create the host")
		return
	}

	// Created and unreachable, which is worth being explicit about rather than
	// leaving somebody to discover. A host entity is a directory record; the
	// machine cannot prove it is this host until it enrolls.
	writeJSON(w, http.StatusCreated, map[string]any{
		"name":        entity.Name,
		"displayName": entity.DisplayName,
	})
}

// handleIssueHostEnrollment hands a machine a way in.
//
// Returns the command to run rather than the bare token, following
// `cardinal host enroll`. An operator holding a secret still has to know what
// to do with it, and the step they get wrong is the keypair — reusing the
// machine's existing SSH host key, which already has another job, or generating
// it somewhere other than the machine, which defeats Cardinal never holding it.
func (s *Server) handleIssueHostEnrollment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	entity, err := s.store.LookupEntity(ctx, directory.TypeHost, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such host")
		return
	}

	actorID := session.SubjectID
	enrollment, err := s.store.CreateHostEnrollment(ctx, entity.ID, &actorID)
	if err != nil {
		s.log.ErrorContext(ctx, "issuing host enrollment failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not issue a token")
		return
	}

	base := strings.TrimRight(s.cfg.Server.PublicURL, "/")
	writeJSON(w, http.StatusCreated, map[string]any{
		"command": "cardinal-agent join --server " + base +
			" --token " + enrollment.Token,
		"expiresAt": enrollment.ExpiresAt,
	})
}

type hostAliasRequest struct {
	Alias string `json:"alias"`
}

func (s *Server) handleAddHostAlias(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	entity, err := s.store.LookupEntity(ctx, directory.TypeHost, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such host")
		return
	}

	var req hostAliasRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}

	actorID := session.SubjectID
	if err := s.store.AddHostAlias(ctx, entity.ID, strings.TrimSpace(req.Alias), &actorID); err != nil {
		// The store owns the rules — a name already claimed by another host is
		// the one that matters, and its message names the holder.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveHostAlias(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	entity, err := s.store.LookupEntity(ctx, directory.TypeHost, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such host")
		return
	}

	actorID := session.SubjectID
	if err := s.store.RemoveHostAlias(ctx, entity.ID, r.PathValue("alias"), &actorID); err != nil {
		writeError(w, http.StatusNotFound, "this host does not hold that name")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
