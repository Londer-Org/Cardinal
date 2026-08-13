package httpapi

import (
	"errors"
	"net/http"
	"time"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// Managing OIDC applications over the API.
//
// Every handler here sits behind requireAdmin, so registering a relying party
// is a Cedar decision like any other. That matters more than it sounds: anyone
// who can register a client can choose its redirect URIs and whether it asks
// for consent, which is enough to build a convincing phishing surface inside
// the organisation's own identity provider.

type applicationResponse struct {
	ClientID     string   `json:"clientId"`
	Name         string   `json:"name"`
	AuthMethod   string   `json:"authMethod"`
	Public       bool     `json:"public"`
	RedirectURIs []string `json:"redirectUris"`
	Scopes       []string `json:"scopes"`

	RequirePKCE    bool `json:"requirePkce"`
	RequireConsent bool `json:"requireConsent"`
	DevMode        bool `json:"devMode"`

	AccessTokenLifetime string `json:"accessTokenLifetime"`
}

func describeApplication(c *store.OIDCClient) applicationResponse {
	return applicationResponse{
		ClientID:            c.ClientID,
		Name:                c.Name,
		AuthMethod:          string(c.AuthMethod),
		Public:              c.Public(),
		RedirectURIs:        c.RedirectURIs,
		Scopes:              c.Scopes,
		RequirePKCE:         c.RequirePKCE,
		RequireConsent:      c.RequireConsent,
		DevMode:             c.DevMode,
		AccessTokenLifetime: c.AccessTokenLifetime.String(),
	}
}

// applicationSummary is one application as the console lists them.
//
// An application entity, which may or may not also be an OIDC relying party.
// This list used to be ListOIDCClients, so an application that only sits behind
// the proxy — no client id, nothing to sign in with — appeared nowhere in the
// console at all, while being precisely the kind that needs a hostname adding.
type applicationSummary struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Disabled    bool   `json:"disabled"`

	// Hostnames it answers to through forwardAuth. Empty is not an error and
	// not unusual: an application reached only over OIDC has none.
	Hostnames []string `json:"hostnames"`

	// OIDC is null when the application speaks no OpenID Connect. Nested rather
	// than flattened with zero values, because "public client" and "no client"
	// are different facts and a false in that position would assert the first.
	OIDC *applicationResponse `json:"oidc"`
}

// handleListApplications returns every application, OIDC client or not.
func (s *Server) handleListApplications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	entries, err := s.store.ListApplications(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing applications failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list applications")
		return
	}

	clients, err := s.store.ListOIDCClients(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing relying parties failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list applications")
		return
	}
	byName := make(map[string]*store.OIDCClient, len(clients))
	for _, c := range clients {
		byName[c.Name] = c
	}

	out := make([]applicationSummary, 0, len(entries))
	for _, e := range entries {
		summary := applicationSummary{
			Name:        e.Name,
			DisplayName: e.DisplayName,
			Disabled:    e.Disabled,
			Hostnames:   e.Hostnames,
		}
		if client, ok := byName[e.Name]; ok {
			described := describeApplication(client)
			summary.OIDC = &described
		}
		out = append(out, summary)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAddApplicationHostname attaches an address to an application.
//
// Keyed on the application's directory name rather than a client id, because
// the applications that most need this have no client id — which is how the
// console came to have no way of doing it.
func (s *Server) handleAddApplicationHostname(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	app, err := s.store.LookupEntity(ctx, directory.TypeApplication, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such application")
		return
	}

	var req struct {
		Hostname string `json:"hostname"`
	}
	if decodeErr := decodeJSON(r, &req); decodeErr != nil {
		writeError(w, http.StatusBadRequest, decodeErr.Error())
		return
	}

	actorID := session.SubjectID
	if addErr := s.store.AddApplicationHostname(ctx, app.ID, req.Hostname, &actorID); addErr != nil {
		if errors.Is(addErr, store.ErrHostnameTaken) {
			// 409 rather than 400: the request is well formed and the refusal is
			// about the state of the directory, which is a different thing for a
			// client to react to.
			writeError(w, http.StatusConflict, addErr.Error())
			return
		}
		writeError(w, http.StatusBadRequest, addErr.Error())
		return
	}

	s.log.InfoContext(ctx, "application hostname added",
		"application", app.Name, "hostname", req.Hostname, "actor", session.SubjectID)

	// Registering a hostname makes an application findable; it does not make it
	// reachable. The shipped policy set admits people through group membership
	// and ships with staff-apps empty on purpose, so an application in no group
	// answers 403 to everybody — which looks exactly like a broken setup.
	//
	// Reported rather than left to the caller to go and check, because both
	// callers would have to: the CLI said this in prose and the console said
	// nothing at all.
	admitted := true
	memberships, err := s.store.ResolveMemberships(ctx, app.ID, time.Time{})
	if err != nil {
		// Not fatal. The hostname is registered either way, and refusing to
		// answer because an advisory lookup failed would be worse than a
		// missing note.
		s.log.WarnContext(ctx, "could not tell whether the application is in any group",
			"application", app.Name, "error", err)
	} else {
		admitted = len(memberships) > 0
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"application": app.Name,
		"hostname":    req.Hostname,
		"inAnyGroup":  admitted,
	})
}

// handleSetApplicationEnabled retires an application, or brings one back.
//
// Keyed on the directory name so it reaches both kinds. The client-id route
// below still exists and does the same thing for a relying party; this is the
// one the console uses, because an application behind the proxy has no client
// id and would otherwise have been creatable from here and not retirable.
func (s *Server) handleSetApplicationEnabled(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	// Checked rather than derived from `== "enable"`. That form makes every
	// unrecognised word mean disable, so a typo in a URL would retire an
	// application and report success.
	state := r.PathValue("state")
	if state != "enable" && state != "disable" {
		writeError(w, http.StatusNotFound, "no such action")
		return
	}
	enabled := state == "enable"
	actorID := session.SubjectID

	if err := s.store.SetApplicationEnabled(
		ctx, r.PathValue("name"), enabled, &actorID,
	); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such application")
			return
		}
		s.log.ErrorContext(ctx, "changing an application's state failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not change that application")
		return
	}

	s.log.InfoContext(ctx, "application state changed",
		"application", r.PathValue("name"), "enabled", enabled,
		"actor", session.SubjectID)

	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveApplicationHostname withdraws one.
func (s *Server) handleRemoveApplicationHostname(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	app, err := s.store.LookupEntity(ctx, directory.TypeApplication, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such application")
		return
	}

	actorID := session.SubjectID
	if removeErr := s.store.RemoveApplicationHostname(
		ctx, app.ID, r.PathValue("hostname"), &actorID,
	); removeErr != nil {
		if errors.Is(removeErr, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "this application does not answer to that name")
			return
		}
		s.log.ErrorContext(ctx, "removing an application hostname failed", "error", removeErr)
		writeError(w, http.StatusInternalServerError, "could not remove that hostname")
		return
	}

	// Immediately, unlike a certificate: forwardAuth asks on every request.
	s.log.InfoContext(ctx, "application hostname removed",
		"application", app.Name, "hostname", r.PathValue("hostname"),
		"actor", session.SubjectID)

	w.WriteHeader(http.StatusNoContent)
}

type applicationDetailResponse struct {
	applicationResponse

	ActiveTokens   int        `json:"activeTokens"`
	StandingGrants int        `json:"standingGrants"`
	LastIssuedAt   *time.Time `json:"lastIssuedAt"`
}

// handleGetApplication describes one relying party, including what it holds.
func (s *Server) handleGetApplication(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientID := r.PathValue("clientID")
	client, err := s.store.OIDCClientByID(ctx, clientID)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such application")
		return
	}

	stats, err := s.store.StatsForClient(ctx, clientID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading application stats failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load application")
		return
	}

	writeJSON(w, http.StatusOK, applicationDetailResponse{
		applicationResponse: describeApplication(client),
		ActiveTokens:        stats.ActiveTokens,
		StandingGrants:      stats.StandingGrants,
		LastIssuedAt:        stats.LastIssuedAt,
	})
}

type registerApplicationRequest struct {
	Name         string   `json:"name"`
	DisplayName  string   `json:"displayName"`
	RedirectURIs []string `json:"redirectUris"`
	Scopes       []string `json:"scopes"`

	// Confidential means "issue a secret". Only for applications running on a
	// server that can actually keep one — a single-page app or a mobile client
	// cannot, and asking for a secret there produces a credential shipped to
	// every user, which is worse than having none.
	Confidential   bool `json:"confidential"`
	RequireConsent bool `json:"requireConsent"`
	DevMode        bool `json:"devMode"`
}

type registerApplicationResponse struct {
	applicationResponse

	// Secret appears exactly once, in this response, and is never recoverable —
	// only its hash is stored. The UI says so at the point it is shown.
	Secret string `json:"secret,omitempty"`
}

// handleRegisterApplication creates a relying party.
func (s *Server) handleRegisterApplication(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req registerApplicationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	actorID := session.SubjectID

	// No redirect URIs means no OpenID Connect, which is a whole legitimate
	// category rather than an incomplete form: an application behind the proxy
	// never speaks OIDC and has nothing to redirect to. It still needs to be an
	// entity, because that is what policy names and what a hostname belongs to.
	if len(req.RedirectURIs) == 0 {
		entity, newErr := directory.NewEntity(
			directory.TypeApplication, req.Name, req.DisplayName)
		if newErr != nil {
			writeError(w, http.StatusBadRequest, newErr.Error())
			return
		}
		if createErr := s.store.CreateEntity(ctx, entity, &actorID); createErr != nil {
			writeCreationError(w, createErr)
			return
		}

		s.log.InfoContext(ctx, "application registered",
			"name", entity.Name, "oidc", false, "actor", session.SubjectID)

		writeJSON(w, http.StatusCreated, applicationSummary{
			Name:        entity.Name,
			DisplayName: entity.DisplayName,
			Hostnames:   []string{},
		})
		return
	}

	method := store.AuthNone
	if req.Confidential {
		method = store.AuthClientSecretBasic
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid", "profile", "email", "groups"}
	}

	registered, err := s.store.RegisterOIDCClient(ctx, store.RegisterClientInput{
		Name:           req.Name,
		DisplayName:    req.DisplayName,
		AuthMethod:     method,
		RedirectURIs:   req.RedirectURIs,
		Scopes:         req.Scopes,
		DevMode:        req.DevMode,
		RequireConsent: req.RequireConsent,
		// The recovery-domain check from ADR 0009 runs here too, not only in
		// the CLI. A rule enforced on one path is a rule with a way around it.
	}, s.cfg.CheckRelyingPartyDomain, &actorID)
	if err != nil {
		// Registration refusals are the operator's to fix — a bad redirect URI,
		// a name already taken, a domain Cardinal must not be the IdP for — so
		// the reason is passed through rather than flattened to "invalid".
		writeCreationError(w, err)
		return
	}

	s.log.InfoContext(ctx, "application registered",
		"client_id", registered.Client.ClientID,
		"name", registered.Client.Name,
		"actor", session.SubjectID)

	writeJSON(w, http.StatusCreated, registerApplicationResponse{
		applicationResponse: describeApplication(registered.Client),
		Secret:              registered.Secret,
	})
}

// handleDisableApplication retires a relying party.
func (s *Server) handleDisableApplication(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	clientID := r.PathValue("clientID")
	actorID := session.SubjectID

	if err := s.store.DisableOIDCClient(ctx, clientID, &actorID); err != nil {
		if errors.Is(err, store.ErrClientNotFound) {
			writeError(w, http.StatusNotFound, "no such application")
			return
		}
		s.log.ErrorContext(ctx, "disabling application failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not disable application")
		return
	}

	s.log.InfoContext(ctx, "application disabled",
		"client_id", clientID, "actor", session.SubjectID)

	w.WriteHeader(http.StatusNoContent)
}
