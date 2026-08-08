package httpapi

import (
	"errors"
	"net/http"
	"time"

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

// handleListApplications returns every registered relying party.
func (s *Server) handleListApplications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clients, err := s.store.ListOIDCClients(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing applications failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list applications")
		return
	}

	out := make([]applicationResponse, 0, len(clients))
	for _, c := range clients {
		out = append(out, describeApplication(c))
	}
	writeJSON(w, http.StatusOK, out)
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

	method := store.AuthNone
	if req.Confidential {
		method = store.AuthClientSecretBasic
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid", "profile", "email", "groups"}
	}

	actorID := session.SubjectID
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
		writeError(w, http.StatusBadRequest, err.Error())
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
