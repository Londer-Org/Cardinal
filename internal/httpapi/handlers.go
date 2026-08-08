package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/auth"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/mail"
	"go.londer.be/cardinal/internal/store"
)

// ── Login ──────────────────────────────────────────────────────────────────

type loginBeginRequest struct {
	// Login is optional. Omitting it starts a discoverable (usernameless)
	// ceremony, which is preferred: the user picks an account from their
	// authenticator, and the server reveals nothing beforehand.
	Login string `json:"login,omitempty"`
}

type ceremonyResponse struct {
	CeremonyID string `json:"ceremonyId"`
	Options    any    `json:"options"`
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req loginBeginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()

	if req.Login == "" {
		options, id, err := s.auth.BeginDiscoverableLogin(ctx)
		if err != nil {
			s.log.ErrorContext(ctx, "discoverable login begin failed", "error", err)
			writeError(w, http.StatusInternalServerError, "could not begin authentication")
			return
		}
		writeJSON(w, http.StatusOK, ceremonyResponse{CeremonyID: id.String(), Options: options})
		return
	}

	entity, err := s.store.LookupEntity(ctx, directory.TypeUser, req.Login)
	if err != nil {
		// Deliberately identical to every other failure below. Distinguishing
		// "no such user" here would turn this endpoint into a username
		// enumeration oracle, which is exactly what discoverable login avoids.
		s.log.InfoContext(ctx, "login begin for unknown or ineligible account")
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}

	options, id, err := s.auth.BeginLogin(ctx, entity.ID)
	if err != nil {
		if errors.Is(err, auth.ErrNotEnrolled) || errors.Is(err, auth.ErrUnknownUser) {
			writeError(w, http.StatusUnauthorized, "authentication failed")
			return
		}
		s.log.ErrorContext(ctx, "login begin failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not begin authentication")
		return
	}
	writeJSON(w, http.StatusOK, ceremonyResponse{CeremonyID: id.String(), Options: options})
}

type finishRequest struct {
	CeremonyID string          `json:"ceremonyId"`
	Response   json.RawMessage `json:"response"`
	Name       string          `json:"name,omitempty"`
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req finishRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ceremonyID, err := uuid.Parse(req.CeremonyID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ceremony id")
		return
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Response)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed authenticator response")
		return
	}

	ctx := r.Context()
	session, err := s.auth.FinishLogin(ctx, ceremonyID, parsed, s.sessionOrigin(r))
	if err != nil {
		// A cloned authenticator is worth surfacing separately in the log — it
		// is a security event rather than a failed login — but the client still
		// learns nothing beyond "failed".
		if errors.Is(err, store.ErrCloneDetected) {
			s.log.WarnContext(ctx, "possible cloned authenticator rejected", "error", err)
		} else {
			s.log.InfoContext(ctx, "login failed", "error", err)
		}
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}

	setSessionCookie(w, session.Token, session.ValidUntil, s.secureCookies, s.cfg.Server.CookieDomain)
	writeJSON(w, http.StatusOK, sessionBody(session))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := SessionFrom(r.Context())

	if err := s.store.RevokeSession(r.Context(), session.ID, &session.SubjectID); err != nil &&
		!errors.Is(err, store.ErrNoSuchSession) {
		s.log.ErrorContext(r.Context(), "logout failed", "error", err)
	}
	clearCookie(w, sessionCookie, s.secureCookies, s.cfg.Server.CookieDomain)
	w.WriteHeader(http.StatusNoContent)
}

type meResponse struct {
	ID            string    `json:"id"`
	Login         string    `json:"login"`
	DisplayName   string    `json:"displayName"`
	AuthMethod    string    `json:"authMethod"`
	AuthAt        time.Time `json:"authAt"`
	DeviceBound   bool      `json:"deviceBound"`
	FullyEnrolled bool      `json:"fullyEnrolled"`
	RecoveryCodes int       `json:"recoveryCodesRemaining"`

	// Email is empty when unset, which is the normal state: Cardinal does not
	// require one, and an account with no email is not a broken account.
	Email string `json:"email"`

	// CanAdminister drives what the UI renders. Not a security boundary — see
	// adminStatusFor — and deliberately re-evaluated per request.
	CanAdminister bool `json:"canAdminister"`

	// AdminNeedsReauth is true when membership is fine and only freshness is
	// missing, so the UI can offer a security key rather than hiding a section
	// the user is entitled to.
	AdminNeedsReauth bool `json:"adminNeedsReauth"`

	// Which parts of administration this session may use. Rendering a form
	// someone will be refused reads as a broken system rather than as a
	// permission they lack.
	CanManageUsers        bool `json:"canManageUsers"`
	CanManageApplications bool `json:"canManageApplications"`

	// The broad tier. Not implied by either of the two above — recovery sits
	// behind this one alone.
	CanAdministerDirectory bool `json:"canAdministerDirectory"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	entity, err := s.store.GetEntity(ctx, session.SubjectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load account")
		return
	}
	enrolled, err := s.store.FullyEnrolled(ctx, session.SubjectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load account")
		return
	}
	remaining, err := s.store.RemainingRecoveryCodes(ctx, session.SubjectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load account")
		return
	}
	admin := s.adminStatusFor(ctx, session)

	writeJSON(w, http.StatusOK, meResponse{
		ID:            entity.ID.String(),
		Login:         entity.Name,
		DisplayName:   entity.DisplayName,
		AuthMethod:    session.AuthMethod,
		AuthAt:        session.AuthAt,
		DeviceBound:   session.DeviceBound,
		FullyEnrolled: enrolled,
		RecoveryCodes: remaining,
		Email:         entityEmail(entity),
		// What the UI should offer, not what it is allowed to do. Every admin
		// endpoint evaluates the policy itself; this only decides what is
		// rendered, and whether to offer a way back in.
		CanAdminister:          admin.Allowed,
		AdminNeedsReauth:       admin.NeedsReauth,
		CanManageUsers:         admin.ManageUsers,
		CanManageApplications:  admin.ManageApplications,
		CanAdministerDirectory: admin.AdministerDirectory,
	})
}

// ── Credential registration ────────────────────────────────────────────────

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	options, id, err := s.auth.BeginRegistration(ctx, session.SubjectID)
	if err != nil {
		s.log.ErrorContext(ctx, "registration begin failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not begin registration")
		return
	}
	writeJSON(w, http.StatusOK, ceremonyResponse{CeremonyID: id.String(), Options: options})
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var req finishRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ceremonyID, err := uuid.Parse(req.CeremonyID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ceremony id")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Response)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed authenticator response")
		return
	}

	ctx := r.Context()
	cred, err := s.auth.FinishRegistration(ctx, ceremonyID, parsed, req.Name)
	if err != nil {
		if errors.Is(err, store.ErrCredentialExists) {
			writeError(w, http.StatusConflict, "this authenticator is already registered")
			return
		}
		s.log.InfoContext(ctx, "registration failed", "error", err)
		writeError(w, http.StatusBadRequest, "registration failed")
		return
	}

	// After the fact and best effort: the passkey is registered either way, and
	// a mail problem must not turn that into an error. This is the message that
	// matters most of the set — a passkey somebody did not add is somebody else
	// able to sign in as them.
	if session, ok := SessionFrom(ctx); ok {
		s.notify(ctx, session.SubjectID, mail.KindPasskeyRegistered, "")
	}

	writeJSON(w, http.StatusCreated, credentialBody(cred))
}

type credentialResponse struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt"`
	BackupEligible bool       `json:"backupEligible"`
	DeviceBound    bool       `json:"deviceBound"`
}

func credentialBody(c *store.Credential) credentialResponse {
	return credentialResponse{
		ID:             c.ID.String(),
		Name:           c.Name,
		CreatedAt:      c.CreatedAt,
		LastUsedAt:     c.LastUsedAt,
		BackupEligible: c.BackupEligible,
		// A credential that cannot sync stays on its hardware, which is what
		// lets policy demand a device-bound factor for privileged actions.
		DeviceBound: !c.BackupEligible,
	}
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	creds, err := s.store.CredentialsFor(ctx, session.SubjectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list credentials")
		return
	}

	out := make([]credentialResponse, 0, len(creds))
	for _, c := range creds {
		out = append(out, credentialBody(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid credential id")
		return
	}

	// Ownership check. Without it, any authenticated user could revoke anyone
	// else's credential by guessing an id — a trivial denial of service against
	// a specific person.
	creds, err := s.store.CredentialsFor(ctx, session.SubjectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load credentials")
		return
	}
	owned := false
	for _, c := range creds {
		if c.ID == id {
			owned = true
			break
		}
	}
	if !owned {
		// 404 rather than 403: confirming the id exists would leak the shape of
		// other accounts' credentials.
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}

	if err := s.store.RevokeCredential(ctx, id, &session.SubjectID); err != nil {
		if errors.Is(err, store.ErrCredentialNotFound) {
			writeError(w, http.StatusNotFound, "credential not found")
			return
		}
		// The store refuses to remove the last credential, which would be a
		// self-inflicted lockout. That message is genuinely useful, so it is
		// passed through.
		writeError(w, http.StatusConflict,
			"cannot revoke your only credential — register another first")
		return
	}

	// The other half of the pair. Somebody removing a passkey they still have
	// knows they did it; somebody who reads this and did not is being locked
	// out, which is the case worth telling them about while there is still time.
	s.notify(ctx, session.SubjectID, mail.KindPasskeyRevoked, "")

	w.WriteHeader(http.StatusNoContent)
}

// ── Recovery codes ─────────────────────────────────────────────────────────

type recoveryCodesResponse struct {
	Codes []string `json:"codes"`
	Note  string   `json:"note"`
}

func (s *Server) handleGenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	// Step-up: issuing recovery codes mints credentials that bypass the
	// authenticator entirely, so an old session is not enough. Once Cedar lands
	// (Phase 2) this becomes a policy rather than a hardcoded check.
	if time.Since(session.AuthAt) > 5*time.Minute {
		writeError(w, http.StatusForbidden,
			"re-authenticate before generating recovery codes")
		return
	}

	codes, err := s.store.GenerateRecoveryCodes(ctx, session.SubjectID, &session.SubjectID)
	if err != nil {
		s.log.ErrorContext(ctx, "generating recovery codes failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not generate recovery codes")
		return
	}

	writeJSON(w, http.StatusCreated, recoveryCodesResponse{
		Codes: codes,
		Note: "Store these offline. They are shown once and cannot be retrieved. " +
			"Any codes issued previously have been invalidated.",
	})
}

func (s *Server) handleRemainingRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	n, err := s.store.RemainingRecoveryCodes(ctx, session.SubjectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not count recovery codes")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"remaining": n})
}

func sessionBody(s *store.Session) map[string]any {
	return map[string]any{
		"subjectId":   s.SubjectID.String(),
		"authMethod":  s.AuthMethod,
		"deviceBound": s.DeviceBound,
		"expiresAt":   s.ValidUntil,
	}
}

// entityEmail reads the address out of the schema-governed attributes.
//
// A column would be simpler, but not every entity type has an email and
// Cardinal does not require one — so it lives in attrs, where the schema
// registry governs it, and is absent rather than empty when unset.
func entityEmail(e *directory.Entity) string {
	email, _ := e.Attrs["email"].(string) //nolint:errcheck // a missing or non-string attribute is the empty string
	return email
}
