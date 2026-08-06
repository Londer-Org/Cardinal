package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

// Enrollment: how a new account gets its first passkey.
//
// These four endpoints are the only unauthenticated write path in Cardinal
// besides sign-in itself, so the reasoning matters.
//
// An invitation token authorises exactly one act — registering a credential on
// one named account — once, within a day, revocably. It yields no session: the
// user signs in afterwards with the passkey they just made, which also proves
// the credential works before they walk away believing it does.
//
// The alternative this replaces was break-glass, an offline key that can assume
// *any* account, used as an onboarding tool because nothing else existed.

// invitationRateLimit bounds flooding, not guessing.
//
// The token is 256 bits, so brute force is not the threat. What this actually
// prevents is one caller turning the unauthenticated endpoints into unbounded
// WebAuthn ceremony creation.
//
// Keyed by client address, which means everyone behind one office NAT shares an
// allowance. That is the reason this is not tighter: onboarding a team on their
// first morning is exactly when a shared source address sees a burst of
// legitimate enrollment traffic, and a limit that turns that into support
// tickets would get raised in a hurry by whoever was on the receiving end.
// Sixty in fifteen minutes is generous for people and still bounds a flood.
var invitationRateLimit = store.RateLimit{
	Scope: "enrollment", Limit: 60, Window: 15 * time.Minute,
}

type invitationResponse struct {
	Login       string    `json:"login"`
	DisplayName string    `json:"displayName"`
	ExpiresAt   time.Time `json:"expiresAt"`

	// AlreadyEnrolled tells the screen to say something different: this is a
	// recovery, not an onboarding, and the person should know that finishing it
	// adds a credential to an account that already has some.
	AlreadyEnrolled bool `json:"alreadyEnrolled"`
}

// handleInvitationDetails describes an invitation to whoever holds the link.
//
// It reveals the login and display name, which is deliberate: someone opening a
// link out of a chat message must be able to see whose account they are about
// to take possession of, and a screen that says only "register a passkey" is
// one that gets used on the wrong account without anyone noticing.
//
// The token is required to see any of it, so this leaks nothing to someone who
// does not already hold a valid invitation.
func (s *Server) handleInvitationDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing invitation")
		return
	}

	if !s.allowEnrollment(w, r) {
		return
	}

	inv, err := s.store.InvitationByToken(ctx, token)
	if err != nil {
		// One message for expired, revoked, spent and never-existed. Telling
		// the holder which would say whether they guessed a real account.
		writeError(w, http.StatusNotFound,
			"this invitation is not valid — it may have expired or already been used. "+
				"Ask whoever sent it for a new one")
		return
	}

	enrolled, err := s.store.HasCredentials(ctx, inv.SubjectID)
	if err != nil {
		s.log.ErrorContext(ctx, "counting credentials failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the account")
		return
	}

	writeJSON(w, http.StatusOK, invitationResponse{
		Login:           inv.Login,
		DisplayName:     inv.DisplayName,
		ExpiresAt:       inv.ExpiresAt,
		AlreadyEnrolled: enrolled,
	})
}

type enrollBeginRequest struct {
	Token string `json:"token"`
}

// handleEnrollBegin starts a registration ceremony against the invited account.
//
// The invitation is checked but not spent here. A ceremony that fails — the
// user cancels, the key is not present, the browser refuses — must not burn the
// invitation, or every fumbled tap would need an administrator.
func (s *Server) handleEnrollBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req enrollBeginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.allowEnrollment(w, r) {
		return
	}

	inv, err := s.store.InvitationByToken(ctx, req.Token)
	if err != nil {
		writeError(w, http.StatusNotFound, "this invitation is not valid")
		return
	}

	options, ceremonyID, err := s.auth.BeginRegistration(ctx, inv.SubjectID)
	if err != nil {
		s.log.ErrorContext(ctx, "beginning enrollment failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not start enrollment")
		return
	}

	writeJSON(w, http.StatusOK, ceremonyResponse{
		CeremonyID: ceremonyID.String(),
		Options:    options,
	})
}

type enrollFinishRequest struct {
	Token      string          `json:"token"`
	CeremonyID string          `json:"ceremonyId"`
	Response   json.RawMessage `json:"response"`
	Name       string          `json:"name"`

	// The invitation is also where an account stops being blank. Without this
	// a new user arrives in every connected application as a UUID and nothing
	// else, and there is no obvious moment afterwards at which they would think
	// to fix it.
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
}

// handleEnrollFinish registers the credential and spends the invitation.
//
// Order matters: the credential is stored first, and only then is the
// invitation marked spent. The other way round, a failure between the two would
// leave the person with a consumed link and no passkey — locked out by the
// mechanism meant to let them in.
func (s *Server) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req enrollFinishRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.allowEnrollment(w, r) {
		return
	}

	inv, err := s.store.InvitationByToken(ctx, req.Token)
	if err != nil {
		writeError(w, http.StatusNotFound, "this invitation is not valid")
		return
	}

	ceremonyID, err := uuid.Parse(req.CeremonyID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ceremony")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Passkey"
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Response)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed authenticator response")
		return
	}

	credential, err := s.auth.FinishRegistration(ctx, ceremonyID, parsed, name)
	if err != nil {
		s.log.InfoContext(ctx, "enrollment ceremony failed", "error", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Ceremonies are bound to a subject when they are created, but bind again
	// here rather than trusting that: this path is unauthenticated, and a
	// ceremony id from a different account must not be redeemable against this
	// invitation.
	if credential.EntityID != inv.SubjectID {
		s.log.ErrorContext(ctx, "enrollment ceremony belonged to another account",
			"invitation_subject", inv.SubjectID, "ceremony_subject", credential.EntityID)
		writeError(w, http.StatusBadRequest, "this ceremony does not match the invitation")
		return
	}

	from, _ := netip.ParseAddr(s.clientIP.resolve(r))
	if _, err := s.store.RedeemInvitation(ctx, req.Token, from); err != nil {
		// The credential exists and works. Refusing now would be worse than
		// leaving the invitation live, and it is single-use in SQL regardless.
		s.log.ErrorContext(ctx, "marking invitation redeemed failed", "error", err)
	}

	// Best-effort: an account with a passkey and no display name is usable, and
	// failing enrollment over a name would be a poor trade.
	update := store.ProfileUpdate{}
	if displayName := strings.TrimSpace(req.DisplayName); displayName != "" {
		update.DisplayName = &displayName
	}
	if email := strings.TrimSpace(req.Email); email != "" {
		update.Email = &email
	}
	if update.DisplayName != nil || update.Email != nil {
		if _, err := s.store.UpdateProfile(ctx, inv.SubjectID, update, &inv.SubjectID); err != nil {
			s.log.ErrorContext(ctx, "saving enrollment details failed", "error", err)
		}
	}

	s.log.InfoContext(ctx, "account enrolled", "subject", inv.SubjectID, "login", inv.Login)

	// Deliberately no session. The user signs in with the passkey they just
	// registered, which proves it works before they walk away believing it
	// does — and keeps an invitation from ever being a way to obtain a session.
	writeJSON(w, http.StatusOK, map[string]any{"enrolled": true, "login": inv.Login})
}

// allowEnrollment applies the rate limit, keyed by client address.
func (s *Server) allowEnrollment(w http.ResponseWriter, r *http.Request) bool {
	ok, err := s.store.Allow(r.Context(), invitationRateLimit, s.clientIP.resolve(r))
	if err != nil {
		// Fails closed. An enrollment path that opens up when the database is
		// unhappy is the wrong way round.
		s.log.ErrorContext(r.Context(), "enrollment rate limit failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "please try again shortly")
		return false
	}
	if !ok {
		writeError(w, http.StatusTooManyRequests, "too many attempts — try again later")
		return false
	}
	return true
}

// ── Administration ──────────────────────────────────────────────────────────

type issueInvitationRequest struct {
	Login string `json:"login"`
}

type issuedInvitationResponse struct {
	Login     string    `json:"login"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expiresAt"`

	// Recovery is true when the account already had credentials. The UI says so
	// loudly: issuing one of these for an account that can already sign in is
	// how a lost-device recovery works, and also what an account takeover looks
	// like.
	Recovery bool `json:"recovery"`
}

func (s *Server) handleIssueInvitation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req issueInvitationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	entity, err := s.store.LookupEntity(ctx, "user", strings.TrimSpace(req.Login))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	recovery, err := s.store.HasCredentials(ctx, entity.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "counting credentials failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the account")
		return
	}

	actorID := session.SubjectID
	issued, err := s.store.IssueInvitation(ctx, entity.ID, &actorID, store.InvitationTTL)
	if err != nil {
		s.log.ErrorContext(ctx, "issuing invitation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not issue an invitation")
		return
	}

	if recovery {
		// Warning level, because this is the shape of an account takeover as
		// well as of a legitimate recovery, and the two are indistinguishable
		// from the record alone.
		s.log.WarnContext(ctx, "invitation issued for an account that can already sign in",
			"subject", entity.ID, "login", entity.Name, "actor", actorID)
	} else {
		s.log.InfoContext(ctx, "invitation issued",
			"subject", entity.ID, "login", entity.Name, "actor", actorID)
	}

	writeJSON(w, http.StatusCreated, issuedInvitationResponse{
		Login:     entity.Name,
		URL:       s.cfg.Server.PublicURL + "/enroll?token=" + issued.Token,
		ExpiresAt: issued.Invitation.ExpiresAt,
		Recovery:  recovery,
	})
}

type pendingInvitationResponse struct {
	Login       string    `json:"login"`
	DisplayName string    `json:"displayName"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

func (s *Server) handleListInvitations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	invitations, err := s.store.PendingInvitations(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing invitations failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list invitations")
		return
	}

	out := make([]pendingInvitationResponse, 0, len(invitations))
	for _, inv := range invitations {
		out = append(out, pendingInvitationResponse{
			Login:       inv.Login,
			DisplayName: inv.DisplayName,
			ExpiresAt:   inv.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	entity, err := s.store.LookupEntity(ctx, "user", r.PathValue("login"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	actorID := session.SubjectID
	if err := s.store.RevokeInvitation(ctx, entity.ID, &actorID); err != nil {
		if errors.Is(err, store.ErrInvitationNotFound) {
			writeError(w, http.StatusNotFound, "no outstanding invitation")
			return
		}
		s.log.ErrorContext(ctx, "revoking invitation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not revoke it")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
