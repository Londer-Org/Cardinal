package httpapi

import (
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/arthur-lonfils/cardinal/internal/config"
	"github.com/arthur-lonfils/cardinal/internal/store"
)

// Self-service profile editing.
//
// Separate from the admin API on purpose. Changing your own display name is not
// administering the directory, and requiring a device-bound credential
// authenticated in the last five minutes to correct a typo in your own name
// would make the step-up rule something people resent rather than respect.
//
// What is editable is deliberately narrow. Not `name`: the login appears in
// policy, in group listings and in every audit record a colleague reads, so
// letting someone rename themselves to a colleague's login — even briefly — is
// an impersonation primitive. Renaming stays an administrative act.

type updateProfileRequest struct {
	// Pointers so "not sent" and "sent empty" are different. Clearing a display
	// name is a legitimate thing to want; a form that omits the field is not a
	// request to blank it.
	DisplayName *string `json:"displayName"`
	Email       *string `json:"email"`
}

// checkEmail applies every rule about an address somebody may be reached at.
//
// Extracted so the administrative path uses exactly these rules rather than a
// similar-looking set. The comment this replaced already said why — "enforced
// on every path that can set one, because a rule enforced on one path is a rule
// with a way around it" — and then there was a second path.
var errMalformedEmail = errors.New("that does not look like an email address")

func (s *Server) checkEmail(address string) error {
	addr, err := mail.ParseAddress(address)
	if err != nil || addr.Address != address {
		return errMalformedEmail
	}

	// The recovery/IdP circularity rule from ADR 0009: an address on a domain
	// Cardinal is the identity provider for cannot serve as a recovery channel,
	// because an outage would take the way back in along with the thing that is
	// down.
	at := strings.LastIndex(address, "@")
	if at < 0 {
		return errMalformedEmail
	}
	return s.cfg.CheckRelyingPartyDomain(address[at+1:])
}

// statusForEmail separates "you typed something wrong" from "we could not
// check", which are a 400 and a 500 and must not be collapsed.
func statusForEmail(err error) int {
	if errors.Is(err, config.ErrCircularRecovery) {
		return http.StatusBadRequest
	}
	if errors.Is(err, errMalformedEmail) {
		return http.StatusBadRequest
	}
	// Anything else came from the domain check failing to run rather than from
	// the address being wrong, and reporting that as "you typed it wrong" would
	// send somebody editing a perfectly good address.
	return http.StatusInternalServerError
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req updateProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	update := store.ProfileUpdate{}

	if req.DisplayName != nil {
		trimmed := strings.TrimSpace(*req.DisplayName)
		if len(trimmed) > 200 {
			writeError(w, http.StatusBadRequest, "that display name is too long")
			return
		}
		update.DisplayName = &trimmed
	}

	if req.Email != nil {
		trimmed := strings.TrimSpace(*req.Email)
		if trimmed != "" {
			if err := s.checkEmail(trimmed); err != nil {
				writeError(w, statusForEmail(err), err.Error())
				return
			}
		}
		update.Email = &trimmed
	}

	if update.DisplayName == nil && update.Email == nil {
		writeError(w, http.StatusBadRequest, "nothing to change")
		return
	}

	actorID := session.SubjectID
	if _, err := s.store.UpdateProfile(ctx, session.SubjectID, update, &actorID); err != nil {
		s.log.ErrorContext(ctx, "updating profile failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not save your details")
		return
	}

	// The full account shape back, so the UI has one source of truth rather
	// than patching its own cache from a partial response.
	s.handleMe(w, r)
}
