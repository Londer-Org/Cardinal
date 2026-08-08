package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// Getting back in with a recovery code.
//
// Codes could be generated and counted and never spent: the store had a
// Redeem function, tested, that no route, command or page called. So the second
// of this project's phase-0 non-negotiables — offline recovery codes, single
// use, shown once — produced something a person could print and then had
// nowhere to type.
//
// A code redeems into an *enrollment*, not a session, and that is the whole
// design. Credential self-service is behind requireDeviceBound, because those
// are the routes that decide what can authenticate as you and a weaker
// credential must not be able to change that. A recovery code is exactly such a
// weaker credential — it is a string on paper — so a session minted from one
// would be unable to register the passkey it exists to let somebody register.
//
// Rather than making a hole for it, redeeming produces the same short-lived
// enrollment an administrator issues with `cardinal invite`. The person then
// walks the enrollment path that already exists and is already tested, and no
// route has to start accepting something that is not device-bound.

// recoveryEnrollmentTTL is how long the enrollment lives.
//
// Minutes, not hours. It is handed straight to the browser that redeemed the
// code, so the only thing a longer window buys is more time for somebody who
// found the printed sheet.
const recoveryEnrollmentTTL = 15 * time.Minute

type redeemRecoveryRequest struct {
	Login string `json:"login"`
	Code  string `json:"code"`
}

// handleRedeemRecoveryCode exchanges a code for an enrollment.
//
// Unauthenticated, necessarily: somebody who could authenticate would not need
// it. Rate limited to five attempts per fifteen minutes, which is what stops a
// code being guessed rather than found.
func (s *Server) handleRedeemRecoveryCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req redeemRecoveryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}
	req.Login = strings.TrimSpace(req.Login)
	if req.Login == "" || strings.TrimSpace(req.Code) == "" {
		writeError(w, http.StatusBadRequest, "a login and a recovery code are both required")
		return
	}

	// One answer for every way this can fail, and it has to be one answer.
	//
	// "No such account" and "wrong code" are different facts, and telling them
	// apart turns this endpoint into a way to ask whether somebody works here —
	// from an unauthenticated request, five times per quarter hour, against a
	// login somebody guessed from an email address.
	refuse := func() {
		writeError(w, http.StatusUnauthorized,
			"that login and recovery code do not match, or the code has been used")
	}

	entity, err := s.store.LookupEntity(ctx, directory.TypeUser, req.Login)
	if err != nil {
		refuse()
		return
	}

	if redeemErr := s.store.RedeemRecoveryCode(ctx, entity.ID, req.Code); redeemErr != nil {
		if errors.Is(redeemErr, store.ErrNoRecoveryCode) ||
			errors.Is(redeemErr, store.ErrCodeAlreadyUsed) {
			refuse()
			return
		}
		s.log.ErrorContext(ctx, "redeeming a recovery code failed", "error", redeemErr)
		writeError(w, http.StatusInternalServerError, "could not check the code")
		return
	}

	// Issued by nobody, because nobody authorised it: the code did. Naming an
	// actor here would make the journal say an administrator invited them.
	invitation, err := s.store.IssueInvitation(ctx, entity.ID, nil, recoveryEnrollmentTTL)
	if err != nil {
		// The code is spent and the enrollment did not happen, which is the one
		// genuinely bad outcome here — so it is logged loudly rather than being
		// left as a 500 somebody has to correlate.
		s.log.ErrorContext(ctx, "RECOVERY CODE SPENT WITHOUT AN ENROLLMENT",
			"subject", entity.ID, "error", err)
		writeError(w, http.StatusInternalServerError,
			"the code was accepted and the enrollment could not be created — "+
				"that code is now spent, so use another")
		return
	}

	s.log.InfoContext(ctx, "recovery code redeemed",
		"subject", entity.ID, "expires", invitation.Invitation.ExpiresAt)

	// The token, for the client to walk the enrollment path with. Not a session:
	// what this proves is that somebody holds a code, and what that earns is the
	// chance to register a credential, not the ability to act as the account.
	writeJSON(w, http.StatusOK, map[string]any{
		"token":     invitation.Token,
		"expiresAt": invitation.Invitation.ExpiresAt,
	})
}
