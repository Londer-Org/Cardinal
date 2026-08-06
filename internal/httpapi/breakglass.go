package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/breakglass"
	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
)

// Break-glass over HTTP.
//
// This is also the bootstrap path, and that is not a workaround. Enrolling a
// passkey requires a session; obtaining a session requires a passkey. Something
// has to break the circle, and the offline key is the right thing to do it:
// there is no separate bootstrap mode to forget to disable, no default
// credential to leak, and every use is audited exactly like an emergency.
//
// The consequence is worth stating plainly: whoever holds the offline key can
// assume any account. That is what an emergency key is. It is why ADR 0009
// requires storing it offline, alerting loudly on use, and testing quarterly.

type breakGlassBeginResponse struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expiresAt"`
	Command   string    `json:"command"`
}

func (s *Server) handleBreakGlassBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if s.cfg.BreakGlass.PublicKey == "" {
		writeError(w, http.StatusNotImplemented, "break-glass is not configured")
		return
	}

	from, _ := netip.ParseAddr(s.clientIP.resolve(r))

	challenge, err := s.store.IssueBreakGlassChallenge(ctx, from)
	if err != nil {
		s.log.ErrorContext(ctx, "issuing break-glass challenge failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not issue a challenge")
		return
	}

	// Every issued challenge is worth noticing, not only redeemed ones: a burst
	// of challenges nobody completes is itself a signal.
	s.log.WarnContext(ctx, "break-glass challenge issued", "expires_at", challenge.ExpiresAt)

	writeJSON(w, http.StatusOK, breakGlassBeginResponse{
		Challenge: challenge.Encode(),
		ExpiresAt: challenge.ExpiresAt,
		// The command is echoed so an operator under pressure at 3am does not
		// have to remember the syntax.
		Command: signCommand(challenge.Encode()),
	})
}

// signCommand builds the command to run against the offline key.
//
// It names the running binary by its actual path rather than a bare "cardinal",
// because that is only a command if someone has already put it on PATH — and
// the first person to hit this is running from a build directory, where the
// echoed command failing is a bad first impression of an emergency procedure.
// The same binary serves and signs, so its own path is the correct answer.
//
// The key path stays a placeholder: it is offline by design, and Cardinal has
// no business claiming to know where it is. It is written as a plain path
// rather than <angle-brackets> because this line is meant to be copied whole,
// and a shell reads < and > as redirection — so the obvious placeholder syntax
// turns a substitution someone forgot into a baffling shell error instead of an
// obvious one.
func signCommand(nonce string) string {
	binary, err := os.Executable()
	if err != nil {
		// A name is still better than nothing, and this only fails on platforms
		// where the path is genuinely unknowable.
		binary = "cardinal"
	}
	return binary + " break-glass sign " + nonce + " -key /path/to/break-glass.key"
}

type breakGlassFinishRequest struct {
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
	// Login names the account to assume. The signature proves authorisation;
	// this says who to become.
	Login string `json:"login"`
}

func (s *Server) handleBreakGlassFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if s.cfg.BreakGlass.PublicKey == "" {
		writeError(w, http.StatusNotImplemented, "break-glass is not configured")
		return
	}

	var req breakGlassFinishRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	nonce, err := decodeChallenge(req.Challenge)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed challenge")
		return
	}

	subject, err := s.store.LookupEntity(ctx, directory.TypeUser, req.Login)
	if err != nil {
		// The challenge is deliberately not consumed here: refusing before
		// verification would let someone burn challenges by naming accounts
		// that do not exist. The rate limiter bounds the attempt instead.
		s.log.WarnContext(ctx, "break-glass attempted for an unknown account")
		writeError(w, http.StatusUnauthorized, "emergency access failed")
		return
	}

	session, err := s.store.RedeemBreakGlassChallenge(
		ctx, nonce, req.Signature, s.cfg.BreakGlass.PublicKey, subject.ID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrChallengeConsumed),
			errors.Is(err, store.ErrChallengeUnknown),
			errors.Is(err, breakglass.ErrChallengeExpired):
			s.log.WarnContext(ctx, "break-glass challenge rejected", "error", err)
		case errors.Is(err, breakglass.ErrInvalidSignature):
			// Someone presented a signature that does not verify against the
			// configured key. Worth waking a human for.
			s.log.ErrorContext(ctx, "BREAK-GLASS SIGNATURE INVALID — possible attempt to forge emergency access")
		default:
			s.log.ErrorContext(ctx, "break-glass redemption failed", "error", err)
		}
		writeError(w, http.StatusUnauthorized, "emergency access failed")
		return
	}

	// Deliberately at error level despite being a success: this is the event an
	// operator must never miss, and it should page. Break-glass that nobody
	// notices is just a backdoor (ADR 0009).
	s.log.ErrorContext(ctx, "BREAK-GLASS SESSION OPENED",
		"subject", subject.Name,
		"session_id", session.ID,
		"expires_at", session.ValidUntil)

	setSessionCookie(w, session.Token, session.ValidUntil, s.secureCookies, s.cfg.Server.CookieDomain)
	writeJSON(w, http.StatusOK, map[string]any{
		"subjectId": session.SubjectID.String(),
		"expiresAt": session.ValidUntil,
		"warning": "Emergency access. This session is short-lived and has been " +
			"recorded. Enrol a passkey, then sign out.",
	})
}

func decodeChallenge(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
}
