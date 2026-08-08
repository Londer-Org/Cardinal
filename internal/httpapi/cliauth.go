package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"go.londer.be/cardinal/internal/store"
)

// Signing a terminal in.
//
// Two endpoints, and the split between them is the security of the thing. The
// console approves and receives a *code*; the terminal exchanges that code for
// a session, presenting a verifier it generated and never sent to anybody. What
// travels through the browser — through shell history, proxy logs, and the
// address bar — is therefore worthless on its own.
//
// The session the terminal ends up with inherits the console's ceremony rather
// than being something weaker. That is the whole reason this exists: policy
// refuses an access token an SSH certificate (ADR 0018), correctly, and the
// alternative to this flow was making tokens device-bound — putting a
// credential that reaches every machine in the fleet into a file on disk.

type cliAuthorizeRequest struct {
	// Callback is where the console will send the browser. Loopback only.
	Callback string `json:"callback"`

	// VerifierHash is the SHA-256 of the terminal's secret, base64url, no
	// padding. The terminal sends it here through the browser and sends the
	// secret itself only to the exchange.
	VerifierHash string `json:"verifierHash"`
}

// handleCLIAuthorize is called by the console when somebody approves.
//
// Behind requireDeviceBound, and that is not belt and braces: the entire point
// is to hand a terminal something a passkey proved, so an access token must not
// be able to bootstrap one. Without this, a leaked token could mint a
// device-bound session and walk straight past every rule that refuses tokens.
func (s *Server) handleCLIAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req cliAuthorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}

	if err := validCLICallback(req.Callback); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Length rather than format: it is a hash the terminal computed, and the
	// only thing worth refusing is something obviously not one.
	if len(req.VerifierHash) < 43 {
		writeError(w, http.StatusBadRequest, "verifierHash is missing or too short")
		return
	}

	code, err := s.store.CreateCLIAuthorization(ctx, session.ID, req.VerifierHash)
	if err != nil {
		s.log.ErrorContext(ctx, "creating a CLI authorization failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not authorize the terminal")
		return
	}

	s.log.InfoContext(ctx, "terminal authorized",
		"subject", session.SubjectID, "callback", req.Callback)

	writeJSON(w, http.StatusOK, map[string]any{
		"code":      code,
		"expiresIn": int(store.CLIAuthTTL.Seconds()),
	})
}

type cliExchangeRequest struct {
	Code     string `json:"code"`
	Verifier string `json:"verifier"`
}

// handleCLIExchange turns a code into a session, once.
//
// Unauthenticated, necessarily — the caller is a terminal that has nothing yet.
// What protects it is that the code is single-use, expires in ninety seconds,
// and cannot be exchanged without a verifier that only ever existed in the
// process that generated it.
func (s *Server) handleCLIExchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req cliExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if req.Code == "" || req.Verifier == "" {
		writeError(w, http.StatusBadRequest, "code and verifier are both required")
		return
	}

	session, err := s.store.ClaimCLIAuthorization(ctx, req.Code, req.Verifier, s.sessionOrigin(r))
	if err != nil {
		if errors.Is(err, store.ErrCLIAuthNotFound) {
			// One answer for unknown, spent and expired. Telling them apart
			// would say whether a guess was close.
			writeError(w, http.StatusUnauthorized, "that authorization is not valid")
			return
		}
		s.log.ErrorContext(ctx, "claiming a CLI authorization failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not complete the exchange")
		return
	}

	s.log.InfoContext(ctx, "terminal session issued",
		"subject", session.SubjectID, "device_bound", session.DeviceBound)

	// In the body, not in a cookie. The caller is not a browser, and a Set-Cookie
	// here would be a credential the terminal has to know to go looking for.
	writeJSON(w, http.StatusOK, map[string]any{
		"token":       session.Token,
		"expiresAt":   session.ValidUntil,
		"subject":     session.SubjectID,
		"deviceBound": session.DeviceBound,
	})
}

// validCLICallback refuses anywhere the browser should not be sent.
//
// Loopback only, and by literal address rather than by name. "localhost" is a
// name somebody else's DNS can answer, and a redirect is the one place where
// being sent to the wrong host means handing over the code.
func validCLICallback(raw string) error {
	if raw == "" {
		return errors.New("callback is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("callback is not a URL")
	}
	if u.Scheme != "http" {
		return errors.New("callback must be http on a loopback address")
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "::1" {
		return errors.New("callback must be 127.0.0.1 or ::1 — a name is something " +
			"another resolver can answer, and this is a redirect carrying a code")
	}
	if u.Port() == "" {
		return errors.New("callback must name a port")
	}
	if strings.Contains(raw, "@") {
		return errors.New("callback must not carry credentials")
	}
	return nil
}
