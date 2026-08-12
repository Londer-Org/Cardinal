package httpapi

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"go.londer.be/cardinal/internal/store"
)

// Signing a terminal in from a device that is not this one.
//
// Three endpoints. The terminal starts a request and gets two values: a device
// code it keeps and polls with, and a short user code it prints. Somebody with
// a browser looks the short one up, sees what they are about to approve, and
// approves it. The terminal's next poll returns a session.
//
// Approving is behind requireDeviceBound like the loopback flow, and for the
// same reason: the entire point is to hand a terminal something a passkey
// proved, so an access token must not be able to bootstrap one.

type deviceStartRequest struct {
	VerifierHash string `json:"verifierHash"`
}

type deviceStartResponse struct {
	DeviceCode string `json:"deviceCode"`
	UserCode   string `json:"userCode"`

	// VerificationURI is where to go, and VerificationURIComplete is the same
	// with the code already in it — for the case where the terminal can show a
	// link somebody clicks on another device.
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`

	ExpiresIn int `json:"expiresIn"`
	Interval  int `json:"interval"`
}

func (s *Server) handleDeviceStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req deviceStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.VerifierHash == "" {
		writeError(w, http.StatusBadRequest, "a verifier hash is required")
		return
	}

	deviceCode, pending, err := s.store.CreateDeviceAuthorization(ctx, req.VerifierHash, clientAddr(r))
	if err != nil {
		s.log.ErrorContext(ctx, "starting a device authorization failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not start the sign-in")
		return
	}

	base := strings.TrimRight(s.cfg.Server.PublicURL, "/")
	writeJSON(w, http.StatusCreated, deviceStartResponse{
		DeviceCode:              deviceCode,
		UserCode:                pending.UserCode,
		VerificationURI:         base + "/cli-login",
		VerificationURIComplete: base + "/cli-login?code=" + pending.UserCode,
		ExpiresIn:               int(time.Until(pending.ExpiresAt).Seconds()),
		Interval:                int(store.DevicePollInterval.Seconds()),
	})
}

type devicePendingResponse struct {
	UserCode  string `json:"userCode"`
	ExpiresAt string `json:"expiresAt"`

	// RequestedFrom is the address the request came from, as this server saw
	// it. Never a name the terminal chose: "approve the code from web-01" is
	// exactly the sentence somebody running this attack would like to arrange,
	// and a self-reported hostname would let them.
	RequestedFrom string `json:"requestedFrom"`
}

// handleDeviceLookup describes a pending request so the console can show what
// is about to be approved.
func (s *Server) handleDeviceLookup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	pending, err := s.store.PendingDeviceRequest(ctx, normaliseUserCode(r.PathValue("code")))
	if err != nil {
		// One answer for unknown, expired and already approved. The difference
		// would tell somebody sweeping for live codes when they had found one.
		writeError(w, http.StatusNotFound, "no request is waiting for that code")
		return
	}

	writeJSON(w, http.StatusOK, devicePendingResponse{
		UserCode:      pending.UserCode,
		ExpiresAt:     pending.ExpiresAt.UTC().Format(time.RFC3339),
		RequestedFrom: pending.RequestedIP,
	})
}

// handleDeviceApprove attaches the approver's session to the request.
func (s *Server) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	code := normaliseUserCode(r.PathValue("code"))
	err := s.store.ApproveDeviceAuthorization(ctx, code, session.ID, session.SubjectID)
	switch {
	case errors.Is(err, store.ErrCLIAuthNotFound):
		writeError(w, http.StatusNotFound, "no request is waiting for that code")
		return
	case err != nil:
		// Distinguished from the refusal above rather than folded into it. A
		// 404 for every failure means a broken approval and a stale code look
		// identical, and the broken one is the expensive kind to find.
		s.log.ErrorContext(ctx, "approving a device authorization failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not approve the terminal")
		return
	}

	s.log.InfoContext(ctx, "terminal approved from another device",
		"code", code, "by", session.SubjectID)
	w.WriteHeader(http.StatusNoContent)
}

type deviceCollectRequest struct {
	DeviceCode string `json:"deviceCode"`
	Verifier   string `json:"verifier"`
}

// handleDeviceCollect is what the terminal polls.
//
// Unauthenticated, necessarily — the caller is a terminal that has nothing yet.
// What protects it is that the device code is single use, expires in minutes,
// and is worthless without the verifier the terminal never sent anywhere.
func (s *Server) handleDeviceCollect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req deviceCollectRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DeviceCode == "" || req.Verifier == "" {
		writeError(w, http.StatusBadRequest, "a device code and its verifier are required")
		return
	}

	session, err := s.store.CollectDeviceAuthorization(ctx, req.DeviceCode, req.Verifier,
		store.SessionOrigin{ClientIP: clientAddr(r).String(), UserAgent: "cardinal CLI (device)"})
	switch {
	case errors.Is(err, store.ErrDevicePending):
		// Not an error the person should see: the terminal is waiting, and this
		// is the answer that says keep waiting. 202 rather than an error status
		// so a proxy or a client library does not treat polling as failure.
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":   "pending",
			"interval": int(store.DevicePollInterval.Seconds()),
		})
		return
	case err != nil:
		writeError(w, http.StatusNotFound, "no approved request for that code")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":       session.Token,
		"subject":     session.SubjectID.String(),
		"deviceBound": session.DeviceBound,
	})
}

// normaliseUserCode accepts what somebody types: any case, with or without the
// separator, and with the spaces a phone keyboard adds.
func normaliseUserCode(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(raw)))

	if len(cleaned) != 8 {
		return cleaned
	}
	return cleaned[:4] + "-" + cleaned[4:]
}

// clientAddr is the address this request came from, as the server sees it.
func clientAddr(r *http.Request) netip.Addr {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return addr
}
