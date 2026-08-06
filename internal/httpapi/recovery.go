package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
)

// Dual-control recovery.
//
// Issuing an enrollment invitation for an account that already has passkeys is
// account takeover by shape: open the link, register a credential, and you are
// that person. One administrator could do that to another, which made the tiers
// decorative — the narrow one contained a path to the broad one.
//
// So the two cases are separated by what they actually are. Onboarding an
// account with no credentials is single control: nobody can sign in to it
// anyway. Restoring an account that can already sign in takes two distinct
// administrators, neither of them the subject.
//
// This is also what replaces the role separation break-glass used to provide
// (ADR 0014) — recovery without shell access to the host, but requiring two
// people rather than one sealed envelope.

type recoveryResponse struct {
	Subject     string    `json:"subject"`
	RequestedBy string    `json:"requestedBy"`
	RequestedAt time.Time `json:"requestedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Reason      string    `json:"reason"`

	// Approvers are named so a second administrator can see who else has
	// agreed. Approving because someone you trust already did is a real part of
	// how this decision gets made, and hiding it does not stop it happening.
	Approvers []string `json:"approvers"`
	Required  int      `json:"required"`
	Satisfied bool     `json:"satisfied"`
}

func describeRecovery(r *store.RecoveryRequest) recoveryResponse {
	return recoveryResponse{
		Subject:     r.Subject,
		RequestedBy: r.RequestedByAs,
		RequestedAt: r.RequestedAt,
		ExpiresAt:   r.ExpiresAt,
		Reason:      r.Reason,
		Approvers:   r.Approvers,
		Required:    store.RecoveryApprovals,
		Satisfied:   r.Satisfied(),
	}
}

func (s *Server) handleListRecoveries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	requests, err := s.store.OpenRecoveries(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing recovery requests failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list requests")
		return
	}

	out := make([]recoveryResponse, 0, len(requests))
	for _, req := range requests {
		out = append(out, describeRecovery(req))
	}
	writeJSON(w, http.StatusOK, out)
}

type requestRecoveryRequest struct {
	Login  string `json:"login"`
	Reason string `json:"reason"`
}

func (s *Server) handleRequestRecovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req requestRecoveryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	subject, err := s.store.LookupEntity(ctx, directory.TypeUser, strings.TrimSpace(req.Login))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	opened, err := s.store.RequestRecovery(ctx, subject.ID, session.SubjectID,
		strings.TrimSpace(req.Reason))
	if err != nil {
		if errors.Is(err, store.ErrSelfRecovery) {
			writeError(w, http.StatusBadRequest,
				"you cannot request recovery of your own account — that would be "+
					"one person minting a second credential for themselves")
			return
		}
		// A duplicate trips the one-live-request index, which is a conflict
		// rather than a fault.
		writeError(w, http.StatusConflict,
			"there is already an open request for that account")
		return
	}

	// Warning level. Somebody asking to take over an account is worth noticing
	// even when it is entirely legitimate, which it usually is.
	s.log.WarnContext(ctx, "recovery requested",
		"subject", subject.Name, "requested_by", session.SubjectID)

	writeJSON(w, http.StatusCreated, describeRecovery(opened))
}

type approvedRecoveryResponse struct {
	recoveryResponse

	// InvitationURL appears only on the approval that satisfies the threshold,
	// and only once.
	InvitationURL string `json:"invitationUrl,omitempty"`
}

func (s *Server) handleApproveRecovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	subject, err := s.store.LookupEntity(ctx, directory.TypeUser, r.PathValue("login"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	approved, err := s.store.ApproveRecovery(ctx, subject.ID, session.SubjectID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrSelfRecovery):
			writeError(w, http.StatusBadRequest, "you cannot approve your own recovery")
		case errors.Is(err, store.ErrAlreadyApproved):
			writeError(w, http.StatusConflict,
				"you have already approved this — dual control needs a second "+
					"person, not a second click")
		case errors.Is(err, store.ErrRecoveryNotFound):
			writeError(w, http.StatusNotFound, "no open request for that account")
		default:
			s.log.ErrorContext(ctx, "approving recovery failed", "error", err)
			writeError(w, http.StatusInternalServerError, "could not record that")
		}
		return
	}

	out := approvedRecoveryResponse{recoveryResponse: describeRecovery(approved)}

	if approved.Satisfied() {
		actorID := session.SubjectID
		issued, err := s.store.IssueInvitation(ctx, subject.ID, &actorID, store.InvitationTTL)
		if err != nil {
			s.log.ErrorContext(ctx, "issuing recovery invitation failed", "error", err)
			writeError(w, http.StatusInternalServerError,
				"the approval was recorded, but the link could not be issued — "+
					"approve again to retry")
			return
		}
		if err := s.store.CompleteRecovery(ctx, approved.ID); err != nil {
			s.log.ErrorContext(ctx, "completing recovery failed", "error", err)
		}
		out.InvitationURL = s.cfg.Server.PublicURL + "/enroll?token=" + issued.Token

		s.log.WarnContext(ctx, "recovery approved and link issued",
			"subject", subject.Name, "approvers", approved.Approvers)
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCancelRecovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	subject, err := s.store.LookupEntity(ctx, directory.TypeUser, r.PathValue("login"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}

	actorID := session.SubjectID
	if err := s.store.CancelRecovery(ctx, subject.ID, &actorID); err != nil {
		if errors.Is(err, store.ErrRecoveryNotFound) {
			writeError(w, http.StatusNotFound, "no open request for that account")
			return
		}
		s.log.ErrorContext(ctx, "cancelling recovery failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not cancel it")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
