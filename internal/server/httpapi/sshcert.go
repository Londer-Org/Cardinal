package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cedar-policy/cedar-go/types"
	"go.londer.be/cardinal/internal/ca/sshca"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/internal/store"
	"golang.org/x/crypto/ssh"
)

// Issuing an SSH certificate: the moment host access is decided.
//
// Everything about the design points here. `sshd` will do no thinking at login
// — it checks a signature and a principal list — so this request is the only
// place a policy can be consulted, and whatever it decides is what the host
// will believe for the certificate's lifetime.
//
// That makes two things load-bearing. The decision has to be logged, because
// nothing downstream will produce another record of it. And the principals have
// to come from the decision rather than the request, because a client naming
// its own principals would be authorising itself.

type sshCertificateRequest struct {
	// Host is the directory name of the machine, as an operator says it.
	Host string `json:"host"`

	// LocalAccount is the Unix user being asked for. Singular: a request for
	// one account is a question policy can answer, whereas a request for a list
	// invites partial answers and a client that quietly proceeds with less than
	// it asked for.
	LocalAccount string `json:"localAccount"`

	// PublicKey is the requester's own key, in authorized_keys form. Cardinal
	// never sees the private half.
	PublicKey string `json:"publicKey"`
}

type sshCertificateResponse struct {
	Certificate string   `json:"certificate"`
	Principals  []string `json:"principals"`
	ExpiresAt   string   `json:"expiresAt"`
	Host        string   `json:"host"`
}

func (s *Server) handleIssueSSHCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	if s.sshCA == nil {
		writeError(w, http.StatusNotImplemented,
			"host access is not enabled on this deployment")
		return
	}

	var req sshCertificateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}

	req.Host = strings.TrimSpace(req.Host)
	req.LocalAccount = strings.TrimSpace(req.LocalAccount)
	if req.Host == "" || req.LocalAccount == "" || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest,
			"host, localAccount and publicKey are all required")
		return
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		writeError(w, http.StatusBadRequest,
			"publicKey is not an SSH public key in authorized_keys form")
		return
	}

	// A host must exist in the directory before anyone can be granted access to
	// it. Refusing an unknown name rather than deciding about it keeps policy
	// from having to reason about machines nobody has enrolled.
	host, err := s.store.LookupEntity(ctx, directory.TypeHost, req.Host)
	if err != nil {
		writeError(w, http.StatusNotFound,
			"no such host — a machine must exist in the directory before access to it can be granted")
		return
	}

	// The host's own group memberships, which are what a policy matches on.
	// Resolved through the same path as a person's, because a host is an entity
	// like any other and "which machines" should not be a second mechanism.
	hostSubject, err := s.claims.ResolveByID(ctx, host.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "resolving host memberships failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}

	subject, err := s.claims.Resolve(ctx, session)
	if err != nil {
		s.log.InfoContext(ctx, "SSH certificate: subject could not be resolved", "error", err)
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	engine := s.policy.Load()
	if engine == nil {
		s.log.ErrorContext(ctx, "SSH certificate: no policy is active — refusing")
		writeError(w, http.StatusServiceUnavailable, "authorization unavailable")
		return
	}

	decision := engine.Evaluate(policy.Request{
		Subject:        subject,
		Action:         policy.ActionSSHLogin,
		Resource:       types.NewEntityUID(policy.TypeHost, types.String(host.ID.String())),
		ResourceGroups: hostSubject.Groups,
		Context: map[string]types.Value{
			"localAccount": types.String(req.LocalAccount),
			"host":         types.String(host.Name),
		},
	})

	principalID := subject.ID
	if logDecisionErr := s.store.LogDecision(ctx, store.DecisionRecord{
		DecisionPoint: "sshCA",
		PrincipalID:   &principalID,
		Action:        "SSHLogin",
		Resource:      host.Name + ":" + req.LocalAccount,
		Allowed:       decision.Allowed,
		Reasons:       decision.Reasons,
		Errors:        decision.Errors,
		PolicyVersion: decision.Version,
		Context: map[string]any{
			"auth_method":  subject.Auth.Method,
			"device_bound": subject.Auth.DeviceBound,
			"groups":       subject.GroupNames(),
		},
		Duration: decision.Duration,
	}); logDecisionErr != nil {
		// Best-effort, as everywhere else. But note this is the *only* record
		// that will ever exist of this authorization — the host will not
		// produce one — so a failure here is logged loudly rather than shrugged
		// at.
		s.log.ErrorContext(ctx, "SSH certificate decision log write failed",
			"error", logDecisionErr, "subject", subject.Login, "host", host.Name)
	}

	if len(decision.Errors) > 0 {
		s.log.ErrorContext(ctx, "SSH certificate policy evaluation errors",
			"errors", decision.Errors)
	}

	if !decision.Allowed {
		s.log.InfoContext(ctx, "SSH certificate refused",
			"subject", subject.Login, "host", host.Name,
			"account", req.LocalAccount, "explanation", decision.Explain())
		// The explanation travels, not just the rule names — because the two
		// kinds of refusal need different actions and look identical
		// otherwise. A forbid names itself and means "a rule is stopping you";
		// a default-deny names nothing and means "nobody has granted this".
		// Sending only an empty policy list would leave the reader unable to
		// tell which, which is the failure the decision explorer exists to fix.
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":  "you may not log into " + host.Name + " as " + req.LocalAccount,
			"reason": decision.Explain(),
			"policy": decision.Reasons,
		})
		return
	}

	cert, err := s.sshCA.Issue(ctx, sshca.Request{
		SubjectID: subject.ID,
		Login:     subject.Login,
		PublicKey: publicKey,
		// Exactly what policy allowed, and nothing the request asked for
		// beyond it. The list is the authorization: OpenSSH treats an empty
		// one as "any principal", so this is also why an empty decision must
		// never reach the CA.
		Principals: []string{req.LocalAccount},
		HostID:     &host.ID,
	})
	if err != nil {
		if errors.Is(err, store.ErrNoActiveSSHCA) {
			writeError(w, http.StatusServiceUnavailable,
				"no certificate authority key is signing — publish and activate one")
			return
		}
		s.log.ErrorContext(ctx, "issuing SSH certificate failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not issue a certificate")
		return
	}

	s.log.InfoContext(ctx, "SSH certificate issued",
		"subject", subject.Login, "host", host.Name, "account", req.LocalAccount,
		"serial", cert.Serial)

	writeJSON(w, http.StatusOK, sshCertificateResponse{
		Certificate: string(ssh.MarshalAuthorizedKey(cert)),
		Principals:  cert.ValidPrincipals,
		ExpiresAt:   time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339), //nolint:gosec // the CA sets this, bounded by DefaultValidity
		Host:        host.Name,
	})
}
