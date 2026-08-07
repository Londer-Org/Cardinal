package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// Vouching for a machine's name.
//
// The end of trust-on-first-use, which is the most visible thing this project
// does. Today every user decides on first contact whether an unknown fingerprint
// really is web-01 — a question nobody can answer, so everybody types `yes`.
// With `@cert-authority` in known_hosts they trust one key instead, and the
// machine proves its own name.
//
// There is no Cedar decision here, and that is on purpose. The question a policy
// would answer — may this machine hold a certificate for this name — has already
// been answered by somebody writing the name into the directory. Adding an
// evaluation whose only possible input is the same fact would be ceremony, not
// authorization. The issuance is recorded in the journal, which is what an
// auditor actually needs.

type hostCertificateRequest struct {
	// PublicKey is the machine's existing SSH host key, in authorized_keys
	// form. Not the key it authenticates to Cardinal with.
	PublicKey string `json:"publicKey"`
}

type hostCertificateResponse struct {
	Certificate string   `json:"certificate"`
	Principals  []string `json:"principals"`
	ExpiresAt   string   `json:"expiresAt"`
}

func (s *Server) handleIssueHostCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cred, ok := HostFrom(ctx)
	if !ok {
		writeError(w, http.StatusUnauthorized, "host authentication failed")
		return
	}

	if s.sshCA == nil {
		writeError(w, http.StatusNotImplemented,
			"host access is not enabled on this deployment")
		return
	}

	var req hostCertificateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "publicKey is required")
		return
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		writeError(w, http.StatusBadRequest,
			"publicKey is not an SSH public key in authorized_keys form")
		return
	}

	// From the directory, and the request has no say in it. A machine asking for
	// a certificate naming git.example.com is asking to be git.example.com, and
	// the only defence against a compromised host doing exactly that is that
	// nothing it sends is consulted here.
	principals, err := s.store.HostPrincipals(ctx, cred.HostID)
	if err != nil {
		s.log.ErrorContext(ctx, "host certificate: resolving principals failed",
			"host", cred.HostName, "error", err)
		writeError(w, http.StatusServiceUnavailable, "could not resolve this host's names")
		return
	}

	cert, err := s.sshCA.IssueHost(ctx, sshca.HostRequest{
		HostID:     cred.HostID,
		Name:       cred.HostName,
		PublicKey:  publicKey,
		Principals: principals,
	})
	if err != nil {
		s.log.ErrorContext(ctx, "host certificate issuance failed",
			"host", cred.HostName, "error", err)
		writeError(w, http.StatusServiceUnavailable, "could not issue a host certificate")
		return
	}

	s.log.InfoContext(ctx, "host certificate issued",
		"host", cred.HostName, "principals", principals, "serial", cert.Serial)

	writeJSON(w, http.StatusOK, hostCertificateResponse{
		Certificate: string(ssh.MarshalAuthorizedKey(cert)),
		Principals:  principals,
		ExpiresAt:   time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339), //nolint:gosec // clamped at signing
	})
}
