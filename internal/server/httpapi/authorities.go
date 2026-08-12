package httpapi

import (
	"context"
	"encoding/pem"
	"net/http"
	"strings"
	"time"
)

// Certificate authorities, and the bundles that have to reach every machine.
//
// Both authorities existed only as CLI commands, which made them invisible: an
// operator could not see whether one existed, when it expires, or which key is
// signing today. That last is not a curiosity — a certificate authority whose
// key expires unnoticed takes the fleet with it, and nothing was surfacing the
// date.
//
// The page's real job is the bundle. `cardinal x509 ca init` says it plainly:
// getting a root into every trust store is the part that takes the time, no
// amount of software does it for you, and an internal CA is worthless until it
// is done. Making the thing you have to distribute one click away is most of
// what a console can contribute to that.
//
// Rotation stays in the CLI. It is a three-step operation — publish, distribute,
// then activate — and the middle step happens outside Cardinal entirely, so a
// button would be the least important part of it and would invite skipping the
// part that matters.

type authorityKeyResponse struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`

	// State is one of signing, published or retired.
	//
	// Three states rather than a boolean because "published" is the one that
	// matters operationally: a key that exists, is trusted, and is not yet
	// signing is a rotation waiting for its distribution step to finish.
	State string `json:"state"`

	CreatedAt time.Time  `json:"createdAt"`
	ActiveAt  *time.Time `json:"activeAt"`
	RetiredAt *time.Time `json:"retiredAt"`
	ExpiresAt *time.Time `json:"expiresAt"`
	Subject   string     `json:"subject"`
}

func authorityState(active, retired *time.Time) string {
	switch {
	case retired != nil:
		return "retired"
	case active != nil:
		return "signing"
	default:
		return "published"
	}
}

// handleAuthorities describes both authorities and hands over their bundles.
//
// One endpoint rather than two because the page is one page: an operator asking
// "what does a machine have to trust" wants both answers, and splitting them
// would mean a console that shows half the story while the other half loads.
func (s *Server) handleAuthorities(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	out := map[string]any{
		"ssh":  s.sshAuthority(ctx, w),
		"x509": s.x509Authority(ctx, w),
	}
	if out["ssh"] == nil || out["x509"] == nil {
		// sshAuthority/x509Authority already wrote the error.
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) sshAuthority(ctx context.Context, w http.ResponseWriter) map[string]any {
	keys, err := s.store.TrustedSSHCAKeys(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing SSH authority keys failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the authorities")
		return nil
	}

	described := make([]authorityKeyResponse, 0, len(keys))
	var bundle strings.Builder
	for _, k := range keys {
		described = append(described, authorityKeyResponse{
			ID: k.ID.String(), Fingerprint: k.Fingerprint, Algorithm: k.Algorithm,
			State:     authorityState(k.ActiveAt, k.RetiredAt),
			CreatedAt: k.CreatedAt, ActiveAt: k.ActiveAt, RetiredAt: k.RetiredAt,
			ExpiresAt: k.ValidUntil,
		})
		// Every trusted key, signing or not. A host trusting only the signing
		// key rejects every certificate issued in the minutes before a
		// rotation, which is the whole reason a key is published before it
		// signs.
		bundle.WriteString(k.PublicKey)
	}

	return map[string]any{
		"enabled": s.sshCA != nil,
		"keys":    described,
		"bundle":  bundle.String(),
	}
}

func (s *Server) x509Authority(ctx context.Context, w http.ResponseWriter) map[string]any {
	keys, err := s.store.TrustedX509CAKeys(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing X.509 authority keys failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the authorities")
		return nil
	}

	described := make([]authorityKeyResponse, 0, len(keys))
	var bundle strings.Builder
	for _, k := range keys {
		expires := k.NotAfter
		described = append(described, authorityKeyResponse{
			ID: k.ID.String(), Fingerprint: k.Fingerprint, Algorithm: k.Algorithm,
			Subject:   k.Subject,
			State:     authorityState(k.ActiveAt, k.RetiredAt),
			CreatedAt: k.NotBefore, ActiveAt: k.ActiveAt, RetiredAt: k.RetiredAt,
			ExpiresAt: &expires,
		})
		if err := pem.Encode(&bundle, &pem.Block{
			Type: "CERTIFICATE", Bytes: k.Certificate.Raw,
		}); err != nil {
			s.log.ErrorContext(ctx, "encoding the trust bundle failed", "error", err)
			writeError(w, http.StatusInternalServerError, "could not build the bundle")
			return nil
		}
	}

	return map[string]any{
		"enabled": s.x509CA != nil,
		"keys":    described,
		"bundle":  bundle.String(),
	}
}

// sshTrustBundle is every trusted SSH authority key, in TrustedUserCAKeys form.
//
// Extracted so the routes that create and rotate a key can return it. Whoever
// just made a key sign is the person who has to distribute the trust, and
// making them fetch it from a second endpoint is how a fleet ends up rotated
// but not trusted.
func (s *Server) sshTrustBundle(ctx context.Context) (string, error) {
	keys, err := s.store.TrustedSSHCAKeys(ctx)
	if err != nil {
		return "", err
	}
	var bundle strings.Builder
	for _, k := range keys {
		bundle.WriteString(k.PublicKey)
	}
	return bundle.String(), nil
}

// x509TrustBundle is every trusted X.509 authority certificate, PEM encoded.
func (s *Server) x509TrustBundle(ctx context.Context) (string, error) {
	keys, err := s.store.TrustedX509CAKeys(ctx)
	if err != nil {
		return "", err
	}
	var bundle strings.Builder
	for _, k := range keys {
		if err := pem.Encode(&bundle, &pem.Block{
			Type: "CERTIFICATE", Bytes: k.Certificate.Raw,
		}); err != nil {
			return "", err
		}
	}
	return bundle.String(), nil
}
