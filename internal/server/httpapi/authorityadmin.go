package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Creating an authority key, and choosing which one signs.
//
// The last of the operations that reached PostgreSQL and nothing else
// (ADR 0033). It is also the sharpest, so what these do *not* do is worth
// stating first.
//
// Creating a key changes nothing. A new authority is not signing until
// something activates it, and that order is deliberate: a CA nothing trusts,
// issuing certificates everything rejects, is a worse failure than not having
// one. So creation is the safe half and rotation is the half that needs a
// distributed trust store first — which Cardinal cannot verify and does not
// pretend to.
//
// Both are behind the broad tier and therefore behind the step-up forbid: a
// device-bound credential used in the last five minutes. Rotating the authority
// that signs every host login from a twelve-hour session on an unlocked laptop
// is exactly what that rule exists to refuse.

// defaultRotationGrace matches the CLI's flag.
//
// Forty-eight hours: long enough that a fleet picks up the new trust on an
// ordinary refresh cycle before the previous key stops being trusted, and short
// enough that a retired key does not linger for a week.
const defaultRotationGrace = 48 * time.Hour

// maxRotationGrace bounds what a caller can ask for.
//
// A grace period is how long a key nobody is signing with stays trusted, which
// is a window in which a stolen retired key still verifies. A month is already
// generous for a fleet that refreshes every few minutes.
const maxRotationGrace = 30 * 24 * time.Hour

type createAuthorityRequest struct {
	// Subject is the X.509 distinguished name. Ignored by the SSH authority,
	// which has no such concept.
	Subject string `json:"subject"`

	// Activate makes the new key sign immediately.
	//
	// Honest about what it costs: for the *first* authority this is what you
	// want, because nothing trusts anything yet. For a replacement it means the
	// new key starts signing before any trust store has been told about it, and
	// every verifier rejects what it produces until they are. The response says
	// which case happened rather than leaving it to be discovered.
	Activate bool `json:"activate"`
}

type createAuthorityResponse struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
	Active      bool   `json:"active"`

	// PublicKey is the SSH authority's public half, in authorized_keys form —
	// the line that has to reach every host's TrustedUserCAKeys.
	PublicKey string `json:"publicKey,omitempty"`

	// Subject and NotAfter describe an X.509 root.
	Subject  string     `json:"subject,omitempty"`
	NotAfter *time.Time `json:"notAfter,omitempty"`

	// Distribute is what has to be in a trust store before this key signs
	// anything. Returned on creation because that is the moment somebody can
	// act on it, and because an operator who has to go and fetch it separately
	// is one who rotates first and distributes afterwards.
	Distribute string `json:"distribute"`
}

func (s *Server) handleCreateSSHAuthority(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	if s.sshCA == nil {
		writeError(w, http.StatusConflict, "host access is not enabled in this deployment")
		return
	}

	var req createAuthorityRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	actorID := session.SubjectID
	key, err := s.store.CreateSSHCAKey(ctx, s.cfg.SSH.CAEncryptionKey, &actorID)
	if err != nil {
		s.log.ErrorContext(ctx, "creating an SSH authority key failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create the key")
		return
	}
	s.log.WarnContext(ctx, "SSH authority key created",
		"key", key.ID, "actor", session.SubjectID, "activate", req.Activate)

	out := createAuthorityResponse{
		ID: key.ID.String(), Fingerprint: key.Fingerprint,
		Algorithm: key.Algorithm, PublicKey: key.PublicKey,
	}

	if req.Activate {
		if err := s.store.ActivateSSHCAKey(ctx, key.ID, defaultRotationGrace, &actorID); err != nil {
			// Created and not activated. Said precisely, because retrying the
			// whole request would create a second key rather than activating
			// this one.
			s.log.ErrorContext(ctx, "activating a new SSH authority key failed", "error", err)
			writeError(w, http.StatusInternalServerError,
				"the key was created but not activated; rotate to "+key.ID.String()+" directly")
			return
		}
		out.Active = true
		s.log.WarnContext(ctx, "SSH authority key activated on creation",
			"key", key.ID, "actor", session.SubjectID)
	}

	if bundle, err := s.sshTrustBundle(ctx); err == nil {
		out.Distribute = bundle
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleCreateX509Authority(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	if s.x509CA == nil {
		writeError(w, http.StatusConflict, "ACME is not enabled in this deployment")
		return
	}

	var req createAuthorityRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Subject == "" {
		writeError(w, http.StatusBadRequest,
			"a subject is required — it is what every certificate this authority "+
				"issues will name as its issuer")
		return
	}

	actorID := session.SubjectID
	key, err := s.store.CreateX509CAKey(ctx, s.cfg.X509.CAEncryptionKey, req.Subject, 0, &actorID)
	if err != nil {
		s.log.ErrorContext(ctx, "creating an X.509 authority key failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create the authority")
		return
	}
	s.log.WarnContext(ctx, "X.509 authority created",
		"key", key.ID, "subject", req.Subject, "actor", session.SubjectID,
		"activate", req.Activate)

	notAfter := key.NotAfter
	out := createAuthorityResponse{
		ID: key.ID.String(), Fingerprint: key.Fingerprint,
		Algorithm: key.Algorithm, Subject: key.Subject, NotAfter: &notAfter,
	}

	if req.Activate {
		if err := s.store.ActivateX509CAKey(ctx, key.ID, &actorID); err != nil {
			s.log.ErrorContext(ctx, "activating a new X.509 authority failed", "error", err)
			writeError(w, http.StatusInternalServerError,
				"the authority was created but not activated; rotate to "+
					key.ID.String()+" directly")
			return
		}
		out.Active = true
		s.log.WarnContext(ctx, "X.509 authority activated on creation",
			"key", key.ID, "actor", session.SubjectID)
	}

	if bundle, err := s.x509TrustBundle(ctx); err == nil {
		out.Distribute = bundle
	}
	writeJSON(w, http.StatusCreated, out)
}

type rotateRequest struct {
	// Grace is how long the previous key stays trusted after it stops signing,
	// as a Go duration. SSH only: an X.509 root's replacement is bounded by the
	// certificates it already issued, which carry their own expiry.
	Grace string `json:"grace"`
}

func (s *Server) handleRotateSSHAuthority(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	if s.sshCA == nil {
		writeError(w, http.StatusConflict, "host access is not enabled in this deployment")
		return
	}

	keyID, err := uuid.Parse(r.PathValue("key"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such key")
		return
	}

	var req rotateRequest
	if decodeErr := decodeJSON(r, &req); decodeErr != nil {
		writeError(w, http.StatusBadRequest, decodeErr.Error())
		return
	}

	grace := defaultRotationGrace
	if req.Grace != "" {
		parsed, parseErr := time.ParseDuration(req.Grace)
		if parseErr != nil {
			writeError(w, http.StatusBadRequest,
				"`grace` must be a duration, e.g. \"48h\"")
			return
		}
		if parsed < 0 || parsed > maxRotationGrace {
			writeError(w, http.StatusBadRequest,
				"`grace` must be between 0 and 720h — it is how long a key nobody "+
					"signs with stays trusted")
			return
		}
		grace = parsed
	}

	if err := s.requireKnownSSHKey(ctx, w, keyID); err != nil {
		return
	}

	actorID := session.SubjectID
	if err := s.store.ActivateSSHCAKey(ctx, keyID, grace, &actorID); err != nil {
		s.log.ErrorContext(ctx, "rotating the SSH authority failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not rotate to that key")
		return
	}
	// Warn rather than info: this changes what every host in the fleet will
	// accept, and it is the line somebody looks for afterwards.
	s.log.WarnContext(ctx, "SSH authority rotated",
		"key", keyID, "grace", grace.String(), "actor", session.SubjectID)

	bundle, _ := s.sshTrustBundle(ctx) //nolint:errcheck // reported as empty, and the rotation already happened
	writeJSON(w, http.StatusOK, map[string]any{
		"active":     keyID.String(),
		"grace":      grace.String(),
		"distribute": bundle,
	})
}

func (s *Server) handleRotateX509Authority(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	if s.x509CA == nil {
		writeError(w, http.StatusConflict, "ACME is not enabled in this deployment")
		return
	}

	keyID, err := uuid.Parse(r.PathValue("key"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such key")
		return
	}
	if err := s.requireKnownX509Key(ctx, w, keyID); err != nil {
		return
	}

	actorID := session.SubjectID
	if err := s.store.ActivateX509CAKey(ctx, keyID, &actorID); err != nil {
		s.log.ErrorContext(ctx, "rotating the X.509 authority failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not rotate to that authority")
		return
	}
	s.log.WarnContext(ctx, "X.509 authority rotated",
		"key", keyID, "actor", session.SubjectID)

	bundle, _ := s.x509TrustBundle(ctx) //nolint:errcheck // as above
	writeJSON(w, http.StatusOK, map[string]any{
		"active":     keyID.String(),
		"distribute": bundle,
	})
}

// requireKnownSSHKey turns an unknown identifier into a 404.
//
// It is not what protects the fleet, and it would be comfortable to claim it
// was: the store retires the current key and activates the target in one
// transaction, so an unknown id rolls both back and nothing changes. Measured
// by removing this check — the rotation was refused, the signing key was
// unchanged, and the caller got a 500.
//
// What this adds is that the caller is told which of their two identifiers was
// wrong, instead of reading an internal error and guessing.
func (s *Server) requireKnownSSHKey(ctx context.Context, w http.ResponseWriter, keyID uuid.UUID) error {
	keys, err := s.store.TrustedSSHCAKeys(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing SSH authority keys failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the authorities")
		return err
	}
	for _, k := range keys {
		if k.ID == keyID {
			return nil
		}
	}
	writeError(w, http.StatusNotFound, "no such key")
	return errors.New("unknown key")
}

// requireKnownX509Key is requireKnownSSHKey for the other authority, with the
// same standing: the transaction is the safety, this is the message.
func (s *Server) requireKnownX509Key(ctx context.Context, w http.ResponseWriter, keyID uuid.UUID) error {
	keys, err := s.store.TrustedX509CAKeys(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing X.509 authority keys failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the authorities")
		return err
	}
	for _, k := range keys {
		if k.ID == keyID {
			return nil
		}
	}
	writeError(w, http.StatusNotFound, "no such authority")
	return errors.New("unknown key")
}
