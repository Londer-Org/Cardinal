// Package auth orchestrates authentication ceremonies.
//
// Cardinal has no passwords. A passkey is the primary credential, and the
// properties that matter follow from that: it is origin-bound, so a convincing
// lookalike site cannot harvest a usable credential, and the server stores only
// a public key, so a database dump yields nothing that can authenticate.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/config"
	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// CeremonyTTL bounds how long a challenge may sit unanswered.
//
// Generous enough for someone to find a security key in a drawer, short enough
// that a challenge captured from a browser's network tab is stale before it is
// useful.
const CeremonyTTL = 5 * time.Minute

// SessionTTL is how long an ordinary authenticated session lasts.
//
// Policy can still demand a *fresh* authentication for privileged actions via
// Cedar (step-up), so this being a working day does not mean administrative
// actions go unchallenged for a working day.
const SessionTTL = 12 * time.Hour

var (
	ErrCeremonyNotFound = errors.New("auth: ceremony not found or expired")
	ErrCeremonyConsumed = errors.New("auth: ceremony already completed")
	ErrUnknownUser      = errors.New("auth: unknown user")
	ErrNotEnrolled      = errors.New("auth: no credentials registered")
)

// Service performs registration and authentication ceremonies.
type Service struct {
	store *store.Store
	wa    *webauthn.WebAuthn
	cfg   *config.Config
}

// NewService builds the ceremony service from validated configuration.
func NewService(s *store.Store, cfg *config.Config) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.WebAuthn.RPID,
		RPDisplayName: cfg.WebAuthn.RPDisplayName,
		RPOrigins:     cfg.WebAuthn.Origins,

		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// Required, not preferred: user verification means the
			// authenticator checked a PIN or biometric, so possession of the
			// device alone is not enough. Without it a stolen unlocked laptop
			// authenticates silently.
			UserVerification: protocol.VerificationRequired,

			// Resident keys enable usernameless login — the user picks an
			// account from the authenticator rather than typing one. That also
			// removes the username-enumeration surface entirely.
			ResidentKey:        protocol.ResidentKeyRequirementPreferred,
			RequireResidentKey: protocol.ResidentKeyNotRequired(),
		},

		// Attestation "none" is the correct default (per FIDO guidance): asking
		// for attestation on every registration collects hardware identifiers
		// for no benefit. Enterprise attestation is worth requiring for admin
		// roles specifically, and that belongs in policy rather than here.
		AttestationPreference: protocol.PreferNoAttestation,

		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{
				Enforce: true, Timeout: CeremonyTTL,
			},
			Login: webauthn.TimeoutConfig{
				Enforce: true, Timeout: CeremonyTTL,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("auth: configuring webauthn: %w", err)
	}
	return &Service{store: s, wa: wa, cfg: cfg}, nil
}

// user adapts a directory entity to the WebAuthn library's User interface.
type user struct {
	entity *directory.Entity
	creds  []webauthn.Credential
}

// WebAuthnID returns the stable identifier bound into every credential.
//
// The entity's UUID, which never changes and is never reused, is exactly the
// right thing here: the spec requires authorization decisions be made on this
// value rather than on a name. Using a username would reintroduce the
// LDAP problem of an identifier that changes when a person is renamed.
func (u *user) WebAuthnID() []byte { return u.entity.ID[:] }

func (u *user) WebAuthnName() string { return u.entity.Name }

func (u *user) WebAuthnDisplayName() string {
	if u.entity.DisplayName != "" {
		return u.entity.DisplayName
	}
	return u.entity.Name
}

func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Service) loadUser(ctx context.Context, entityID uuid.UUID) (*user, error) {
	e, err := s.store.GetEntity(ctx, entityID)
	if err != nil {
		return nil, err
	}
	if !e.Active() {
		return nil, fmt.Errorf("%w: account is disabled", ErrUnknownUser)
	}

	stored, err := s.store.CredentialsFor(ctx, entityID)
	if err != nil {
		return nil, err
	}

	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		wc := webauthn.Credential{ID: c.CredentialID, PublicKey: c.PublicKey}
		wc.Authenticator.SignCount = c.SignCount
		wc.Authenticator.AAGUID = c.AAGUID
		wc.Flags.BackupEligible = c.BackupEligible
		wc.Flags.BackupState = c.BackupState
		creds = append(creds, wc)
	}
	return &user{entity: e, creds: creds}, nil
}

// BeginRegistration starts enrolling a new passkey for an existing account.
func (s *Service) BeginRegistration(ctx context.Context, entityID uuid.UUID) (*protocol.CredentialCreation, uuid.UUID, error) {
	u, err := s.loadUser(ctx, entityID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	// Excluding existing credentials makes the authenticator refuse to enrol
	// twice, so a user cannot silently create a duplicate they will later be
	// confused by.
	exclusions := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.creds {
		exclusions = append(exclusions, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
		})
	}

	options, sessionData, err := s.wa.BeginRegistration(u,
		webauthn.WithExclusions(exclusions))
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("auth: beginning registration: %w", err)
	}

	id, err := s.saveCeremony(ctx, "registration", &entityID, sessionData)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return options, id, nil
}

// FinishRegistration verifies the authenticator's response and stores the
// credential.
func (s *Service) FinishRegistration(
	ctx context.Context, ceremonyID uuid.UUID,
	response *protocol.ParsedCredentialCreationData, name string,
) (*store.Credential, error) {
	sessionData, entityID, err := s.consumeCeremony(ctx, ceremonyID, "registration")
	if err != nil {
		return nil, err
	}
	if entityID == nil {
		return nil, ErrCeremonyNotFound
	}

	u, err := s.loadUser(ctx, *entityID)
	if err != nil {
		return nil, err
	}

	cred, err := s.wa.CreateCredential(u, *sessionData, response)
	if err != nil {
		return nil, fmt.Errorf("auth: verifying registration: %w", err)
	}

	return s.store.RegisterCredential(ctx, *entityID, cred, name)
}

// BeginLogin starts authenticating a known account.
func (s *Service) BeginLogin(ctx context.Context, entityID uuid.UUID) (*protocol.CredentialAssertion, uuid.UUID, error) {
	u, err := s.loadUser(ctx, entityID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	if len(u.creds) == 0 {
		return nil, uuid.Nil, ErrNotEnrolled
	}

	options, sessionData, err := s.wa.BeginLogin(u)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("auth: beginning login: %w", err)
	}

	id, err := s.saveCeremony(ctx, "authentication", &entityID, sessionData)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return options, id, nil
}

// BeginDiscoverableLogin starts a usernameless login.
//
// The user picks an account from their authenticator rather than typing one,
// which removes username enumeration as an attack surface: the server reveals
// nothing before the authenticator has already proven possession.
func (s *Service) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, uuid.UUID, error) {
	options, sessionData, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("auth: beginning discoverable login: %w", err)
	}

	id, err := s.saveCeremony(ctx, "authentication", nil, sessionData)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return options, id, nil
}

// FinishLogin verifies an assertion and opens a session.
func (s *Service) FinishLogin(
	ctx context.Context, ceremonyID uuid.UUID,
	response *protocol.ParsedCredentialAssertionData,
) (*store.Session, error) {
	sessionData, entityID, err := s.consumeCeremony(ctx, ceremonyID, "authentication")
	if err != nil {
		return nil, err
	}

	var (
		cred    *webauthn.Credential
		subject uuid.UUID
	)

	if entityID != nil {
		u, err := s.loadUser(ctx, *entityID)
		if err != nil {
			return nil, err
		}
		cred, err = s.wa.ValidateLogin(u, *sessionData, response)
		if err != nil {
			return nil, fmt.Errorf("auth: verifying login: %w", err)
		}
		subject = *entityID
	} else {
		// Discoverable login: the authenticator tells us which credential it
		// used, and the user handle identifies the account.
		cred, err = s.wa.ValidateDiscoverableLogin(
			func(rawID, userHandle []byte) (webauthn.User, error) {
				id, err := uuid.FromBytes(userHandle)
				if err != nil {
					return nil, fmt.Errorf("%w: malformed user handle", ErrUnknownUser)
				}
				subject = id
				return s.loadUser(ctx, id)
			}, *sessionData, response)
		if err != nil {
			return nil, fmt.Errorf("auth: verifying discoverable login: %w", err)
		}
	}

	// Clone detection. A regression here means two authenticators are
	// presenting the same credential, so the login is refused even though the
	// signature was valid.
	if err := s.store.UpdateSignCount(ctx, cred.ID, cred.Authenticator.SignCount); err != nil {
		return nil, err
	}

	stored, err := s.store.CredentialByID(ctx, cred.ID)
	if err != nil {
		return nil, err
	}

	return s.store.CreateSession(ctx, subject, store.SessionSpec{
		AuthMethod: "passkey",
		TTL:        SessionTTL,
		// A credential that cannot be backed up stays on its hardware, which is
		// what lets policy demand a device-bound factor for privileged actions.
		DeviceBound:  !stored.BackupEligible,
		CredentialID: &stored.ID,
	})
}

func (s *Service) saveCeremony(ctx context.Context, kind string, entityID *uuid.UUID, data *webauthn.SessionData) (uuid.UUID, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return uuid.Nil, fmt.Errorf("auth: encoding ceremony: %w", err)
	}
	return s.store.SaveCeremony(ctx, kind, entityID, encoded,
		time.Now().Add(CeremonyTTL))
}

func (s *Service) consumeCeremony(ctx context.Context, id uuid.UUID, kind string) (*webauthn.SessionData, *uuid.UUID, error) {
	raw, entityID, err := s.store.ConsumeCeremony(ctx, id, kind)
	if err != nil {
		return nil, nil, err
	}
	var data webauthn.SessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, nil, fmt.Errorf("auth: decoding ceremony: %w", err)
	}
	return &data, entityID, nil
}
