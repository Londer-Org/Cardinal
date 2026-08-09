// Package ssf builds the Security Event Tokens Cardinal transmits.
//
// Revoking a session in Cardinal ends it in Cardinal. An application that
// issued its own session from an OIDC login learns nothing until its token
// expires — fifteen minutes at best, a refresh cycle at worst — so "signed out
// everywhere" was true here and not true of the things Cardinal signed you
// into. For a compromised account that gap is the whole incident.
//
// The Shared Signals Framework closes it by pushing a signed statement of what
// happened. This package is the token: CAEP names the events, RFC 8417 is the
// envelope, RFC 9493 is how a subject is identified. Delivery and storage live
// elsewhere, so what is transmitted can be tested without a network.
package ssf

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// CAEP event types, as their URIs. The URI is the identifier — a receiver
// switches on it — so these are the contract rather than the names beside them.
const (
	// EventSessionRevoked says a session has ended before its natural expiry.
	// The event that closes the gap this package exists for.
	EventSessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

	// EventCredentialChange says a credential was added or removed. A receiver
	// enforcing its own step-up rules cares: the passkey it decided to trust
	// may no longer exist.
	EventCredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change" //nolint:gosec // G101: a CAEP event-type URI, not a credential

	// EventAssuranceLevelChange says how strongly somebody is authenticated has
	// changed. Emitted when an account is disabled, which is the strongest
	// possible reduction.
	EventAssuranceLevelChange = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"

	// EventVerification is the stream check RFC 8935 defines, so an operator
	// can prove delivery works without waiting for somebody to be compromised.
	EventVerification = "https://schemas.openid.net/secevent/ssf/event-type/verification"
)

// AllEvents is what a stream may subscribe to.
var AllEvents = []string{
	EventSessionRevoked, EventCredentialChange, EventAssuranceLevelChange,
	EventVerification,
}

// Valid reports whether an event type is one Cardinal transmits.
func Valid(eventType string) bool {
	for _, e := range AllEvents {
		if e == eventType {
			return true
		}
	}
	return false
}

// Event is what happened, before it becomes a token.
type Event struct {
	Type string

	// Subject is who it is about. Zero for a stream-level event.
	SubjectID uuid.UUID

	// Reason is free text for a human reading a receiver's log. Deliberately
	// coarse — "an administrator revoked this" rather than which administrator
	// — because this crosses a trust boundary into somebody else's system, and
	// a directory should not narrate its internals to every application it
	// talks to.
	Reason string

	// At is when access actually changed, not when this is delivered.
	At time.Time
}

// Transmitter signs events for one issuer.
type Transmitter struct {
	// Issuer is Cardinal's public URL, matching the OIDC issuer exactly. A
	// receiver checks it against the one it discovered, and a value that
	// differs by a trailing slash is a token nobody accepts.
	Issuer string

	// Key signs. The OIDC signing key, deliberately: a receiver verifies
	// against the JWKS it already fetches for tokens, so this needs no key
	// distribution of its own and rotates with the one that already rotates.
	Key   *rsa.PrivateKey
	KeyID string
}

// setKey accepts the signing key as the store hands it over.
//
// Typed as any at the boundary so this package does not depend on how keys are
// stored, and checked here so a wrong type is one error at emission rather than
// a panic inside the signer.
func (t *Transmitter) setKey(key any) error {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("ssf: signing needs an RSA key, got %T", key)
	}
	t.Key = rsaKey
	return nil
}

// Sign builds a Security Event Token for one receiver.
//
// The audience is the receiver's client id. One event going to three receivers
// is three tokens, each with its own audience, because a token a receiver can
// replay to another receiver is a token that says nothing about who was meant
// to have it.
func (t Transmitter) Sign(e Event, audience string) (string, error) {
	if t.Key == nil {
		return "", errors.New("ssf: no signing key, so nothing can be transmitted")
	}

	at := e.At
	if at.IsZero() {
		at = time.Now()
	}

	// The subject identifier format from RFC 9493. iss_sub rather than email:
	// an email is mutable and belongs to a person, the pair here is the same
	// identifier the receiver already has in the `sub` of its ID token.
	subject := map[string]any{
		"format": "iss_sub",
		"iss":    t.Issuer,
		"sub":    e.SubjectID.String(),
	}

	detail := map[string]any{
		// Seconds, per CAEP. Named event_timestamp rather than reusing iat
		// because they answer different questions: when it happened, and when
		// this token was made.
		"event_timestamp": at.Unix(),
	}
	if e.Reason != "" {
		detail["reason_admin"] = map[string]any{"en": e.Reason}
	}
	if e.Type != EventVerification {
		detail["subject"] = subject
	}

	claims := map[string]any{
		"iss": t.Issuer,
		"aud": audience,
		"iat": at.Unix(),
		"jti": uuid.New().String(),
		"events": map[string]any{
			e.Type: detail,
		},
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: t.Key},
		(&jose.SignerOptions{}).
			WithType("secevent+jwt").
			WithHeader(jose.HeaderKey("kid"), t.KeyID),
	)
	if err != nil {
		return "", fmt.Errorf("ssf: building the signer: %w", err)
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("ssf: signing the event: %w", err)
	}
	return token, nil
}

// Configuration is the document a receiver fetches to learn what this
// transmitter does.
//
// The honest part is delivery_methods_supported and the note beside it. Stream
// management over the API is not implemented — streams are configured by a
// Cardinal administrator — and a receiver that expects to create its own finds
// that out here rather than from a 404 while somebody is being deprovisioned.
type Configuration struct {
	Issuer                   string   `json:"issuer"`
	JWKSURI                  string   `json:"jwks_uri"`
	DeliveryMethodsSupported []string `json:"delivery_methods_supported"`
	ConfigurationEndpoint    string   `json:"configuration_endpoint,omitempty"`
	StatusEndpoint           string   `json:"status_endpoint,omitempty"`
	SpecVersion              string   `json:"spec_version"`
	CriticalSubjectMembers   []string `json:"critical_subject_members,omitempty"`

	// Note is not part of the specification and is here on purpose. A receiver
	// author reading this document is exactly the person who needs to know
	// which half is implemented.
	Note string `json:"cardinal_note"`
}

// DeliveryPush is RFC 8935.
const DeliveryPush = "https://schemas.openid.net/secevent/risc/delivery-method/push"

// MarshalIndent renders the configuration document.
func (c Configuration) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}
