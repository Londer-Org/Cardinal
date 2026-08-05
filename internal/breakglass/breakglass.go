// Package breakglass implements Cardinal's emergency access mechanism.
//
// Break-glass answers one question: how do you regain administrative control
// when the normal authentication path is unavailable, or is no longer trusted?
//
// The root of trust is an Ed25519 keypair generated offline. The private key
// never exists on the server. Cardinal holds only the public key, and holds it
// in its *configuration file* rather than the database. That placement is the
// whole design:
//
//   - a database compromise cannot substitute an attacker's key
//   - a database restore cannot silently roll the key back to an older value
//   - verification does not depend on directory state being readable
//
// See docs/adr/0009-recovery-and-break-glass.md.
package breakglass

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SessionTTL bounds an emergency session.
//
// Short by intent: break-glass exists to restore normal access, not to be
// worked in. Anyone still needing it after fifteen minutes should re-authorise
// deliberately rather than drift into using it as an administrative account.
const SessionTTL = 15 * time.Minute

// ChallengeTTL bounds how long a challenge may be signed.
//
// Long enough to fetch a key from a safe, short enough that a challenge
// captured from a terminal or log is worthless by the time it is found.
const ChallengeTTL = 5 * time.Minute

// challengeSize is 32 bytes of entropy — far beyond what is needed to prevent
// collision or prediction, and free.
const challengeSize = 32

var (
	ErrNotConfigured    = errors.New("breakglass: no break-glass key is configured")
	ErrInvalidSignature = errors.New("breakglass: signature does not verify")
	ErrChallengeExpired = errors.New("breakglass: challenge has expired")
	ErrMalformedKey     = errors.New("breakglass: malformed public key")
)

// KeyPair is a freshly generated break-glass identity.
//
// It exists only in memory during the bootstrap ceremony: the private half is
// displayed once for offline storage and is deliberately never persisted by
// Cardinal.
type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// Generate creates a new break-glass keypair.
func Generate() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("breakglass: generating key: %w", err)
	}
	return &KeyPair{Public: pub, Private: priv}, nil
}

// EncodePublic renders a public key for the configuration file.
func EncodePublic(pub ed25519.PublicKey) string {
	return "cardinal-bg-v1:" + base64.StdEncoding.EncodeToString(pub)
}

// EncodePrivate renders a private key for offline storage.
//
// The prefix makes the string greppable in secret scanners: if this ever
// appears in a repository, a backup, or a chat message, it should be found
// immediately and the key rotated.
func EncodePrivate(priv ed25519.PrivateKey) string {
	return "cardinal-bg-priv-v1:" + base64.StdEncoding.EncodeToString(priv)
}

// DecodePublic parses a configured public key.
func DecodePublic(s string) (ed25519.PublicKey, error) {
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), "cardinal-bg-v1:")
	if !ok {
		return nil, fmt.Errorf("%w: expected a cardinal-bg-v1: prefix", ErrMalformedKey)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedKey, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d",
			ErrMalformedKey, ed25519.PublicKeySize, len(b))
	}
	return b, nil
}

// DecodePrivate parses an offline private key.
func DecodePrivate(s string) (ed25519.PrivateKey, error) {
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), "cardinal-bg-priv-v1:")
	if !ok {
		return nil, fmt.Errorf("%w: expected a cardinal-bg-priv-v1: prefix", ErrMalformedKey)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedKey, err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d",
			ErrMalformedKey, ed25519.PrivateKeySize, len(b))
	}
	return b, nil
}

// Challenge is a server-issued nonce awaiting signature.
//
// Challenge-response rather than a bare secret: the private key is never
// transmitted, so it cannot be captured in transit, in a log, or by whoever is
// standing behind the operator during an incident.
type Challenge struct {
	Nonce     []byte
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// NewChallenge issues a challenge valid for ChallengeTTL.
func NewChallenge() (*Challenge, error) {
	nonce := make([]byte, challengeSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("breakglass: generating challenge: %w", err)
	}
	now := time.Now().UTC()
	return &Challenge{
		Nonce:     nonce,
		IssuedAt:  now,
		ExpiresAt: now.Add(ChallengeTTL),
	}, nil
}

// Encode renders a challenge for display to the operator.
func (c *Challenge) Encode() string {
	return base64.StdEncoding.EncodeToString(c.Nonce)
}

// signingPayload is what actually gets signed.
//
// The domain-separation prefix means a signature produced for break-glass can
// never be replayed as a signature for some other Cardinal protocol that also
// uses Ed25519 — SSH certificate issuance, for instance. Reusing a key across
// protocols without domain separation is a well-worn way to turn two safe
// designs into one unsafe one.
func (c *Challenge) signingPayload() []byte {
	return append([]byte("cardinal-break-glass-v1:"), c.Nonce...)
}

// Sign produces a signature over the challenge. Runs on the operator's machine,
// not the server.
func (c *Challenge) Sign(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c.signingPayload()))
}

// Verify checks a signature against the configured public key.
//
// Expiry is checked first: an expired challenge is rejected regardless of
// whether the signature is valid, so a captured challenge cannot be used later
// by someone who obtains the key.
func (c *Challenge) Verify(pub ed25519.PublicKey, signature string) error {
	if time.Now().UTC().After(c.ExpiresAt) {
		return fmt.Errorf("%w: issued at %s, valid for %s",
			ErrChallengeExpired, c.IssuedAt.Format(time.RFC3339), ChallengeTTL)
	}

	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return fmt.Errorf("%w: not valid base64: %w", ErrInvalidSignature, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return ErrNotConfigured
	}
	// ed25519.Verify is constant-time with respect to the signature.
	if !ed25519.Verify(pub, c.signingPayload(), sig) {
		return ErrInvalidSignature
	}
	return nil
}
