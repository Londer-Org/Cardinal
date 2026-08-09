package ssf_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/server/ssf"
)

func transmitter(t *testing.T) (ssf.Transmitter, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return ssf.Transmitter{
		Issuer: "https://id.example.com",
		Key:    key,
		KeyID:  "test-key",
	}, &key.PublicKey
}

// verify parses a SET the way a receiver would, and returns its claims.
//
// Through a real JOSE library rather than by splitting on dots, because the
// claim being tested is that somebody else's verifier accepts this — and a
// hand-rolled parser here would only prove Cardinal agrees with itself.
func verify(t *testing.T, token string, public *rsa.PublicKey) map[string]any {
	t.Helper()

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err, "a receiver could not parse this as a signed JWT")

	var claims map[string]any
	require.NoError(t, parsed.Claims(public, &claims),
		"the signature did not verify against the published key")
	return claims
}

// TestASessionRevocationIsATokenAReceiverCanRead.
//
// The event the whole thing exists for. Everything asserted here is something a
// receiver switches on: the type URI, who it is about, and when it happened.
func TestASessionRevocationIsATokenAReceiverCanRead(t *testing.T) {
	tx, public := transmitter(t)
	subject := uuid.New()
	when := time.Now().Add(-30 * time.Second).Truncate(time.Second)

	token, err := tx.Sign(ssf.Event{
		Type:      ssf.EventSessionRevoked,
		SubjectID: subject,
		Reason:    "an administrator revoked this",
		At:        when,
	}, "client-abc")
	require.NoError(t, err)

	claims := verify(t, token, public)
	assert.Equal(t, "https://id.example.com", claims["iss"])
	assert.Equal(t, "client-abc", claims["aud"],
		"a token with the wrong audience is one a receiver can replay elsewhere")

	events, ok := claims["events"].(map[string]any)
	require.True(t, ok, "no events claim: %v", claims)

	detail, ok := events[ssf.EventSessionRevoked].(map[string]any)
	require.True(t, ok, "the event is not keyed by its type URI: %v", events)

	// When access changed, not when the token was made. A receiver deciding how
	// to treat a five-minute-old revocation needs this to be the truth rather
	// than the moment a retry happened to succeed.
	assert.EqualValues(t, when.Unix(), detail["event_timestamp"])

	identifier, ok := detail["subject"].(map[string]any)
	require.True(t, ok, "no subject: %v", detail)
	assert.Equal(t, "iss_sub", identifier["format"])
	assert.Equal(t, subject.String(), identifier["sub"],
		"the subject must be the same identifier the receiver has in its ID token")
}

// TestTheTypeHeaderIsSecevent.
//
// RFC 8417 requires typ: secevent+jwt, and a strict receiver checks it. Getting
// it wrong produces a token that verifies and is then rejected for a reason
// nobody reads carefully.
func TestTheTypeHeaderIsSecevent(t *testing.T) {
	tx, _ := transmitter(t)

	token, err := tx.Sign(ssf.Event{
		Type: ssf.EventSessionRevoked, SubjectID: uuid.New(),
	}, "client-abc")
	require.NoError(t, err)

	parsed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Len(t, parsed.Signatures, 1)

	header := parsed.Signatures[0].Header
	assert.Equal(t, "secevent+jwt", header.ExtraHeaders[jose.HeaderType])
	assert.Equal(t, "test-key", header.KeyID,
		"without a kid a receiver cannot pick the right key out of the JWKS")
}

// TestEveryTokenIsUnique: jti is what lets a receiver discard a duplicate, and
// delivery retries mean duplicates happen.
func TestEveryTokenIsUnique(t *testing.T) {
	tx, public := transmitter(t)
	seen := map[string]bool{}

	for range 5 {
		token, err := tx.Sign(ssf.Event{
			Type: ssf.EventSessionRevoked, SubjectID: uuid.New(),
		}, "client-abc")
		require.NoError(t, err)

		jti, _ := verify(t, token, public)["jti"].(string) //nolint:errcheck // a missing jti is the assertion below
		require.NotEmpty(t, jti, "no jti, so a receiver cannot discard a repeat")
		assert.False(t, seen[jti], "two tokens share a jti")
		seen[jti] = true
	}
}

// TestSigningWithoutAKeyIsRefused.
//
// Rather than producing something unsigned. A transmitter with no key is a
// deployment with the OIDC provider switched off, and an unsigned security
// event is worse than none: a receiver that accepted one would accept anybody's.
func TestSigningWithoutAKeyIsRefused(t *testing.T) {
	_, err := ssf.Transmitter{Issuer: "https://id.example.com"}.
		Sign(ssf.Event{Type: ssf.EventSessionRevoked}, "client-abc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no signing key")
}

// TestVerificationCarriesNoSubject: it is about the stream, and putting a
// person in it would tell a receiver about somebody for no reason.
func TestVerificationCarriesNoSubject(t *testing.T) {
	tx, public := transmitter(t)

	token, err := tx.Sign(ssf.Event{Type: ssf.EventVerification}, "client-abc")
	require.NoError(t, err)

	events, ok := verify(t, token, public)["events"].(map[string]any)
	require.True(t, ok)
	detail, ok := events[ssf.EventVerification].(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, detail, "subject")
}

// TestTheConfigurationSaysWhatIsNotImplemented.
//
// A receiver author reading this document is exactly the person who needs to
// know which half exists. Discovering that stream management is absent from a
// 404 during a deprovisioning is the alternative.
func TestTheConfigurationSaysWhatIsNotImplemented(t *testing.T) {
	raw, err := ssf.Configuration{
		Issuer:                   "https://id.example.com",
		JWKSURI:                  "https://id.example.com/oidc/keys",
		DeliveryMethodsSupported: []string{ssf.DeliveryPush},
		SpecVersion:              "1_0-ID2",
		Note:                     "Streams are configured by a Cardinal administrator.",
	}.MarshalIndent()
	require.NoError(t, err)

	var document map[string]any
	require.NoError(t, json.Unmarshal(raw, &document))
	assert.Contains(t, document, "cardinal_note")
	assert.Equal(t, []any{ssf.DeliveryPush}, document["delivery_methods_supported"])
}
