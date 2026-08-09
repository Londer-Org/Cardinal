package auth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/config"
	"go.londer.be/cardinal/internal/server/auth"
)

// The ceremonies in this package need a database and a browser, and the
// end-to-end suite drives both. What can be checked here without either is the
// step before them: that a misconfigured relying party is refused at
// construction rather than at somebody's first sign-in.

func webAuthnConfig(rpID string, origins ...string) *config.Config {
	cfg := &config.Config{}
	cfg.WebAuthn.RPID = rpID
	cfg.WebAuthn.RPDisplayName = "Cardinal"
	cfg.WebAuthn.Origins = origins
	return cfg
}

func TestNewServiceRefusesARelyingPartyWithNoOrigin(t *testing.T) {
	t.Parallel()

	_, err := auth.NewService(nil, webAuthnConfig("id.cardinal.test"))
	require.Error(t, err,
		"an assertion is checked against the permitted origins, so a service "+
			"with none could never accept one")
	assert.Contains(t, err.Error(), "RPOrigins")
}

// TestNewServiceToleratesAnEmptyRPIDBecauseConfigDoesNot records where the
// check actually lives.
//
// Measured, not assumed: go-webauthn accepts an empty RPID and derives it from
// the origin. That would be a bad thing to rely on — the RPID is baked into
// every credential ever registered and cannot be changed afterwards without
// invalidating all of them — and Cardinal does not rely on it, because
// config.Validate refuses an empty rp_id before a Service is ever built.
//
// This test exists so that if that config rule is ever relaxed, the comment
// above stops being true somewhere visible.
func TestNewServiceToleratesAnEmptyRPIDBecauseConfigDoesNot(t *testing.T) {
	t.Parallel()

	_, err := auth.NewService(nil, webAuthnConfig("", "https://id.cardinal.test"))
	assert.NoError(t, err, "the library does not enforce this")

	cfg := webAuthnConfig("", "https://id.cardinal.test")
	cfg.Server.PublicURL = "https://id.cardinal.test"
	cfg.Server.Listen = ":8080"
	require.Error(t, cfg.Validate(), "configuration is where an empty rp_id is refused")
}

func TestNewServiceAcceptsAWellFormedRelyingParty(t *testing.T) {
	t.Parallel()

	service, err := auth.NewService(nil, webAuthnConfig(
		"cardinal.test", "https://id.cardinal.test:8443"))
	require.NoError(t, err)
	assert.NotNil(t, service)
}

// TestCeremonyTTLIsShort: a ceremony is a window in which a challenge is
// outstanding, and the challenge is what makes an assertion unrepeatable.
func TestCeremonyTTLIsShort(t *testing.T) {
	t.Parallel()

	assert.Positive(t, auth.CeremonyTTL)
	assert.LessOrEqual(t, auth.CeremonyTTL.Minutes(), 15.0,
		"long enough to find a security key, short enough that an abandoned "+
			"challenge is not left outstanding")
}
