package store_test

import (
	"testing"

	"github.com/arthur-lonfils/cardinal/internal/config"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedirectURIValidation.
//
// Redirect URIs are the most abused part of OAuth: an attacker who can get an
// authorization code delivered to a URI they control has the account. Every
// case here is a real technique, not a hypothetical.
func TestRedirectURIValidation(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	cases := []struct {
		name     string
		uri      string
		devMode  bool
		accepted bool
		because  string
	}{
		{
			name: "https is fine", uri: "https://app.example.com/callback",
			accepted: true,
		},
		{
			name: "wildcard is refused", uri: "https://*.example.com/callback",
			accepted: false,
			because:  "anyone controlling a matching host could receive authorization codes",
		},
		{
			name: "fragment is refused", uri: "https://app.example.com/cb#token",
			accepted: false,
			because:  "fragments are never sent to the server, so this author has misunderstood the flow",
		},
		{
			name: "plain http is refused", uri: "http://app.example.com/callback",
			accepted: false,
			because:  "an authorization code would cross the network in the clear",
		},
		{
			name: "http on loopback is permitted", uri: "http://127.0.0.1:1234/callback",
			accepted: true,
			because:  "RFC 8252 requires it for native apps, and the port varies per launch",
		},
		{
			name: "http on localhost is permitted", uri: "http://localhost:8080/callback",
			accepted: true,
		},
		{
			name: "plain http with dev_mode is permitted", uri: "http://app.internal/cb",
			devMode: true, accepted: true,
			because: "an explicit, visible opt-out rather than a silent default",
		},
		{
			name: "no scheme is refused", uri: "app.example.com/callback",
			accepted: false,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.RegisterOIDCClient(ctx, store.RegisterClientInput{
				// Unique name per case; entity names are unique per type.
				Name:         "client-" + string(rune('a'+i)),
				AuthMethod:   store.AuthNone,
				RedirectURIs: []string{tc.uri},
				DevMode:      tc.devMode,
			}, nil, nil)

			if tc.accepted {
				require.NoError(t, err, tc.because)
				return
			}
			require.ErrorIs(t, err, store.ErrInsecureRedirect, tc.because)
		})
	}
}

// TestCircularRecoveryDependencyRefusedAtRegistration.
//
// ADR 0009's governing rule, finally enforced where it bites: a recovery
// channel must not depend on the system being recovered. Registering the
// recovery-email domain as a relying party would mean a Cardinal outage takes
// the recovery channel with it — and that change is normally made for entirely
// unrelated reasons, by someone not thinking about account recovery.
func TestCircularRecoveryDependencyRefusedAtRegistration(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	cfg := &config.Config{
		Recovery: config.Recovery{
			EmailEnabled: true,
			EmailDomains: []string{"example.com"},
		},
	}

	_, err := s.RegisterOIDCClient(ctx, store.RegisterClientInput{
		Name:         "company-mail",
		AuthMethod:   store.AuthNone,
		RedirectURIs: []string{"https://mail.example.com/oidc/callback"},
	}, cfg.CheckRelyingPartyDomain, nil)

	require.ErrorIs(t, err, config.ErrCircularRecovery,
		"Cardinal must refuse to be the identity provider for a domain it "+
			"also trusts to recover accounts")

	t.Run("an unrelated domain registers fine", func(t *testing.T) {
		_, err := s.RegisterOIDCClient(ctx, store.RegisterClientInput{
			Name:         "grafana",
			AuthMethod:   store.AuthNone,
			RedirectURIs: []string{"https://grafana.internal/oidc/callback"},
		}, cfg.CheckRelyingPartyDomain, nil)
		require.NoError(t, err)
	})
}

// TestPublicClientsHaveNoSecret: a public client cannot keep a secret, so
// issuing one would be theatre. PKCE is what protects it instead.
func TestPublicClientsHaveNoSecret(t *testing.T) {
	s := newStore(t)

	registered, err := s.RegisterOIDCClient(t.Context(), store.RegisterClientInput{
		Name:         "single-page-app",
		AuthMethod:   store.AuthNone,
		RedirectURIs: []string{"https://spa.example.com/callback"},
	}, nil, nil)
	require.NoError(t, err)

	assert.Empty(t, registered.Secret)
	assert.True(t, registered.Client.Public())
	assert.True(t, registered.Client.RequirePKCE,
		"PKCE is what protects a client that cannot hold a secret")
}

// TestConfidentialClientSecretIsShownOnceAndHashed.
func TestConfidentialClientSecretIsShownOnceAndHashed(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	registered, err := s.RegisterOIDCClient(ctx, store.RegisterClientInput{
		Name:         "backend-service",
		AuthMethod:   store.AuthClientSecretBasic,
		RedirectURIs: []string{"https://svc.example.com/callback"},
	}, nil, nil)
	require.NoError(t, err)
	require.NotEmpty(t, registered.Secret)

	clientID := registered.Client.ClientID

	require.NoError(t, s.VerifyClientSecret(ctx, clientID, registered.Secret))
	require.ErrorIs(t, s.VerifyClientSecret(ctx, clientID, "wrong"), store.ErrInvalidSecret)

	t.Run("the stored hash does not itself authenticate", func(t *testing.T) {
		var stored []byte
		require.NoError(t, s.Pool().QueryRow(ctx,
			`SELECT secret_hash FROM oidc_clients WHERE client_id = $1`,
			clientID).Scan(&stored))

		assert.NotContains(t, string(stored), registered.Secret)
		require.ErrorIs(t, s.VerifyClientSecret(ctx, clientID, string(stored)),
			store.ErrInvalidSecret)
	})
}

// TestPKCERequiredByDefault.
//
// OAuth 2.1 makes PKCE mandatory even for confidential clients, because a
// leaked authorization code is otherwise sufficient on its own.
func TestPKCERequiredByDefault(t *testing.T) {
	s := newStore(t)

	for _, method := range []store.AuthMethod{
		store.AuthNone, store.AuthClientSecretBasic, store.AuthPrivateKeyJWT,
	} {
		t.Run(string(method), func(t *testing.T) {
			registered, err := s.RegisterOIDCClient(t.Context(), store.RegisterClientInput{
				Name:         "client-" + string(method),
				AuthMethod:   method,
				RedirectURIs: []string{"https://app.example.com/callback"},
			}, nil, nil)
			require.NoError(t, err)
			assert.True(t, registered.Client.RequirePKCE,
				"PKCE must be required for every client type, not only public ones")
		})
	}
}

// TestClientIDIsOpaque: client_id travels in browser URLs and referrer headers,
// so a readable one leaks the shape of internal systems to wherever a user
// navigates next.
func TestClientIDIsOpaque(t *testing.T) {
	s := newStore(t)

	registered, err := s.RegisterOIDCClient(t.Context(), store.RegisterClientInput{
		Name:         "internal-payroll-system",
		AuthMethod:   store.AuthNone,
		RedirectURIs: []string{"https://payroll.example.com/callback"},
	}, nil, nil)
	require.NoError(t, err)

	assert.NotContains(t, registered.Client.ClientID, "payroll",
		"the client_id must not embed the application's name")
	assert.GreaterOrEqual(t, len(registered.Client.ClientID), 32)
}

// TestApplicationIsADirectoryEntity: applications are not a separate registry,
// so an app can be a group member, a policy subject, and appear in the audit
// trail exactly like a person.
func TestApplicationIsADirectoryEntity(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	registered, err := s.RegisterOIDCClient(ctx, store.RegisterClientInput{
		Name:         "grafana",
		DisplayName:  "Grafana",
		AuthMethod:   store.AuthNone,
		RedirectURIs: []string{"https://grafana.example.com/callback"},
	}, nil, nil)
	require.NoError(t, err)

	entity, err := s.GetEntity(ctx, registered.Client.EntityID)
	require.NoError(t, err)
	assert.Equal(t, "grafana", entity.Name)
	assert.Equal(t, "Grafana", entity.DisplayName)

	var events int
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM events WHERE entity_id = $1`,
		registered.Client.EntityID).Scan(&events))
	assert.Positive(t, events, "registering an application must be audited")

	report, err := s.ValidateChain(ctx)
	require.NoError(t, err)
	assert.True(t, report.Valid)
}

func TestUnknownClientRejected(t *testing.T) {
	s := newStore(t)
	_, err := s.OIDCClientByID(t.Context(), "no-such-client")
	require.ErrorIs(t, err, store.ErrClientNotFound)
}
