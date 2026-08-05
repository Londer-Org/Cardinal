package oidcprovider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/claims"
	"github.com/arthur-lonfils/cardinal/internal/config"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Storage must satisfy the library's contract. Asserted at compile time so a
// missing method is a build failure rather than a nil-interface panic on the
// first authorization request.
var _ op.Storage = (*Storage)(nil)

// Provider is Cardinal's OpenID Connect provider.
type Provider struct {
	provider *op.Provider
	storage  *Storage
}

// New builds the provider.
//
// The signing key is created on first use rather than requiring a separate
// bootstrap step: a deployment that starts without one would otherwise fail
// every authorization with an error nobody could act on.
func New(ctx context.Context, s *store.Store, resolver *claims.Resolver, cfg *config.Config) (*Provider, error) {
	if cfg.OIDC.SigningKeyEncryptionKey == "" {
		return nil, fmt.Errorf(
			"oidcprovider: oidc.signing_key_encryption_key is required — the " +
				"signing key can forge tokens for every application, so it is not " +
				"stored in the clear")
	}

	if _, err := s.EnsureSigningKey(ctx, cfg.OIDC.SigningKeyEncryptionKey); err != nil {
		return nil, fmt.Errorf("oidcprovider: preparing signing key: %w", err)
	}

	issuer := cfg.Server.PublicURL
	if issuer == "" {
		return nil, fmt.Errorf(
			"oidcprovider: server.public_url is required — it is the issuer " +
				"identifier, and every token carries it")
	}

	storage := NewStorage(s, resolver, cfg.OIDC.SigningKeyEncryptionKey,
		func(authRequestID string) string {
			// Where the library sends an unauthenticated authorization request.
			// Cardinal's own login page picks the ID back up and completes the
			// flow once the user has signed in.
			return "/oidc/login?auth=" + authRequestID
		})

	// The key that encrypts the library's internal cookies. Derived from the
	// same configured secret so there is one thing to manage, but hashed with a
	// distinct label so the two uses cannot be substituted for one another.
	cookieKey := sha256.Sum256([]byte("cardinal-oidc-cookie:" + cfg.OIDC.SigningKeyEncryptionKey))

	provider, err := op.NewProvider(&op.Config{
		CryptoKey: cookieKey,

		// Refresh tokens are enabled; the storage rotates them on every use.
		SupportedUILocales: nil,

		// PKCE is advertised as supported, and every registered client requires
		// it (OAuth 2.1). Advertising S256 only: `plain` lets anyone who
		// intercepted the challenge derive the verifier, which defeats the
		// point.
		CodeMethodS256: true,

		// Authentication at the token endpoint may use a client secret or none
		// (public clients with PKCE).
		AuthMethodPost:          true,
		AuthMethodPrivateKeyJWT: false,
		GrantTypeRefreshToken:   true,
		RequestObjectSupported:  false,
		SupportedClaims:         op.DefaultSupportedClaims,
		DeviceAuthorization:     op.DeviceAuthorizationConfig{Lifetime: 0},
	}, storage, op.StaticIssuer(issuer),
		// Endpoints are stated explicitly rather than left to defaults.
		//
		// Two reasons. Everything lives under /oidc/ so it cannot collide with
		// the admin UI's client-side routes as those grow. And stating them
		// here is what guarantees the discovery document and the actual routing
		// agree — the default set advertised /revoke while Cardinal mounted
		// /oauth/revoke, which a client would only discover at revocation time.
		op.WithCustomEndpoints(
			op.NewEndpoint("/oidc/authorize"),
			op.NewEndpoint("/oidc/token"),
			op.NewEndpoint("/oidc/userinfo"),
			op.NewEndpoint("/oidc/revoke"),
			op.NewEndpoint("/oidc/end-session"),
			op.NewEndpoint("/oidc/keys"),
		),
		op.WithCustomIntrospectionEndpoint(op.NewEndpoint("/oidc/introspect")),

		// Cardinal terminates TLS at the proxy, so the library must not insist
		// on seeing HTTPS itself. The proxy is what guarantees it.
		op.WithAllowInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: building provider: %w", err)
	}

	return &Provider{provider: provider, storage: storage}, nil
}

// Handler serves the OIDC endpoints: discovery, authorize, token, userinfo and
// JWKS.
func (p *Provider) Handler() http.Handler { return p.provider }

// Storage exposes the storage layer, so Cardinal's login flow can complete an
// authorization request once the user has signed in.
func (p *Provider) Storage() *Storage { return p.storage }

// RotateSigningKey generates a new signing key, retiring the current one after
// a grace period during which it still verifies.
func (p *Provider) RotateSigningKey(ctx context.Context, s *store.Store, sealKey string) error {
	// The grace period must comfortably exceed the longest token lifetime, or
	// tokens issued moments before the rotation stop verifying.
	_, err := s.RotateSigningKey(ctx, sealKey, 48*time.Hour)
	return err
}
